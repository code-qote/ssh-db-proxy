package sqlparser

import (
	"fmt"

	pg_query "github.com/pganalyze/pg_query_go/v6"
)

type (
	StatementType int32
	RangeType     int32
)

const (
	NoOp StatementType = iota
	Select
	Join
	Update
	Insert
	Delete
)

type Operation struct {
	Type   StatementType
	Table  string
	Column string

	currentTable bool
}

type state struct {
	Type  StatementType
	Table string
	Node  *pg_query.Node
}

func FindOperations(query string) ([]Operation, error) {
	root, err := pg_query.Parse(query)
	if err != nil {
		return nil, fmt.Errorf("parse query: %w", err)
	}

	var (
		tableAliases  = make(map[string]string)
		columnAliases = make(map[string]struct{})
		ctes          = make(map[string]struct{})
		tables        = make(map[string]struct{})
		statements    = make([]state, 0, len(root.Stmts))
		operations    = make(map[Operation]struct{})
	)

	handleFrom := func(statement state, from []*pg_query.Node) (currentTable string) {
		var item *pg_query.Node
		for len(from) > 0 {
			item, from = from[0], from[1:]
			if item == nil {
				continue
			}
			switch node := item.Node.(type) {
			case *pg_query.Node_RangeVar:
				if node.RangeVar.Alias != nil {
					tableAliases[node.RangeVar.Alias.Aliasname] = node.RangeVar.Relname
					tables[node.RangeVar.Alias.Aliasname] = struct{}{}
				} else {
					tableAliases[node.RangeVar.Relname] = node.RangeVar.Relname
					tables[node.RangeVar.Relname] = struct{}{}
				}
				if currentTable == "" {
					currentTable = node.RangeVar.Relname
				}
			case *pg_query.Node_JoinExpr:
				from = append(from, node.JoinExpr.Larg)
				from = append(from, node.JoinExpr.Rarg)
				statements = append(statements, state{Join, statement.Table, node.JoinExpr.Quals})
			default:
				statements = append(statements, withNode(statement, item))
			}
		}
		return
	}

	handleRelation := func(relation *pg_query.RangeVar) (currentTable string) {
		if relation == nil {
			return
		}
		if relation.Alias != nil {
			tableAliases[relation.Alias.Aliasname] = relation.Relname
			tables[relation.Alias.Aliasname] = struct{}{}
		} else {
			tableAliases[relation.Relname] = relation.Relname
			tables[relation.Relname] = struct{}{}
		}
		return relation.Relname
	}

	statements = append(statements, sliceMap(root.Stmts, func(item *pg_query.RawStmt) state { return state{NoOp, "", item.Stmt} })...)
	for len(statements) > 0 {
		var statement state
		if len(statements) > 0 {
			statement, statements = statements[0], statements[1:]
		}
		if statement.Node == nil {
			continue
		}
		switch stmt := statement.Node.Node.(type) {
		case *pg_query.Node_ColumnRef:
			if statement.Type != NoOp {
				op := Operation{Type: statement.Type}
				tableProvided := false
				if len(stmt.ColumnRef.Fields) == 1 {
					if column, ok := stmt.ColumnRef.Fields[0].Node.(*pg_query.Node_String_); ok && column != nil {
						op.Column = column.String_.Sval
					}
					op.Table = statement.Table
					op.currentTable = true
				} else {
					if table, ok := stmt.ColumnRef.Fields[0].Node.(*pg_query.Node_String_); ok && table != nil {
						tableProvided = true
						op.Table = tableAliases[table.String_.Sval]
					}
					if column, ok := stmt.ColumnRef.Fields[1].Node.(*pg_query.Node_String_); ok && column != nil {
						op.Column = column.String_.Sval
					}
				}
				if _, isColumnAlias := columnAliases[op.Column]; op.Table == "" && (op.Type == Select || tableProvided || isColumnAlias) {
					continue
				}
				if _, isCTE := ctes[op.Table]; isCTE {
					continue
				}
				operations[op] = struct{}{}
			}
		case *pg_query.Node_ResTarget:
			if stmt.ResTarget.Name != "" {
				switch statement.Type {
				case Update, Insert:
					statements = append(statements, withNode(statement, &pg_query.Node{
						Node: &pg_query.Node_ColumnRef{
							ColumnRef: &pg_query.ColumnRef{
								Fields: []*pg_query.Node{
									{
										Node: &pg_query.Node_String_{String_: &pg_query.String{Sval: stmt.ResTarget.Name}},
									},
								},
							},
						},
					}))
				case Select:
					columnAliases[stmt.ResTarget.Name] = struct{}{}
				}
			}
			statements = append(statements, withNode(statement, stmt.ResTarget.Val))
		case *pg_query.Node_SelectStmt:
			selectStmt := stmt.SelectStmt
			switch selectStmt.Op {
			case pg_query.SetOperation_SETOP_NONE:
				currentTable := handleFrom(statement, selectStmt.FromClause)
				statements = append(statements, sliceMap(selectStmt.TargetList, func(item *pg_query.Node) state { return state{Select, currentTable, item} })...)
				statements = append(statements, sliceMap(selectStmt.ValuesLists, func(item *pg_query.Node) state { return state{Select, currentTable, item} })...)
				statements = append(statements, state{Select, currentTable, selectStmt.WhereClause})
				statements = append(statements, state{Select, currentTable, selectStmt.HavingClause})
				if selectStmt.WithClause != nil {
					statements = append(statements, sliceMap(selectStmt.WithClause.Ctes, func(item *pg_query.Node) state { return withNode(statement, item) })...)
				}
			case pg_query.SetOperation_SETOP_UNION, pg_query.SetOperation_SETOP_EXCEPT, pg_query.SetOperation_SETOP_INTERSECT:
				statements = append(statements, withNode(statement, &pg_query.Node{Node: &pg_query.Node_SelectStmt{SelectStmt: selectStmt.Larg}}))
				statements = append(statements, withNode(statement, &pg_query.Node{Node: &pg_query.Node_SelectStmt{SelectStmt: selectStmt.Rarg}}))
			}
		case *pg_query.Node_UpdateStmt:
			updateStmt := stmt.UpdateStmt
			currentTable := handleRelation(updateStmt.Relation)
			handleFrom(statement, updateStmt.FromClause)
			statements = append(statements, sliceMap(updateStmt.TargetList, func(item *pg_query.Node) state { return state{Update, currentTable, item} })...)
			statements = append(statements, state{Select, currentTable, updateStmt.WhereClause})
			statements = append(statements, sliceMap(updateStmt.ReturningList, func(item *pg_query.Node) state { return state{Select, currentTable, item} })...)
			if updateStmt.WithClause != nil {
				statements = append(statements, sliceMap(updateStmt.WithClause.Ctes, func(item *pg_query.Node) state { return withNode(statement, item) })...)
			}
		case *pg_query.Node_DeleteStmt:
			deleteStmt := stmt.DeleteStmt
			currentTable := handleRelation(deleteStmt.Relation)
			if deleteStmt.WhereClause != nil {
				statements = append(statements, state{Delete, currentTable, deleteStmt.WhereClause})
			}
			statements = append(statements, sliceMap(deleteStmt.ReturningList, func(item *pg_query.Node) state { return state{Select, currentTable, item} })...)
			statements = append(statements, sliceMap(deleteStmt.UsingClause, func(item *pg_query.Node) state { return state{Select, currentTable, item} })...)
			if deleteStmt.WithClause != nil {
				statements = append(statements, sliceMap(deleteStmt.WithClause.Ctes, func(item *pg_query.Node) state { return withNode(statement, item) })...)
			}
		case *pg_query.Node_InsertStmt:
			insertStmt := stmt.InsertStmt
			currentTable := handleRelation(insertStmt.Relation)
			statements = append(statements, withNode(statement, stmt.InsertStmt.SelectStmt))
			statements = append(statements, sliceMap(stmt.InsertStmt.Cols, func(item *pg_query.Node) state { return state{Insert, currentTable, item} })...)
			statements = append(statements, sliceMap(stmt.InsertStmt.ReturningList, func(item *pg_query.Node) state { return state{Select, currentTable, item} })...)
			if insertStmt.WithClause != nil {
				statements = append(statements, sliceMap(insertStmt.WithClause.Ctes, func(item *pg_query.Node) state { return withNode(statement, item) })...)
			}
			if stmt.InsertStmt.OnConflictClause != nil {
				statements = append(statements, state{Select, currentTable, stmt.InsertStmt.OnConflictClause.WhereClause})
				statements = append(statements, sliceMap(stmt.InsertStmt.OnConflictClause.TargetList, func(item *pg_query.Node) state { return state{Update, currentTable, item} })...)
				if stmt.InsertStmt.OnConflictClause.Infer != nil {
					statements = append(statements, state{Select, currentTable, stmt.InsertStmt.OnConflictClause.Infer.WhereClause})
					statements = append(statements, sliceMap(stmt.InsertStmt.OnConflictClause.Infer.IndexElems, func(item *pg_query.Node) state { return state{Select, currentTable, item} })...)
				}
			}
		case *pg_query.Node_FuncCall:
			statements = append(statements, sliceMap(stmt.FuncCall.Args, func(item *pg_query.Node) state { return withNode(statement, item) })...)
			if stmt.FuncCall.Over != nil {
				statements = append(statements, sliceMap(stmt.FuncCall.Over.PartitionClause, func(item *pg_query.Node) state { return withNode(statement, item) })...)
			}
		case *pg_query.Node_CaseExpr:
			statements = append(statements, sliceMap(stmt.CaseExpr.Args, func(item *pg_query.Node) state { return state{Type: Select, Table: statement.Table, Node: item} })...)
			statements = append(statements, state{Type: Select, Table: statement.Table, Node: stmt.CaseExpr.Defresult})
		case *pg_query.Node_CaseWhen:
			statements = append(statements, withNode(statement, stmt.CaseWhen.Result))
			statements = append(statements, withNode(statement, stmt.CaseWhen.Expr))
		case *pg_query.Node_List:
			statements = append(statements, sliceMap(stmt.List.Items, func(item *pg_query.Node) state { return withNode(statement, item) })...)
		case *pg_query.Node_RawStmt:
			statements = append(statements, withNode(statement, stmt.RawStmt.Stmt))
		case *pg_query.Node_SubLink:
			statements = append(statements, withNode(statement, stmt.SubLink.Testexpr))
			statements = append(statements, withNode(statement, stmt.SubLink.Subselect))
		case *pg_query.Node_AExpr:
			statements = append(statements, withNode(statement, stmt.AExpr.Lexpr))
			statements = append(statements, withNode(statement, stmt.AExpr.Rexpr))
		case *pg_query.Node_RangeSubselect:
			statements = append(statements, withNode(statement, stmt.RangeSubselect.Subquery))
		case *pg_query.Node_BoolExpr:
			statements = append(statements, sliceMap(stmt.BoolExpr.Args, func(item *pg_query.Node) state { return withNode(statement, item) })...)
		case *pg_query.Node_NullTest:
			statements = append(statements, withNode(statement, stmt.NullTest.Arg))
		case *pg_query.Node_NullIfExpr:
			statements = append(statements, sliceMap(stmt.NullIfExpr.Args, func(item *pg_query.Node) state { return withNode(statement, item) })...)
		case *pg_query.Node_CommonTableExpr:
			ctes[stmt.CommonTableExpr.Ctename] = struct{}{}
			statements = append(statements, withNode(statement, stmt.CommonTableExpr.Ctequery))
		}
	}
	preResult := make(map[Operation]struct{}, len(operations))
	for op := range operations {
		if _, ok := columnAliases[op.Column]; ok && op.currentTable {
			delete(operations, op)
			continue
		}
		op.currentTable = false
		preResult[op] = struct{}{}
	}
	result := make([]Operation, 0, len(preResult))
	for op := range preResult {
		result = append(result, op)
	}
	return result, nil
}

func withNode(state state, newNode *pg_query.Node) state {
	state.Node = newNode
	return state
}

func sliceMap[T, R any](collection []T, predicate func(T) R) []R {
	result := make([]R, len(collection))
	for i := range collection {
		result[i] = predicate(collection[i])
	}
	return result
}
