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
}

//func FindOperationsRecursive(query string) ([]Operation, error) {
//	root, err := pg_query.Parse(query)
//	if err != nil {
//		return nil, fmt.Errorf("parse query: %w", err)
//	}
//	var (
//		tableAliases = make(map[string]string)
//		tables       = make(map[string]struct{})
//		statements   = make([]*pg_query.Node, 0, len(root.Stmts))
//		conditions   []*pg_query.Node
//		operations   = make(map[Operation]struct{})
//	)
//	walk := func(stmt *pg_query.Node, currentTable string) {
//		if stmt == nil {
//			return
//		}
//		switch node := stmt.Node.(type) {
//		case *pg_query.Node_List:
//			for _, item := range node.List.Items {
//				walk(item, currentTable)
//			}
//			statements = append(statements, stmt.List.Items...)
//		case *pg_query.Node_RawStmt:
//			statements = append(statements, stmt.RawStmt.Stmt)
//		}
//	}
//	for _, stmt := range root.Stmts {
//		walk(stmt.Stmt, "")
//	}
//	result := make([]Operation, 0, len(operations))
//	for op := range operations {
//		result = append(result, op)
//	}
//	return result, nil
//}

func FindOperations(query string) ([]Operation, error) {
	root, err := pg_query.Parse(query)
	if err != nil {
		return nil, fmt.Errorf("parse query: %w", err)
	}

	type state struct {
		node         *pg_query.Node
		currentTable string
	}

	var (
		tableAliases = make(map[string]string)
		tables       = make(map[string]struct{})
		statements   = make([]state, 0, len(root.Stmts))
		conditions   []*pg_query.Node
		operations   = make(map[Operation]struct{})
	)
	for _, stmt := range root.Stmts {
		statements = append(statements, state{stmt.Stmt, ""})
	}
	for len(statements) > 0 || len(conditions) > 0 {
		var statement state
		if len(statements) > 0 {
			statement, statements = statements[0], statements[1:]
		}
		if statement.node != nil {
			switch stmt := statement.node.Node.(type) {
			case *pg_query.Node_List:
				for _, item := range stmt.List.Items {
					statements = append(statements, state{node: item, currentTable: statement.currentTable})
				}
			case *pg_query.Node_RawStmt:
				statements = append(statements, state{node: stmt.RawStmt.Stmt, currentTable: statement.currentTable})
			case *pg_query.Node_SubLink:
				if stmt.SubLink.Testexpr != nil {
					conditions = append(conditions, stmt.SubLink.Testexpr)
				}
				if stmt.SubLink.Subselect != nil {
					statements = append(statements, stmt.SubLink.Subselect)
				}
			case *pg_query.Node_SelectStmt:
				selectStmt := stmt.SelectStmt
				switch selectStmt.Op {
				case pg_query.SetOperation_SETOP_NONE:
					currentTable := ""
					for _, item := range selectStmt.FromClause {
						if rangeSubSelect, ok := item.Node.(*pg_query.Node_RangeSubselect); ok && rangeSubSelect != nil {
							statements = append(statements, rangeSubSelect.RangeSubselect.Subquery)
						}
						if rangeVar, ok := item.Node.(*pg_query.Node_RangeVar); ok && rangeVar != nil {
							if rangeVar.RangeVar.Alias != nil {
								tableAliases[rangeVar.RangeVar.Alias.Aliasname] = rangeVar.RangeVar.Relname
								tables[rangeVar.RangeVar.Alias.Aliasname] = struct{}{}
							} else {
								tableAliases[rangeVar.RangeVar.Relname] = rangeVar.RangeVar.Relname
								tables[rangeVar.RangeVar.Relname] = struct{}{}
							}
							currentTable = rangeVar.RangeVar.Relname
						}
					}
					joinConditions, joinStatements, joinTableAliases, joinTables, joinCurrentTable := conditionsFromJoinClauses(selectStmt.FromClause)
					for k, v := range joinTableAliases {
						tableAliases[k] = v
					}
					for k := range joinTables {
						tables[k] = struct{}{}
					}
					conditions = append(conditions, joinConditions...)
					statements = append(statements, joinStatements...)
					if joinCurrentTable != "" {
						currentTable = joinCurrentTable
					}
					for _, item := range selectStmt.TargetList {
						targetConditions, targetStatements := handleResTarget(item, currentTable, Select)
						conditions = append(conditions, targetConditions...)
						statements = append(statements, targetStatements...)
					}
					if selectStmt.WhereClause != nil {
						conditions = append(conditions, selectStmt.WhereClause)
					}
					if selectStmt.WithClause != nil {
						for _, item := range selectStmt.WithClause.Ctes {
							statements = append(statements, item)
						}
					}
				case pg_query.SetOperation_SETOP_UNION, pg_query.SetOperation_SETOP_EXCEPT, pg_query.SetOperation_SETOP_INTERSECT:
					if selectStmt.Larg != nil {
						statements = append(statements, &pg_query.Node{Node: &pg_query.Node_SelectStmt{SelectStmt: selectStmt.Larg}})
					}
					if selectStmt.Rarg != nil {
						statements = append(statements, &pg_query.Node{Node: &pg_query.Node_SelectStmt{SelectStmt: selectStmt.Rarg}})
					}
				}
			case *pg_query.Node_UpdateStmt:
				var currentTable string
				updateStmt := stmt.UpdateStmt
				if updateStmt.Relation != nil {
					if updateStmt.Relation.Alias != nil {
						tableAliases[updateStmt.Relation.Alias.Aliasname] = updateStmt.Relation.Relname
						tables[updateStmt.Relation.Alias.Aliasname] = struct{}{}
					} else {
						tableAliases[updateStmt.Relation.Relname] = updateStmt.Relation.Relname
						tables[updateStmt.Relation.Relname] = struct{}{}
					}
					currentTable = updateStmt.Relation.Relname
				}
				for _, target := range updateStmt.TargetList {
					if node, ok := target.Node.(*pg_query.Node_ResTarget); ok && node != nil {
						conditions = append(conditions, &pg_query.Node{
							Node: &pg_query.Node_ColumnRef{
								ColumnRef: &pg_query.ColumnRef{
									Fields: []*pg_query.Node{
										{Node: &pg_query.Node_String_{String_: &pg_query.String{Sval: currentTable}}},
										{Node: &pg_query.Node_String_{String_: &pg_query.String{Sval: node.ResTarget.Name}}},
										{Node: &pg_query.Node_Integer{Integer: &pg_query.Integer{Ival: int32(Update)}}},
									},
								},
							},
						})
						targetConditions, targetStatements := handleResTarget(target, currentTable, Update)
						conditions = append(conditions, targetConditions...)
						statements = append(statements, targetStatements...)
					}
				}
				if updateStmt.WhereClause != nil {
					conditions = append(conditions, updateStmt.WhereClause)
				}
				if updateStmt.WithClause != nil {
					for _, item := range updateStmt.WithClause.Ctes {
						statements = append(statements, item)
					}
				}
			case *pg_query.Node_DeleteStmt:
				if stmt.DeleteStmt.WhereClause != nil {
					conditions = append(conditions, stmt.DeleteStmt.WhereClause)
				}
			case *pg_query.Node_InsertStmt:
			}
		}

		if len(conditions) > 0 {
			var nextItem *pg_query.Node
			nextItem, conditions = conditions[0], conditions[1:]
			if item, ok := nextItem.Node.(*pg_query.Node_ColumnRef); ok && item != nil {
				columnField, tableField, statementTypeField := item.ColumnRef.Fields[1], item.ColumnRef.Fields[0], item.ColumnRef.Fields[2]
				var op Operation
				if column, ok := columnField.Node.(*pg_query.Node_String_); ok && column != nil {
					op.Column = column.String_.Sval
				}
				if tableField != nil {
					if table, ok := tableField.Node.(*pg_query.Node_String_); ok && table != nil {
						op.Table = tableAliases[table.String_.Sval]
					}
				}
				if statementType, ok := statementTypeField.Node.(*pg_query.Node_Integer); ok && statementType != nil {
					op.Type = StatementType(statementType.Integer.Ival)
				}
				if _, isTable := tables[op.Table]; isTable || op.Table != "" || (op.Type == Join && (tableField == nil || isTable)) {
					operations[op] = struct{}{}
				}
			}
		}
	}
	result := make([]Operation, 0, len(operations))
	for op := range operations {
		result = append(result, op)
	}
	return result, nil
}

func handleResTarget(item *pg_query.Node, currentTable string, statementType StatementType) (conditions []*pg_query.Node, statements []*pg_query.Node) {
	if node, ok := item.Node.(*pg_query.Node_ResTarget); ok && node != nil {
		if node.ResTarget != nil && node.ResTarget.Val != nil {
			switch target := node.ResTarget.Val.Node.(type) {
			case *pg_query.Node_ColumnRef:
				if len(target.ColumnRef.Fields) == 1 {
					target.ColumnRef.Fields = []*pg_query.Node{
						{Node: &pg_query.Node_String_{String_: &pg_query.String{Sval: currentTable}}},
						target.ColumnRef.Fields[0],
					}
				}
				target.ColumnRef.Fields = append(target.ColumnRef.Fields, &pg_query.Node{
					Node: &pg_query.Node_Integer{Integer: &pg_query.Integer{Ival: int32(statementType)}},
				})
				conditions = append(conditions, node.ResTarget.Val)
			case *pg_query.Node_FuncCall:
				for _, arg := range target.FuncCall.Args {
					switch node := arg.Node.(type) {
					case *pg_query.Node_ColumnRef:
						if len(node.ColumnRef.Fields) == 1 {
							node.ColumnRef.Fields = []*pg_query.Node{
								{Node: &pg_query.Node_String_{String_: &pg_query.String{Sval: currentTable}}},
								node.ColumnRef.Fields[0],
							}
						}
						node.ColumnRef.Fields = append(node.ColumnRef.Fields, &pg_query.Node{
							Node: &pg_query.Node_Integer{Integer: &pg_query.Integer{Ival: int32(statementType)}},
						})
						conditions = append(conditions, arg)
					default:
						statements = append(statements, arg)
					}
				}
			default:
				statements = append(statements, &pg_query.Node{Node: target})
			}
		}
	}
	return
}

func conditionsFromJoinClauses(fromClause []*pg_query.Node) (conditions []*pg_query.Node, statements []*pg_query.Node, tableAliases map[string]string, tables map[string]struct{}, currentTable string) {
	tableAliases = make(map[string]string)
	tables = make(map[string]struct{})

	handleJoinArg := func(node *pg_query.Node) {
		switch node := node.Node.(type) {
		case *pg_query.Node_JoinExpr:
			recConditions, recStatements, recTableAliases, recTables, _ := conditionsFromJoinClauses([]*pg_query.Node{{Node: node}})
			for k, v := range recTableAliases {
				tableAliases[k] = v
			}
			for k := range recTables {
				tables[k] = struct{}{}
			}
			conditions = append(conditions, recConditions...)
			statements = append(statements, recStatements...)
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
		case *pg_query.Node_RangeSubselect:
			statements = append(statements, node.RangeSubselect.Subquery)
		}
	}

	for _, item := range fromClause {
		switch node := item.Node.(type) {
		case *pg_query.Node_AExpr:
			if node.AExpr.Lexpr != nil {
				aexprConditions, aexprStatements := handleAExpr(node.AExpr.Lexpr)
				conditions = append(conditions, aexprConditions...)
				statements = append(statements, aexprStatements...)
			}
			if node.AExpr.Rexpr != nil {
				aexprConditions, aexprStatements := handleAExpr(node.AExpr.Rexpr)
				conditions = append(conditions, aexprConditions...)
				statements = append(statements, aexprStatements...)
			}
		case *pg_query.Node_JoinExpr:
			if node.JoinExpr.Quals != nil {
				recConditions, recStatements, recTableAliases, recTables, _ := conditionsFromJoinClauses([]*pg_query.Node{{Node: node.JoinExpr.Quals.Node}})
				for k, v := range recTableAliases {
					tableAliases[k] = v
				}
				for k := range recTables {
					tables[k] = struct{}{}
				}
				conditions = append(conditions, recConditions...)
				statements = append(statements, recStatements...)
			}
			if node.JoinExpr.Larg != nil {
				handleJoinArg(node.JoinExpr.Larg)
			}
			if node.JoinExpr.Rarg != nil {
				handleJoinArg(node.JoinExpr.Rarg)
			}
		}
	}
	return
}

func handleAExpr(node *pg_query.Node) (conditions []*pg_query.Node, statements []*pg_query.Node) {
	switch columnRef := node.Node.(type) {
	case *pg_query.Node_ColumnRef:
		if len(columnRef.ColumnRef.Fields) == 1 {
			columnRef.ColumnRef.Fields = []*pg_query.Node{nil, columnRef.ColumnRef.Fields[0]}
		}
		columnRef.ColumnRef.Fields = append(columnRef.ColumnRef.Fields, &pg_query.Node{
			Node: &pg_query.Node_Integer{Integer: &pg_query.Integer{Ival: int32(Join)}},
		})
		conditions = append(conditions, node)
	default:
		statements = append(statements, node)
	}
	return
}
