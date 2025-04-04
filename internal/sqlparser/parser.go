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
	for _, stmt := range root.Stmts {
		statements = append(statements, state{NoOp, "", stmt.Stmt})
	}
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
				if op.Type == Select && op.Table == "" {
					continue
				}
				if op.Type == Join && tableProvided && op.Table == "" {
					continue
				}
				if _, ok := columnAliases[op.Column]; ok && op.Table == "" {
					continue
				}
				operations[op] = struct{}{}
			}
		case *pg_query.Node_ResTarget:
			if stmt.ResTarget.Name != "" {
				switch statement.Type {
				case Update:
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
				for _, item := range selectStmt.TargetList {
					statements = append(statements, state{Select, currentTable, item})
				}
				if selectStmt.WhereClause != nil {
					statements = append(statements, state{Select, currentTable, selectStmt.WhereClause})
				}
				if selectStmt.WithClause != nil {
					//for _, item := range selectStmt.WithClause.Ctes {
					//	statements = append(statements, item)
					//}
				}
			case pg_query.SetOperation_SETOP_UNION, pg_query.SetOperation_SETOP_EXCEPT, pg_query.SetOperation_SETOP_INTERSECT:
				statements = append(statements, withNode(statement, &pg_query.Node{Node: &pg_query.Node_SelectStmt{SelectStmt: selectStmt.Larg}}))
				statements = append(statements, withNode(statement, &pg_query.Node{Node: &pg_query.Node_SelectStmt{SelectStmt: selectStmt.Rarg}}))
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
			handleFrom(statement, updateStmt.FromClause)
			for _, target := range updateStmt.TargetList {
				statements = append(statements, state{Update, currentTable, target})
			}
			if updateStmt.WhereClause != nil {
				statements = append(statements, state{Select, currentTable, updateStmt.WhereClause})
			}
			if updateStmt.WithClause != nil {
				//for _, item := range updateStmt.WithClause.Ctes {
				//	statements = append(statements, item)
				//}
			}
		case *pg_query.Node_DeleteStmt:
			//if stmt.DeleteStmt.WhereClause != nil {
			//	conditions = append(conditions, stmt.DeleteStmt.WhereClause)
			//}
		case *pg_query.Node_InsertStmt:
		case *pg_query.Node_FuncCall:
			for _, arg := range stmt.FuncCall.Args {
				statements = append(statements, withNode(statement, arg))
			}
		case *pg_query.Node_CaseExpr:
			for _, arg := range stmt.CaseExpr.Args {
				statements = append(statements, state{Type: Select, Table: statement.Table, Node: arg})
			}
			statements = append(statements, state{Type: Select, Table: statement.Table, Node: stmt.CaseExpr.Defresult})
		case *pg_query.Node_CaseWhen:
			statements = append(statements, withNode(statement, stmt.CaseWhen.Result))
			statements = append(statements, withNode(statement, stmt.CaseWhen.Expr))
		case *pg_query.Node_List:
			for _, item := range stmt.List.Items {
				statements = append(statements, withNode(statement, item))
			}
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
		}
	}

	preResult := make(map[Operation]struct{})
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
