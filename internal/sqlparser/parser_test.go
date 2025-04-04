package sqlparser

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQueryCondition(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		query := "select tt.a, tt.b from table1 as tt;"
		ops, err := FindOperations(query)
		require.NoError(t, err)
		require.ElementsMatch(t, ops, []Operation{
			{Type: Select, Table: "table1", Column: "a"},
			{Type: Select, Table: "table1", Column: "b"},
		})
	})
	t.Run("subquery", func(t *testing.T) {
		query := "select tt.a, tt.b from (select a, b from table1) as tt;"
		ops, err := FindOperations(query)
		require.NoError(t, err)
		require.ElementsMatch(t, ops, []Operation{
			{Type: Select, Table: "table1", Column: "a"},
			{Type: Select, Table: "table1", Column: "b"},
		})

		query = "select tt.a, tt.b from (select tt.a, tt.b from table1 as tt) as tt;"
		ops, err = FindOperations(query)
		require.NoError(t, err)
		require.ElementsMatch(t, ops, []Operation{
			{Type: Select, Table: "table1", Column: "a"},
			{Type: Select, Table: "table1", Column: "b"},
		})

		query = "select tt.a, table2.c from (select tt.a, tt.b from table1 as tt) as tt, table2;"
		ops, err = FindOperations(query)
		require.NoError(t, err)
		require.ElementsMatch(t, ops, []Operation{
			{Type: Select, Table: "table1", Column: "a"},
			{Type: Select, Table: "table1", Column: "b"},
			{Type: Select, Table: "table2", Column: "c"},
		})

		query = "select tt.a, c from (select tt.a, tt.b from table1 as tt) as tt, table2;"
		ops, err = FindOperations(query)
		require.NoError(t, err)
		require.ElementsMatch(t, ops, []Operation{
			{Type: Select, Table: "table1", Column: "a"},
			{Type: Select, Table: "table1", Column: "b"},
			{Type: Select, Table: "table2", Column: "c"},
		})
	})

	t.Run("subquery-complicated", func(t *testing.T) {
		query := `SELECT 
    u.user_id, 
    u.name, 
    (
        SELECT json_agg(o)
        FROM (
            SELECT 
                o.order_id, 
                o.order_date, 
                (
                    SELECT string_agg(p.product_name, ', ')
                    FROM order_items oi
                    WHERE oi.order_id = o.order_id
                ) AS product_list
            FROM 
                orders o
            WHERE 
                o.user_id = u.user_id
                AND o.order_date >= CURRENT_DATE - INTERVAL '1 year'
        ) o
    ) AS orders_last_year
FROM 
    users u
WHERE 
    (
        SELECT COUNT(*)
        FROM orders o
        WHERE o.user_id = u.user_id
        AND o.order_date >= CURRENT_DATE - INTERVAL '1 month'
    ) > 0;`

		ops, err := FindOperations(query)
		require.NoError(t, err)
		require.ElementsMatch(t, ops, []Operation{
			{Type: Select, Table: "orders", Column: "order_id"},
			{Type: Select, Table: "orders", Column: "order_date"},
			{Type: Select, Table: "users", Column: "user_id"},
			{Type: Select, Table: "users", Column: "name"},
		})
	})

	t.Run("join", func(t *testing.T) {
		query := "select a from table1 inner join table2 on b = a"
		ops, err := FindOperations(query)
		require.NoError(t, err)
		require.ElementsMatch(t, ops, []Operation{
			{Type: Select, Table: "table1", Column: "a"},
			{Type: Join, Table: "", Column: "a"},
			{Type: Join, Table: "", Column: "b"},
		})

		query = "select table1.a from table1 inner join table2 on table2.b = table1.a"
		ops, err = FindOperations(query)
		require.NoError(t, err)
		require.ElementsMatch(t, ops, []Operation{
			{Type: Select, Table: "table1", Column: "a"},
			{Type: Join, Table: "table1", Column: "a"},
			{Type: Join, Table: "table2", Column: "b"},
		})
	})

	t.Run("join-complicated", func(t *testing.T) {
		query := `SELECT
    c.id AS customer_id,
    c.name AS customer_name,
    c.email AS customer_email
FROM
    customers c
    INNER JOIN orders o ON c.id = o.customer_id
    LEFT JOIN payments p ON o.id = p.order_id
    INNER JOIN order_items oi ON o.id = oi.order_id
    INNER JOIN products prod ON oi.product_id = prod.id
WHERE
    o.order_date BETWEEN '2023-01-01' AND '2023-12-31'
    AND c.email LIKE '%@example.com%'
ORDER BY
    o.order_date DESC,
    c.name ASC;`
		ops, err := FindOperations(query)
		require.NoError(t, err)
		require.ElementsMatch(t, ops, []Operation{
			{Type: Select, Table: "customers", Column: "id"},
			{Type: Select, Table: "customers", Column: "name"},
			{Type: Select, Table: "customers", Column: "email"},
			{Type: Join, Table: "customers", Column: "id"},
			{Type: Join, Table: "orders", Column: "customer_id"},
			{Type: Join, Table: "orders", Column: "id"},
			{Type: Join, Table: "payments", Column: "order_id"},
			{Type: Join, Table: "order_items", Column: "order_id"},
			{Type: Join, Table: "order_items", Column: "product_id"},
			{Type: Join, Table: "products", Column: "id"},
		})
	})

	t.Run("join-with-subquery", func(t *testing.T) {
		query := `SELECT
    c.name AS customer_name,
    total_orders.total_order_count,
    total_orders.total_order_amount
FROM
    customers c
INNER JOIN (
    SELECT
        o.customer_id,
        COUNT(o.id) AS total_order_count,
        SUM(o.total_amount) AS total_order_amount
    FROM
        orders o
    GROUP BY
        o.customer_id
) AS total_orders ON c.id = total_orders.customer_id
WHERE
    total_orders.total_order_amount > 1000
ORDER BY
    total_orders.total_order_amount DESC;`
		ops, err := FindOperations(query)
		require.NoError(t, err)
		require.ElementsMatch(t, ops, []Operation{
			{Type: Select, Table: "customers", Column: "name"},
			{Type: Select, Table: "orders", Column: "customer_id"},
			{Type: Select, Table: "orders", Column: "total_amount"},
			{Type: Select, Table: "orders", Column: "id"},
			{Type: Join, Table: "customers", Column: "id"},
		})

		query = `SELECT
    cat.name AS category_name,
    sales_summary.total_sales_count,
    sales_summary.total_sales_amount
FROM
    categories cat
INNER JOIN (
    SELECT
        p.category_id,
        COUNT(s.id) AS total_sales_count,
        SUM(s.amount) AS total_sales_amount
    FROM
        sales s
    INNER JOIN products p ON s.product_id = p.id
    GROUP BY
        p.category_id
) AS sales_summary ON cat.id = sales_summary.category_id
WHERE
    sales_summary.total_sales_amount > 5000
ORDER BY
    sales_summary.total_sales_amount DESC;`
		ops, err = FindOperations(query)
		require.NoError(t, err)
		require.ElementsMatch(t, ops, []Operation{
			{Type: Select, Table: "categories", Column: "name"},
			{Type: Select, Table: "products", Column: "category_id"},
			{Type: Select, Table: "sales", Column: "id"},
			{Type: Select, Table: "sales", Column: "amount"},
			{Type: Join, Table: "products", Column: "id"},
			{Type: Join, Table: "sales", Column: "product_id"},
			{Type: Join, Table: "categories", Column: "id"},
		})
	})

	t.Run("update", func(t *testing.T) {
		query := `update table1 set a = 1, b = 2;`
		ops, err := FindOperations(query)
		require.NoError(t, err)
		require.ElementsMatch(t, ops, []Operation{
			{Type: Update, Table: "table1", Column: "a"},
			{Type: Update, Table: "table1", Column: "b"},
		})
	})

	t.Run("update-with-subselect", func(t *testing.T) {
		query := `update table1 set a = (select max((select min(c) from table3 where table3.c = table2.d)) from table2), b = a;`
		ops, err := FindOperations(query)
		require.NoError(t, err)
		require.ElementsMatch(t, ops, []Operation{
			{Type: Select, Table: "table2", Column: "d"},
			{Type: Select, Table: "table3", Column: "c"},
			{Type: Update, Table: "table1", Column: "a"},
			{Type: Update, Table: "table1", Column: "b"},
		})
	})

	t.Run("update-with-subquery-complicated", func(t *testing.T) {
		query := `UPDATE customers
SET discount_rate = 
    CASE
        WHEN total_spent > 10000 THEN 0.20
        WHEN total_spent > 5000 THEN 0.10
        ELSE discount_rate
    END
FROM (
    SELECT
        o.customer_id,
        SUM(o.total_amount) AS total_spent
    FROM
        orders o
    WHERE
        o.order_date >= (CURRENT_DATE - INTERVAL '1 year')
    GROUP BY
        o.customer_id
) AS spending
WHERE
    customers.id = spending.customer_id;`
		ops, err := FindOperations(query)
		require.NoError(t, err)
		require.ElementsMatch(t, ops, []Operation{
			{Type: Select, Table: "customers", Column: "discount_rate"},
			{Type: Select, Table: "orders", Column: "customer_id"},
			{Type: Select, Table: "orders", Column: "total_amount"},
			{Type: Select, Table: "orders", Column: "order_date"},
			{Type: Select, Table: "customers", Column: "id"},
			{Type: Update, Table: "customers", Column: "discount_rate"},
		})
	})

	queryWithCTE := `
WITH DepartmentSalaries AS (
    SELECT e.employee_id, e.salary, d.department_name
    FROM employees e
    JOIN departments d ON e.department_id = d.department_id
    WHERE d.department_name = 'Engineering'
)
UPDATE employees
SET salary = salary * 1.1
WHERE employee_id IN (SELECT employee_id FROM DepartmentSalaries);`
	_ = queryWithCTE

}
