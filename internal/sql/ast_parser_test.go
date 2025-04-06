package sql

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQueryCondition(t *testing.T) {
	t.Run("select-all", func(t *testing.T) {
		query := "select * from table1;"
		ops, err := ExtractQueryStatements(query)
		require.NoError(t, err)
		require.ElementsMatch(t, ops, []QueryStatement{
			{Type: Select, Table: "table1", Column: ""},
		})
	})
	t.Run("delete-all", func(t *testing.T) {
		query := "delete from table1;"
		ops, err := ExtractQueryStatements(query)
		require.NoError(t, err)
		require.ElementsMatch(t, ops, []QueryStatement{
			{Type: Delete, Table: "table1", Column: ""},
		})
	})
	t.Run("simple", func(t *testing.T) {
		query := "select tt.a, tt.b from table1 as tt;"
		ops, err := ExtractQueryStatements(query)
		require.NoError(t, err)
		require.ElementsMatch(t, ops, []QueryStatement{
			{Type: Select, Table: "table1", Column: "a"},
			{Type: Select, Table: "table1", Column: "b"},
		})
	})
	t.Run("subquery", func(t *testing.T) {
		query := "select tt.a, tt.b from (select a, b from table1) as tt;"
		ops, err := ExtractQueryStatements(query)
		require.NoError(t, err)
		require.ElementsMatch(t, ops, []QueryStatement{
			{Type: Select, Table: "table1", Column: "a"},
			{Type: Select, Table: "table1", Column: "b"},
		})

		query = "select tt.a, tt.b from (select tt.a, tt.b from table1 as tt) as tt;"
		ops, err = ExtractQueryStatements(query)
		require.NoError(t, err)
		require.ElementsMatch(t, ops, []QueryStatement{
			{Type: Select, Table: "table1", Column: "a"},
			{Type: Select, Table: "table1", Column: "b"},
		})

		query = "select tt.a, table2.c from (select tt.a, tt.b from table1 as tt) as tt, table2;"
		ops, err = ExtractQueryStatements(query)
		require.NoError(t, err)
		require.ElementsMatch(t, ops, []QueryStatement{
			{Type: Select, Table: "table1", Column: "a"},
			{Type: Select, Table: "table1", Column: "b"},
			{Type: Select, Table: "table2", Column: "c"},
		})

		query = "select tt.a, c from (select tt.a, tt.b from table1 as tt) as tt, table2;"
		ops, err = ExtractQueryStatements(query)
		require.NoError(t, err)
		require.ElementsMatch(t, ops, []QueryStatement{
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

		ops, err := ExtractQueryStatements(query)
		require.NoError(t, err)
		require.ElementsMatch(t, ops, []QueryStatement{
			{Type: Select, Table: "orders", Column: "order_id"},
			{Type: Select, Table: "orders", Column: "order_date"},
			{Type: Select, Table: "orders", Column: "user_id"},
			{Type: Select, Table: "order_items", Column: "order_id"},
			{Type: Select, Table: "users", Column: "user_id"},
			{Type: Select, Table: "users", Column: "name"},
		})
	})

	t.Run("join", func(t *testing.T) {
		query := "select a from table1 inner join table2 on b = a"
		ops, err := ExtractQueryStatements(query)
		require.NoError(t, err)
		require.ElementsMatch(t, ops, []QueryStatement{
			{Type: Select, Table: "table1", Column: "a"},
			{Type: Join, Table: "", Column: "a"},
			{Type: Join, Table: "", Column: "b"},
		})

		query = "select table1.a from table1 inner join table2 on table2.b = table1.a"
		ops, err = ExtractQueryStatements(query)
		require.NoError(t, err)
		require.ElementsMatch(t, ops, []QueryStatement{
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
		ops, err := ExtractQueryStatements(query)
		require.NoError(t, err)
		require.ElementsMatch(t, ops, []QueryStatement{
			{Type: Select, Table: "customers", Column: "id"},
			{Type: Select, Table: "customers", Column: "name"},
			{Type: Select, Table: "customers", Column: "email"},
			{Type: Select, Table: "orders", Column: "order_date"},
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
		ops, err := ExtractQueryStatements(query)
		require.NoError(t, err)
		require.ElementsMatch(t, ops, []QueryStatement{
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
		ops, err = ExtractQueryStatements(query)
		require.NoError(t, err)
		require.ElementsMatch(t, ops, []QueryStatement{
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
		ops, err := ExtractQueryStatements(query)
		require.NoError(t, err)
		require.ElementsMatch(t, ops, []QueryStatement{
			{Type: Update, Table: "table1", Column: "a"},
			{Type: Update, Table: "table1", Column: "b"},
		})
	})

	t.Run("update-with-subselect", func(t *testing.T) {
		query := `update table1 set a = (select max((select min(c) from table3 where table3.c = table2.d)) from table2), b = a;`
		ops, err := ExtractQueryStatements(query)
		require.NoError(t, err)
		require.ElementsMatch(t, ops, []QueryStatement{
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
		ops, err := ExtractQueryStatements(query)
		require.NoError(t, err)
		require.ElementsMatch(t, ops, []QueryStatement{
			{Type: Select, Table: "customers", Column: "discount_rate"},
			{Type: Select, Table: "orders", Column: "customer_id"},
			{Type: Select, Table: "orders", Column: "total_amount"},
			{Type: Select, Table: "orders", Column: "order_date"},
			{Type: Select, Table: "customers", Column: "id"},
			{Type: Update, Table: "customers", Column: "discount_rate"},
		})
	})

	t.Run("delete", func(t *testing.T) {
		query := `delete from table1 where a = 1;`
		ops, err := ExtractQueryStatements(query)
		require.NoError(t, err)
		require.ElementsMatch(t, ops, []QueryStatement{
			{Type: Delete, Table: "table1", Column: "a"},
		})

		query = `delete from table1 where a = (select max(b) from table2);`
		ops, err = ExtractQueryStatements(query)
		require.NoError(t, err)
		require.ElementsMatch(t, ops, []QueryStatement{
			{Type: Delete, Table: "table1", Column: "a"},
			{Type: Select, Table: "table2", Column: "b"},
		})
	})

	t.Run("delete-select-update-complicated", func(t *testing.T) {
		query := `DELETE FROM customers
USING (
    SELECT c.id
    FROM customers c
    LEFT JOIN orders o ON c.id = o.customer_id AND o.order_date >= (CURRENT_DATE - INTERVAL '1 year')
    WHERE c.active = FALSE AND o.id IS NULL
) AS inactive_customers
WHERE customers.id = inactive_customers.id;`
		ops, err := ExtractQueryStatements(query)
		require.NoError(t, err)
		require.ElementsMatch(t, ops, []QueryStatement{
			{Type: Select, Table: "customers", Column: "active"},
			{Type: Select, Table: "customers", Column: "id"},
			{Type: Select, Table: "orders", Column: "id"},
			{Type: Join, Table: "customers", Column: "id"},
			{Type: Join, Table: "orders", Column: "customer_id"},
			{Type: Join, Table: "orders", Column: "order_date"},
			{Type: Delete, Table: "customers", Column: "id"},
		})
	})

	t.Run("update-with-having", func(t *testing.T) {
		query := `UPDATE customers
	SET account_balance = 0
	FROM (
		SELECT c.id
	FROM customers c
	INNER JOIN orders o ON c.id = o.customer_id
	WHERE o.order_date >= (CURRENT_DATE - INTERVAL '1 year')
	GROUP BY c.id
	HAVING SUM(o.total_amount) < -1000
	) AS excessive_returns
	WHERE customers.id = excessive_returns.id;`
		ops, err := ExtractQueryStatements(query)
		require.NoError(t, err)
		require.ElementsMatch(t, ops, []QueryStatement{
			{Type: Select, Table: "customers", Column: "id"},
			{Type: Select, Table: "orders", Column: "total_amount"},
			{Type: Select, Table: "orders", Column: "order_date"},
			{Type: Join, Table: "orders", Column: "customer_id"},
			{Type: Join, Table: "customers", Column: "id"},
			{Type: Update, Table: "customers", Column: "account_balance"},
		})
	})

	t.Run("insert", func(t *testing.T) {
		query := `insert into table1 (a, b) values ((select max(c) from table1), (select min(c) from table2)) 
on conflict do update set a = (select 1), b = (select min(c) from table2);`
		ops, err := ExtractQueryStatements(query)
		require.NoError(t, err)
		require.ElementsMatch(t, ops, []QueryStatement{
			{Type: Select, Table: "table1", Column: "c"},
			{Type: Select, Table: "table2", Column: "c"},
			{Type: Update, Table: "table1", Column: "a"},
			{Type: Update, Table: "table1", Column: "b"},
			{Type: Insert, Table: "table1", Column: "a"},
			{Type: Insert, Table: "table1", Column: "b"},
		})
	})

	t.Run("cte", func(t *testing.T) {
		query := `
WITH DepartmentSalaries AS (
    SELECT e.employee_id, e.salary, d.department_name
    FROM employees e
    JOIN departments d ON e.department_id = d.department_id
    WHERE d.department_name = 'Engineering'
)
UPDATE employees
SET salary = salary * 1.1
WHERE employee_id IN (SELECT employee_id FROM DepartmentSalaries);`
		ops, err := ExtractQueryStatements(query)
		require.NoError(t, err)
		require.ElementsMatch(t, ops, []QueryStatement{
			{Type: Select, Table: "employees", Column: "salary"},
			{Type: Select, Table: "employees", Column: "employee_id"},
			{Type: Select, Table: "departments", Column: "department_name"},
			{Type: Join, Table: "employees", Column: "department_id"},
			{Type: Join, Table: "departments", Column: "department_id"},
			{Type: Update, Table: "employees", Column: "salary"},
		})
	})

	t.Run("mixed-complicated-queries", func(t *testing.T) {
		t.Run("nested-subqueries", func(t *testing.T) {
			query := `
SELECT e.employee_id, e.salary
FROM employees e
WHERE e.salary > (
    SELECT AVG(salary)
    FROM employees
    WHERE department_id = e.department_id
);`

			ops, err := ExtractQueryStatements(query)
			require.NoError(t, err)
			require.ElementsMatch(t, ops, []QueryStatement{
				{Type: Select, Table: "employees", Column: "employee_id"},
				{Type: Select, Table: "employees", Column: "salary"},
				{Type: Select, Table: "employees", Column: "department_id"},
			})
		})

		t.Run("multiple-joins", func(t *testing.T) {
			query := `
SELECT e.employee_id, e.first_name, d.department_name, l.city
FROM employees e
JOIN departments d ON e.department_id = d.department_id
JOIN locations l ON d.location_id = l.location_id
WHERE l.country_id = 'US';`

			ops, err := ExtractQueryStatements(query)
			require.NoError(t, err)
			require.ElementsMatch(t, ops, []QueryStatement{
				{Type: Select, Table: "employees", Column: "employee_id"},
				{Type: Select, Table: "employees", Column: "first_name"},
				{Type: Select, Table: "departments", Column: "department_name"},
				{Type: Select, Table: "locations", Column: "city"},
				{Type: Join, Table: "employees", Column: "department_id"},
				{Type: Join, Table: "departments", Column: "department_id"},
				{Type: Join, Table: "departments", Column: "location_id"},
				{Type: Join, Table: "locations", Column: "location_id"},
				{Type: Select, Table: "locations", Column: "country_id"},
			})
		})

		t.Run("complex-cte", func(t *testing.T) {
			query := `
WITH SalaryIncrease AS (
    SELECT employee_id, salary * 1.1 AS new_salary
    FROM employees
    WHERE department_id IN (
        SELECT department_id
        FROM departments
        WHERE location_id = 1700
    )
)
UPDATE employees
SET salary = (SELECT new_salary FROM SalaryIncrease WHERE employee_id = employees.employee_id)
WHERE employee_id IN (SELECT employee_id FROM SalaryIncrease);`

			ops, err := ExtractQueryStatements(query)
			require.NoError(t, err)
			require.ElementsMatch(t, ops, []QueryStatement{
				{Type: Select, Table: "employees", Column: "employee_id"},
				{Type: Select, Table: "employees", Column: "salary"},
				{Type: Select, Table: "employees", Column: "department_id"},
				{Type: Select, Table: "departments", Column: "department_id"},
				{Type: Select, Table: "departments", Column: "location_id"},
				{Type: Update, Table: "employees", Column: "salary"},
			})
		})

		t.Run("group-by-having", func(t *testing.T) {
			query := `
SELECT d.department_name, AVG(e.salary) AS avg_salary
FROM employees e
JOIN departments d ON e.department_id = d.department_id
GROUP BY d.department_name
HAVING AVG(e.salary) > 50000;`

			ops, err := ExtractQueryStatements(query)
			require.NoError(t, err)
			require.ElementsMatch(t, ops, []QueryStatement{
				{Type: Select, Table: "departments", Column: "department_name"},
				{Type: Select, Table: "employees", Column: "salary"},
				{Type: Join, Table: "employees", Column: "department_id"},
				{Type: Join, Table: "departments", Column: "department_id"},
			})
		})

		t.Run("window-functions", func(t *testing.T) {
			query := `
SELECT employee_id, salary, 
       RANK() OVER (PARTITION BY department_id ORDER BY salary DESC) as rank
FROM employees;`

			ops, err := ExtractQueryStatements(query)
			require.NoError(t, err)
			require.ElementsMatch(t, ops, []QueryStatement{
				{Type: Select, Table: "employees", Column: "employee_id"},
				{Type: Select, Table: "employees", Column: "salary"},
				{Type: Select, Table: "employees", Column: "department_id"},
			})
		})

		t.Run("complex-union", func(t *testing.T) {
			query := `
SELECT employee_id, first_name
FROM employees
WHERE salary > 50000
UNION
SELECT employee_id, first_name
FROM managers
WHERE salary > 100000;`

			ops, err := ExtractQueryStatements(query)
			require.NoError(t, err)
			require.ElementsMatch(t, ops, []QueryStatement{
				{Type: Select, Table: "employees", Column: "employee_id"},
				{Type: Select, Table: "employees", Column: "first_name"},
				{Type: Select, Table: "employees", Column: "salary"},
				{Type: Select, Table: "managers", Column: "employee_id"},
				{Type: Select, Table: "managers", Column: "first_name"},
				{Type: Select, Table: "managers", Column: "salary"},
			})
		})

		t.Run("delete", func(t *testing.T) {
			query := `
DELETE FROM employees
WHERE department_id = (
    SELECT department_id
    FROM departments
    WHERE department_name = 'Sales'
);`

			ops, err := ExtractQueryStatements(query)
			require.NoError(t, err)
			require.ElementsMatch(t, ops, []QueryStatement{
				{Type: Delete, Table: "employees", Column: "department_id"},
				{Type: Select, Table: "departments", Column: "department_id"},
				{Type: Select, Table: "departments", Column: "department_name"},
			})
		})

		t.Run("insert-select", func(t *testing.T) {
			query := `
INSERT INTO high_salary_employees (employee_id, salary)
SELECT employee_id, salary
FROM employees
WHERE salary > 100000;`

			ops, err := ExtractQueryStatements(query)
			require.NoError(t, err)
			require.ElementsMatch(t, ops, []QueryStatement{
				{Type: Insert, Table: "high_salary_employees", Column: "employee_id"},
				{Type: Insert, Table: "high_salary_employees", Column: "salary"},
				{Type: Select, Table: "employees", Column: "employee_id"},
				{Type: Select, Table: "employees", Column: "salary"},
			})
		})

		t.Run("aggregate-functions", func(t *testing.T) {
			query := `
SELECT department_id, COUNT(*) as num_employees, MAX(salary) as max_salary
FROM employees
GROUP BY department_id;`

			ops, err := ExtractQueryStatements(query)
			require.NoError(t, err)
			require.ElementsMatch(t, ops, []QueryStatement{
				{Type: Select, Table: "employees", Column: "department_id"},
				{Type: Select, Table: "employees", Column: "salary"},
			})
		})

		t.Run("recursive-cte", func(t *testing.T) {
			query := `
WITH RECURSIVE EmployeeHierarchy AS (
    SELECT employee_id, manager_id, first_name
    FROM employees
    WHERE manager_id IS NULL
    UNION ALL
    SELECT e.employee_id, e.manager_id, e.first_name
    FROM employees e
    INNER JOIN EmployeeHierarchy eh ON e.manager_id = eh.employee_id
)
SELECT employee_id, first_name
FROM EmployeeHierarchy;`

			ops, err := ExtractQueryStatements(query)
			require.NoError(t, err)
			require.ElementsMatch(t, ops, []QueryStatement{
				{Type: Select, Table: "employees", Column: "employee_id"},
				{Type: Select, Table: "employees", Column: "manager_id"},
				{Type: Select, Table: "employees", Column: "first_name"},
				{Type: Join, Table: "employees", Column: "manager_id"},
			})
		})

		t.Run("full-outer-join", func(t *testing.T) {
			query := `
SELECT e.employee_id, e.first_name, d.department_name
FROM employees e
FULL OUTER JOIN departments d ON e.department_id = d.department_id;`

			ops, err := ExtractQueryStatements(query)
			require.NoError(t, err)
			require.ElementsMatch(t, ops, []QueryStatement{
				{Type: Select, Table: "employees", Column: "employee_id"},
				{Type: Select, Table: "employees", Column: "first_name"},
				{Type: Select, Table: "departments", Column: "department_name"},
				{Type: Join, Table: "employees", Column: "department_id"},
				{Type: Join, Table: "departments", Column: "department_id"},
			})
		})

		t.Run("cross-join", func(t *testing.T) {
			query := `
SELECT e.first_name, p.project_name
FROM employees e
CROSS JOIN projects p;`

			ops, err := ExtractQueryStatements(query)
			require.NoError(t, err)
			require.ElementsMatch(t, ops, []QueryStatement{
				{Type: Select, Table: "employees", Column: "first_name"},
				{Type: Select, Table: "projects", Column: "project_name"},
			})
		})

		t.Run("case-statement", func(t *testing.T) {
			query := `
SELECT employee_id,
       CASE 
           WHEN salary < 40000 THEN 'Low'
           WHEN salary BETWEEN 40000 AND 80000 THEN 'Medium'
           ELSE 'High'
       END as salary_range
FROM employees;`

			ops, err := ExtractQueryStatements(query)
			require.NoError(t, err)
			require.ElementsMatch(t, ops, []QueryStatement{
				{Type: Select, Table: "employees", Column: "employee_id"},
				{Type: Select, Table: "employees", Column: "salary"},
			})
		})

		t.Run("lateral-join", func(t *testing.T) {
			query := `
SELECT e.first_name, e.last_name, j.recent_job
FROM employees e
LEFT JOIN LATERAL (
    SELECT job_id AS recent_job
    FROM jobs
    WHERE employee_id = e.employee_id
    ORDER BY start_date DESC
    LIMIT 1
) j ON true;`

			ops, err := ExtractQueryStatements(query)
			require.NoError(t, err)
			require.ElementsMatch(t, ops, []QueryStatement{
				{Type: Select, Table: "employees", Column: "first_name"},
				{Type: Select, Table: "employees", Column: "last_name"},
				{Type: Select, Table: "employees", Column: "employee_id"},
				{Type: Select, Table: "jobs", Column: "job_id"},
				{Type: Select, Table: "jobs", Column: "employee_id"},
			})
		})

		t.Run("super-complex-query", func(t *testing.T) {
			query := `
WITH RECURSIVE EmployeeHierarchy AS (
    SELECT e.employee_id, e.manager_id, e.first_name, e.department_id, 1 AS depth
    FROM employees e
    WHERE e.manager_id IS NULL
    UNION ALL
    SELECT e.employee_id, e.manager_id, e.first_name, e.department_id, eh.depth + 1
    FROM employees e
    INNER JOIN EmployeeHierarchy eh ON e.manager_id = eh.employee_id
),
DepartmentStatistics AS (
    SELECT d.department_id, d.department_name, COUNT(e.employee_id) AS employee_count, AVG(e.salary) AS avg_salary
    FROM departments d
    LEFT JOIN employees e ON d.department_id = e.department_id
    GROUP BY d.department_id, d.department_name
    HAVING COUNT(e.employee_id) > 5
),
RecentHighEarners AS (
    SELECT e.employee_id, e.first_name, e.salary
    FROM employees e
    WHERE e.salary > (SELECT AVG(salary) FROM employees) AND e.hire_date > '2020-01-01'
    ORDER BY e.salary DESC
    LIMIT 10
)
SELECT eh.first_name AS employee_name, 
       eh.depth, 
       ds.department_name, 
       ds.employee_count, 
       ds.avg_salary, 
       rhe.salary AS recent_high_earner_salary
FROM EmployeeHierarchy eh
JOIN DepartmentStatistics ds ON eh.department_id = ds.department_id
LEFT JOIN RecentHighEarners rhe ON eh.employee_id = rhe.employee_id
ORDER BY eh.depth DESC, ds.avg_salary DESC;`

			ops, err := ExtractQueryStatements(query)
			require.NoError(t, err)
			require.ElementsMatch(t, ops, []QueryStatement{
				// EmployeeHierarchy CTE operations
				{Type: Select, Table: "employees", Column: "employee_id"},
				{Type: Select, Table: "employees", Column: "manager_id"},
				{Type: Select, Table: "employees", Column: "first_name"},
				{Type: Select, Table: "employees", Column: "department_id"},
				{Type: Join, Table: "employees", Column: "manager_id"},

				// DepartmentStatistics CTE operations
				{Type: Select, Table: "departments", Column: "department_id"},
				{Type: Select, Table: "departments", Column: "department_name"},
				{Type: Select, Table: "employees", Column: "salary"},
				{Type: Join, Table: "departments", Column: "department_id"},
				{Type: Join, Table: "employees", Column: "department_id"},

				// RecentHighEarners CTE operations
				{Type: Select, Table: "employees", Column: "hire_date"},
			})
		})

		t.Run("complex-update-from-select", func(t *testing.T) {
			query := `
UPDATE employees
SET salary = salary * 1.05
WHERE department_id IN (
    SELECT department_id
    FROM departments
    WHERE location_id = (
        SELECT location_id
        FROM locations
        WHERE city = 'New York'
    )
);`

			ops, err := ExtractQueryStatements(query)
			require.NoError(t, err)
			require.ElementsMatch(t, ops, []QueryStatement{
				{Type: Update, Table: "employees", Column: "salary"},
				{Type: Select, Table: "employees", Column: "department_id"},
				{Type: Select, Table: "departments", Column: "department_id"},
				{Type: Select, Table: "departments", Column: "location_id"},
				{Type: Select, Table: "locations", Column: "location_id"},
				{Type: Select, Table: "locations", Column: "city"},
			})
		})

		t.Run("insert-with-cte-and-having", func(t *testing.T) {
			query := `
WITH HighAvgs AS (
    SELECT department_id, AVG(salary) avg_salary
    FROM employees
    GROUP BY department_id
    HAVING AVG(salary) > 75000
)
INSERT INTO high_salary_departments (department_id, avg_salary)
SELECT department_id, avg_salary
FROM HighAvgs;`

			ops, err := ExtractQueryStatements(query)
			require.NoError(t, err)
			require.ElementsMatch(t, ops, []QueryStatement{
				{Type: Select, Table: "employees", Column: "department_id"},
				{Type: Select, Table: "employees", Column: "salary"},
				{Type: Insert, Table: "high_salary_departments", Column: "department_id"},
			})
		})

		t.Run("complex-delete-with-subquery", func(t *testing.T) {
			query := `
DELETE FROM employees
WHERE employee_id IN (
    SELECT employee_id
    FROM employees e
    JOIN projects p ON e.employee_id = p.employee_id
    WHERE p.end_date < '2023-01-01'
    GROUP BY employee_id
    HAVING COUNT(p.project_id) < 2
);`

			ops, err := ExtractQueryStatements(query)
			require.NoError(t, err)
			require.ElementsMatch(t, ops, []QueryStatement{
				{Type: Delete, Table: "employees", Column: "employee_id"},
				{Type: Select, Table: "employees", Column: "employee_id"},
				{Type: Join, Table: "employees", Column: "employee_id"},
				{Type: Join, Table: "projects", Column: "employee_id"},
				{Type: Select, Table: "projects", Column: "end_date"},
				{Type: Select, Table: "projects", Column: "project_id"},
			})
		})
	})
}
