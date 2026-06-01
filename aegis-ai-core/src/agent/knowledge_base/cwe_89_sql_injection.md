# CWE-89 SQL Injection

Tags: cwe-89, sql, injection, prepared-statements

SQL injection happens when untrusted input is concatenated into SQL text. The
attacker can change query structure, bypass filters, read data, or modify rows.

## Fix template

- Use prepared statements or query builder APIs with bound parameters.
- Keep user input out of table names, column names, sort clauses, and raw SQL
  fragments unless a strict allowlist proves the value is safe.
- Prefer ORM lookup APIs for simple entity fetches.
- Do not rely on escaping alone for dynamic SQL construction.

## Review notes

Check whether the user-controlled value is part of SQL syntax or only a bound
value. Parameters protect values, not already-built query text.
