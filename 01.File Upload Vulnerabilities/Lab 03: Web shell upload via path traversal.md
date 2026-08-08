```text
┌────────────────────────────────────────────────────────────────────────┐
│                        REAL-WORLD TESTING FLOW                         │
└────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
          ┌──────────────────────────────────────────────────┐
          │ Phase 1: Endpoint Reconnaissance & Baseline Tests │
          └──────────────────────────────────────────────────┘
                                   │
                                   ▼
          ┌──────────────────────────────────────────────────┐
          │ Phase 2: Path Traversal Injection & Bypass       │
          └──────────────────────────────────────────────────┘
                                   │
                                   ▼
          ┌──────────────────────────────────────────────────┐
          │ Phase 3: Execution Context Verification          │
          └──────────────────────────────────────────────────┘
                                   │
                                   ▼
          ┌──────────────────────────────────────────────────┐
          │ Phase 4: Risk Impact Assessment & Reporting PoC  │
          └──────────────────────────────────────────────────┘

```

---

### Step-by-Step Methodology Flow

#### Phase 1: Endpoint Reconnaissance & Baseline Tests

* **Target Identification:** Locate all functionality accepting user uploads (profile photos, document submissions, attachment forms, CSV imports).
* **Baseline Upload:** Upload a harmless image file (e.g., `test.png`) while capturing the traffic in Burp Suite.
* **Storage Location Analysis:** Determine how the application serves the uploaded file:
* *Direct File Access:* Served directly from a web root folder (e.g., `[https://example.com/uploads/avatars/test.png](https://example.com/uploads/avatars/test.png)`).
* *Indirect File Access:* Served via a database routing handler (e.g., `[https://example.com/download.php?id=8842](https://example.com/download.php?id=8842)`). Direct execution is rarely possible here unless path traversal alters the storage destination on disk.


* **Script Upload Test:** Attempt to upload a benign PHP/script file directly (e.g., `test.php` containing `<?php echo "VULN_TEST"; ?>`).
* If it uploads to `/uploads/` and executes when requested: **Direct Web Shell Vulnerability** exists (no path traversal needed).
* If it uploads to `/uploads/` but downloads or displays as raw text: The upload directory has script execution disabled (e.g., `php_admin_flag engine off` in Apache or restricted location block in Nginx). **Path traversal is required to move the file to an executable directory.**



---

#### Phase 2: Path Traversal Injection & Bypass Techniques

Modify the `filename` parameter within the `Content-Disposition` multipart header in Burp Repeater using progressive obfuscation techniques:

* **Standard Traversal:**
```http
Content-Disposition: form-data; name="avatar"; filename="../test.php"

```


* **Nested Traversal Bypass (if the server strips `../` sequentially):**
```http
Content-Disposition: form-data; name="avatar"; filename="....//test.php"

```


* **URL Encoding Bypass (if the server decodes input late in processing):**
* Single Encoding: `filename="..%2ftest.php"`
* Double Encoding: `filename="..%252ftest.php"`
* Encoded Null Byte (Legacy systems/PHP < 5.3.4): `filename="test.php%00.png"`


* **OS-Specific Separators:**
* Windows targets: `filename="..\\test.php"` or `filename="..%5ctest.php"`



---

#### Phase 3: Execution Context Verification

* **Analyze Upload Responses:** Look at the confirmation response returned by the application:
* `File uploaded to /avatars/test.php` -> Traversal sequence stripped.
* `File uploaded to /avatars/../test.php` or `File uploaded to /test.php` -> Traversal sequence processed.


* **Request the Payload Location:** Calculate where the file shifted to based on the base path.
* *Base:* `/static/images/avatars/`
* *Payload:* `../test.php`
* *Target Path:* `/static/images/test.php`


* **Evaluate Execution:** Send a `GET` request to the target path:
* **HTTP 200 OK + "VULN_TEST" in body:** Execution confirmed. Web shell path traversal vulnerability verified.
* **HTTP 200 OK + Raw PHP Code rendered:** File moved, but target directory also lacks execution permissions.
* **HTTP 404 Not Found:** File failed to write, was deleted by security controls, or traversed to a non-existent directory.
* **HTTP 403 Forbidden:** Directory permissions prevent reading/executing files in the parent directory.



---

### Real-World Response Matrix

| Response Pattern | Server Behavior | Next Action Step |
| --- | --- | --- |
| `File avatars/test.php saved` | Server strips `../` completely | Test nested traversal (`....//`) or double encoding (`..%252f`). |
| `File avatars/../test.php saved` | Server accepts encoded traversal | Access parent directory via HTTP GET to test code execution. |
| `400 Bad Request / WAF Block` | Web Application Firewall rule triggered | Test alternative bypasses (unicode slashes, parameter pollution). |
| `500 Internal Server Error` | File permission error or invalid path write | Adjust traversal depth (e.g., try `../` vs `../../../../tmp/`). |

---

### Critical Real-World Factors

* **Directory Execution Restrictions:** Upload folders (e.g., `/var/www/html/uploads/`) are usually configured with static file execution rules only. The primary objective of path traversal in file uploads is moving the script into a parent folder (e.g., `/var/www/html/`) where the web server handler (PHP-FPM, mod_php) processes scripts.
* **File System Permissions (DACL/POSIX):** The web server process (e.g., `www-data`, `nginx`, `IUSR`) must have write permissions on the directory you are traversing into. Traversing too far up (e.g., into `/var/www/` or root `/`) often fails due to permission denied errors.
* **Safe Proof-of-Concept (PoC) Policy:** In real-world penetration tests or bug bounty programs, **never** upload fully functional interactive web shells or destructive code (`system($_GET['cmd'])` or system file exfiltration).
* *Safe Payload Example:* `<?php echo "ProofOfConcept_" . rand(1000,9999); ?>` or `<?php phpinfo(); ?>`.
* Demonstrating file write outside the intended directory + execution of a randomized string provides full impact proof without introducing security risks to the target infrastructure.



