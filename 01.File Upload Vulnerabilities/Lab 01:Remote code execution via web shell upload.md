```text
┌────────────────────────────────────────────────────────────────────────┐
│                   UNRESTRICTED RCE UPLOAD TESTING FLOW                 │
└────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
          ┌──────────────────────────────────────────────────┐
          │ Phase 1: Tech Stack & Upload Handler Recon       │
          └──────────────────────────────────────────────────┘
                                   │
                                   ▼
          ┌──────────────────────────────────────────────────┐
          │ Phase 2: Unrestricted File Upload Attempt        │
          └──────────────────────────────────────────────────┘
                                   │
                                   ▼
          ┌──────────────────────────────────────────────────┐
          │ Phase 3: Path Identification & Execution Test    │
          └──────────────────────────────────────────────────┘
                                   │
                                   ▼
          ┌──────────────────────────────────────────────────┐
          │ Phase 4: Risk Proof-of-Concept & Verification    │
          └──────────────────────────────────────────────────┘

```

---

### Step-by-Step Methodology Flow

#### Phase 1: Tech Stack & Upload Handler Recon

* **Technology Fingerprinting:** Identify the target server runtime before selecting a payload format:
* **PHP:** Apache / Nginx + PHP-FPM (`.php`, `.phtml`, `.php5`)
* **ASP.NET:** IIS Server (`.aspx`, `.asp`, `.ashx`)
* **Java:** Tomcat / WildFly (`.jsp`, `.jspx`, `.war`)


* **Baseline Functional Upload:** Upload a legitimate asset (e.g., `avatar.png`) while monitoring traffic in Burp Suite.
* **Storage Location Discovery:** Locate where the server stores and serves uploaded assets:
* Inspect the HTML source for image rendering (`<img src="/static/uploads/avatars/avatar.png">`).
* Check HTTP response headers (`Location`, `Content-Location`, or JSON response payloads containing relative paths).



---

#### Phase 2: Unrestricted File Upload Attempt

* **Craft a Benign Script Payload:** Match your script extension to the backend technology stack.
* *Analogy:* A web shell upload is like a digital Trojan Horse—if the security guard (backend) accepts the package without opening it, and the inner courtyard (execution engine) runs whatever is inside, you gain total control.


* **Submit Raw Script File:** Upload `poc.php` directly through the application's file upload interface without modifying any headers, extensions, or file contents.
* **Analyze Application Response:**
* **HTTP 200/201 (Accepted):** The backend lacks basic file type validation. Proceed immediately to execution testing.
* **HTTP 400/403/422 (Rejected):** Validation is active. Note the specific error message (e.g., "Invalid extension", "MIME type not allowed") to determine whether to test Content-Type bypasses, extension bypasses, or magic byte injection.



---

#### Phase 3: Path Identification & Execution Test

* **Construct the Full Request Path:** Combine the base URL with the relative upload directory discovered in Phase 1 (e.g., `[https://example.com/files/avatars/poc.php](https://example.com/files/avatars/poc.php)`).
* **Issue Direct GET Request:** Request the script file directly in Burp Repeater or the browser.
* **Confirmation Conditions for RCE:**
* **Executed Output Rendered:** The server processes the file via its script interpreter (e.g., PHP-FPM) and returns the string output of your functions. **Vulnerability Confirmed.**
* **Raw Code Rendered:** The file was uploaded, but the directory lacks execution rights (e.g., `engine = off`).
* **Forced Download:** The server responds with `Content-Disposition: attachment`, treating the file as a static download rather than executing it.



---

### Real-World Response Matrix

| Upload Response | GET File Response | Server State | Next Action Step |
| --- | --- | --- | --- |
| `200 OK (Uploaded)` | `200 OK (Output Rendered)` | No file validation + Executable directory. | **Critical RCE Confirmed.** Stop testing and prepare report. |
| `200 OK (Uploaded)` | `200 OK (Raw Source Code)` | No file validation + Non-executable directory. | Pivot to **Path Traversal** (`../poc.php`) to reach an executable folder. |
| `200 OK (Uploaded)` | `404 Not Found` | File renamed automatically or stored outside web root. | Perform path brute-forcing or analyze asset generation logic (e.g., UUIDs/Hashes). |
| `400 / 403 (Rejected)` | N/A | Validation controls present. | Pivot to **Content-Type Bypass**, **Extension Bypasses**, or **Polyglot Files**. |

---

### Critical Real-World Factors

* **Cloud & S3 Architecture:** Modern web applications frequently store user uploads in object storage (e.g., AWS S3, Google Cloud Storage, Azure Blob).
* If the file lands directly in an S3 bucket, **Remote Code Execution is impossible** because S3 serves static objects without an application execution runtime.
* *Impact Shift:* Check if uploading `.html` or `.svg` files allows Stored Cross-Site Scripting (XSS).


* **Web Application Firewalls (WAF):** WAFs analyze incoming request bodies for known shell signatures (`system()`, `passthru()`, `shell_exec()`).
* Use lightweight, non-malicious verification payloads:
```php
<?php echo "RCE_VERIFICATION_" . (4000 + 42); ?>

```




* **Safe Ethical Hacking PoC Standard:**
* **Never** upload fully featured public web shells (e.g., `b374k`, `c99`, or interactive command shells).
* Demonstrating command execution via benign functions (e.g., `phpversion()`, `phpinfo()`, or simple arithmetic echo statements) fully satisfies vulnerability reporting criteria without leaving high-risk backdoors on target infrastructure.



---

### Related Next Steps to Explore

* **Bypassing Extension Blacklists:** Exploiting weak regex filters using alternate extensions (`.phtml`, `.php7`, `.inc`, `.phar`, `.htaccess`).
* **Polyglot Web Shells:** Concealing executable web shell code within image binary headers (e.g., EXIF metadata) to pass deep inspection filters.
* **Server Infrastructure Hardening:** Restricting execution permissions on upload directories (`noexec` mount flags) and implementing random file renaming algorithms.

---

> **Key Insight:** Unrestricted file upload into a web-accessible directory is the most direct attack vector in web security, turning a simple HTTP POST request into complete system-level command execution.
