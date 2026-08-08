```text
┌────────────────────────────────────────────────────────────────────────┐
│                 CONTENT-TYPE BYPASS TESTING FLOW                       │
└────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
          ┌──────────────────────────────────────────────────┐
          │ Phase 1: Baseline Reconnaissance & Control Check │
          └──────────────────────────────────────────────────┘
                                   │
                                   ▼
          ┌──────────────────────────────────────────────────┐
          │ Phase 2: Content-Type Header Manipulation       │
          └──────────────────────────────────────────────────┘
                                   │
                                   ▼
          ┌──────────────────────────────────────────────────┐
          │ Phase 3: Execution Context Verification          │
          └──────────────────────────────────────────────────┘
                                   │
                                   ▼
          ┌──────────────────────────────────────────────────┐
          │ Phase 4: Impact Assessment & Safe PoC            │
          └──────────────────────────────────────────────────┘

```

---

### Step-by-Step Methodology Flow

#### Phase 1: Baseline Reconnaissance & Control Check

* **Identify Upload Functionality:** Locate any form that accepts files (profile photos, document attachments, identity verification uploads).
* **Capture Baseline Request:** Upload a valid file (e.g., `valid.jpg`) through Burp Suite.
* Inspect the `POST` body: Notice the header `Content-Type: image/jpeg` supplied automatically by the browser.


* **Attempt Unmodified Script Upload:** Upload a script file directly (e.g., `poc.php` containing a simple echo statement).
* Observe the server response. If the server responds with an error like `"Invalid file type: Only JPG/PNG allowed"`, determine *how* the application made that decision.



---

#### Phase 2: Content-Type Header Manipulation

* **Isolate the Validation Mechanism:** The application rejected `poc.php`. In web application development, this check typically happens in one of three places:
1. **Extension check** (verifying `.php` vs `.jpg`).
2. **Content-Type header check** (verifying `application/x-php` vs `image/jpeg`).
3. **Magic byte inspection** (checking actual file binary headers).


* **Execute the Bypass Test:**
* Send the rejected `POST` request for `poc.php` to **Burp Repeater**.
* Keep the filename intact (`filename="poc.php"`).
* Change the sub-header in the multipart body from:
```http
Content-Type: application/x-php

```


to:
```http
Content-Type: image/jpeg

```


* Click **Send**.



---

#### Phase 3: Execution Context Verification

* **Evaluate Upload Result:**
* If the server responds with **HTTP 200/201** and confirms file creation, the backend relies solely on the user-supplied `Content-Type` header (e.g., inspecting `$_FILES['avatar']['type']` in PHP without verifying the file on disk).


* **Test Code Execution:**
* Locate the direct path to the uploaded file (e.g., `[https://example.com/uploads/avatars/poc.php](https://example.com/uploads/avatars/poc.php)`).
* Issue a `GET` request to that URL in Burp or a browser.
* **Vulnerability Confirmed:** If the PHP code executes and renders the text output, the Content-Type restriction was the *only* control preventing execution.



---

### Real-World Response Matrix

| Upload Response | GET File Response | Root Cause | Next Action Step |
| --- | --- | --- | --- |
| `200 OK (Uploaded)` | `200 OK (Script Executes)` | Blind trust in client `Content-Type` + Directory allows execution. | **Vulnerability Confirmed.** Document PoC and report. |
| `200 OK (Uploaded)` | `200 OK (Displays raw PHP code)` | `Content-Type` bypass succeeded, but execution is disabled in `/uploads/`. | Combine with **Path Traversal** (`../poc.php`) to move to an executable directory. |
| `200 OK (Uploaded)` | `200 OK (Downloads file as attachment)` | Server forces static file download via `Content-Disposition: attachment`. | Attempt execution via Local File Inclusion (LFI) or XSS payloads (`.svg`/`.html`). |
| `400 / 403 (Rejected)` | N/A | Server checks Extension OR Magic Bytes, not just `Content-Type`. | Move to **Extension Bypass** (`poc.php.jpg`, `poc.phtml`) or **Magic Byte Injection**. |

---

### Critical Real-World Factors

* **Why Developers Make This Mistake:** Web frameworks often provide built-in file upload arrays (like PHP's `$_FILES`). The `$_FILES['userfile']['type']` variable is populated directly from the browser's HTTP `Content-Type` header. Novice developers inspect this string rather than running server-side MIME detection functions (like `finfo_file()`).
* **Cloud & S3 Storage Environments:** Modern enterprise applications often upload files directly to cloud storage buckets (AWS S3, Azure Blob, Google Cloud Storage) or serve them behind a CDN.
* If `poc.php` lands in an S3 bucket, it **will not execute** server-side code because S3 is static file storage.
* *Impact Shift:* Instead of Remote Code Execution (RCE), test if changing `Content-Type` to `text/html` allows Stored Cross-Site Scripting (XSS) when viewed directly in the browser.


* **Safe Proof-of-Concept (PoC):** Never upload active web shells (`c99`, `b374k`, or `system($_GET['cmd'])`) to client systems.
* Use non-destructive, deterministic payloads:
```php
<?php echo "Security_Test_" . md5("PoC_Confirmation"); ?>

```





---

### Related Next Steps to Explore

* **Magic Byte Spoofing:** Bypassing deep packet inspection by prepending image signatures (`GIF89a;` or JPEG hex `FF D8 FF E0`) to script payloads.
* **Double Extension & Null Byte Exploitation:** Bypassing extension checks using `poc.php.jpeg`, `poc.php%00.jpg`, or IIS semi-colon execution `poc.php;.jpg`.
* **SVG/HTML Stored XSS via Uploads:** Exploiting file uploads for client-side execution when server-side execution is blocked.

---

> **Key Insight:** The HTTP `Content-Type` header is completely user-controlled; treating it as a security boundary is an inherent design flaw that converts a file upload control into an open door for server-side code execution.
