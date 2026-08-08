```text
┌────────────────────────────────────────────────────────────────────────┐
│             EXTENSION BLACKLIST BYPASS VIA .HTACCESS FLOW              │
└────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
          ┌──────────────────────────────────────────────────┐
          │ Phase 1: Server Recon & Blacklist Fingerprinting │
          └──────────────────────────────────────────────────┘
                                   │
                                   ▼
          ┌──────────────────────────────────────────────────┐
          │ Phase 2: Server Override Upload (.htaccess)      │
          └──────────────────────────────────────────────────┘
                                   │
                                   ▼
          ┌──────────────────────────────────────────────────┐
          │ Phase 3: Custom Extension Payload Upload         │
          └──────────────────────────────────────────────────┘
                                   │
                                   ▼
          ┌──────────────────────────────────────────────────┐
          │ Phase 4: Execution Context Verification & PoC    │
          └──────────────────────────────────────────────────┘

```

---

### Step-by-Step Methodology Flow

#### Phase 1: Server Recon & Blacklist Fingerprinting

* **Identify Web Server Architecture:** Inspect HTTP response headers (`Server: Apache/2.4.41`) or error pages to confirm the target runs **Apache HTTP Server** (required for `.htaccess` processing).
* **Confirm Blacklist Enforcement:** Attempt to upload a standard PHP script (`poc.php`).
* If rejected with `"Extension not allowed"` or similar, the application uses an extension filter.
* If accepted and executed, you have direct RCE without needing configuration overrides.


* **Test Alternate PHP Extensions:** Before attempting configuration overrides, check if the blacklist missed common secondary PHP extensions:
* `.phtml`, `.php3`, `.php4`, `.php5`, `.php7`, `.phar`, `.inc`, `.pht`



---

#### Phase 2: Server Override Upload (`.htaccess`)

* **Conceptual Mechanism:** Blacklists focus on file extensions (e.g., blocking `.php`), but often fail to block server configuration files. Uploading an `.htaccess` file overrides local directory rules.
* *Analogy:* A blacklist is like a bouncer checking guest names against a banned list ("No one named PHP allowed"). Uploading an `.htaccess` file is like slipping a new rulebook to the staff that says: *"Anyone wearing a blue tag (`.l33t`) must be treated as a VIP (`mod_php` executable)."*


* **Craft the `.htaccess` File:** Create a local file named `.htaccess` with content mapping a custom, arbitrary extension to the PHP MIME handler:
```apache
AddType application/x-httpd-php .l33t

```


*(Alternative Directive if `AddType` is restricted):*
```apache
<FilesMatch "\.l33t$">
    SetHandler application/x-httpd-php
</FilesMatch>

```


* **Upload Configuration Override:**
* Intercept the upload request in Burp Repeater.
* Set `filename=".htaccess"` and `Content-Type: text/plain`.
* Replace the file content with your chosen Apache directive and send.



---

#### Phase 3: Custom Extension Payload Upload

* **Craft the Execution Payload:** Create a benign test file named `poc.l33t` matching the extension defined in your `.htaccess` file:
```php
<?php echo "HTACCESS_BYPASS_SUCCESS_" . (2000 + 42); ?>

```


* **Submit the Custom Extension File:** Upload `poc.l33t` through the standard upload endpoint.
* **Evaluate Upload Acceptance:** The server's blacklist parser sees `.l33t`, fails to match it against banned strings (`.php`, `.exe`), and permits the file onto the filesystem.

---

#### Phase 4: Execution Context Verification & PoC

* **Calculate File Path:** Reconstruct the direct URI path where the uploaded file is stored (e.g., `[https://example.com/uploads/avatars/poc.l33t](https://example.com/uploads/avatars/poc.l33t)`).
* **Trigger Execution via GET Request:** Issue a direct HTTP `GET` request to the uploaded `.l33t` file.
* **Verify Outcome:**
* **HTTP 200 OK + `HTACCESS_BYPASS_SUCCESS_2042` in body:** Apache processed the `.htaccess` rules, mapped `.l33t` to `mod_php`, and executed the PHP code. **Vulnerability Confirmed.**
* **HTTP 200 OK + Raw PHP source text rendered:** File uploaded, but Apache ignored `.htaccess` (likely `AllowOverride None` in server configuration).
* **HTTP 500 Internal Server Error:** Syntax error inside `.htaccess` or the injected directive is prohibited by `AllowOverride` limits.



---

### Real-World Response Matrix

| `.htaccess` Upload Status | `.l33t` GET Response | Underlying Root Cause | Next Action Step |
| --- | --- | --- | --- |
| `200 OK (Uploaded)` | `200 OK (Executed Code)` | `AllowOverride` active + `.htaccess` uploaded + Blacklist bypassed. | **Critical Vulnerability Confirmed.** Document PoC and report. |
| `200 OK (Uploaded)` | `200 OK (Raw Source Code)` | `.htaccess` written to disk, but `AllowOverride None` prevents rule execution. | Pivot to alternate extension bypasses (`.phtml`, `.phar`) or case variations (`.PhP`). |
| `200 OK (Uploaded)` | `500 Internal Server Error` | Directives used (`AddType`/`SetHandler`) are forbidden by server `AllowOverride` restrictions. | Try minimalist `.htaccess` directives or test `php_value` flags. |
| `400 / 403 (Rejected)` | N/A | Application blacklists dotfiles or filenames starting with `.`. | Pivot to IIS `web.config` overrides or obfuscated extensions (`poc.php.`, `poc.php;.jpg`). |

---

### Critical Real-World Factors

* **Web Server Architecture Dependencies:**
* **Apache:** Reads `.htaccess` per directory if `AllowOverride FileInfo` or `AllowOverride All` is set in `httpd.conf`.
* **Nginx:** Does **not** support `.htaccess` files. If the target runs Nginx, this technique will not work; target Nginx misconfigurations like `cgi.fix_pathinfo=1` instead.
* **IIS (Windows):** Uses `web.config` instead of `.htaccess`. If the server is IIS, upload a `web.config` file to map handler scripts:
```xml
<configuration>
  <system.webServer>
    <handlers>
      <add name="CustomPHP" path="*.l33t" verb="*" modules="FastCgiModule" scriptProcessor="C:\php\php-cgi.exe" resourceType="Unspecified" />
    </handlers>
  </system.webServer>
</configuration>

```




* **Blacklist Flaws vs. Whitelist Defense:** Blacklists fail because defenders must block *every* dangerous extension, while attackers only need to find *one* missing file type or config file (`.htaccess`, `.user.ini`, `web.config`). A robust security architecture uses strict whitelisting (permitting *only* `.jpg`, `.png`).
* **Safe Ethical Hacking PoC Standard:**
* Never upload functional web shells or backdoors (`c99`, `b374k`, or `system($_GET['cmd'])`).
* Use deterministic, harmless evaluation strings (`<?php phpversion(); ?>` or simple arithmetic print statements) to confirm execution safely.



---

### Related Next Steps to Explore

* **IIS `web.config` Execution Handler Injection:** Exploiting Windows/IIS file upload endpoints by remapping handler scripts via custom `web.config` uploads.
* **PHP Configuration Injection via `.user.ini`:** Using `.user.ini` files on Nginx/PHP-FPM servers to inject `auto_prepend_file` directives.
* **Obfuscated Extension Bypasses:** Testing trailing dots (`poc.php.`), null bytes (`poc.php%00.jpg`), semi-colons (`poc.php;.jpg`), and URL/unicode encoding tricks.

---

> **Key Insight:** Extension blacklists rely on the flawed assumption that only script extensions execute code; overriding web server configuration files like `.htaccess` bypasses filename validation entirely by redefining the rules of execution for arbitrary file extensions.
