```text
┌────────────────────────────────────────────────────────────────────────┐
│            BLIND OS COMMAND INJECTION (TIME DELAYS) FLOW               │
└────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
          ┌──────────────────────────────────────────────────┐
          │ Phase 1: Target Discovery & Baseline Timing      │
          └──────────────────────────────────────────────────┘
                                   │
                                   ▼
          ┌──────────────────────────────────────────────────┐
          │ Phase 2: Delimiter & Time-Delay Payload Injection│
          └──────────────────────────────────────────────────┘
                                   │
                                   ▼
          ┌──────────────────────────────────────────────────┐
          │ Phase 3: Differential Timing Verification        │
          └──────────────────────────────────────────────────┘
                                   │
                                   ▼
          ┌──────────────────────────────────────────────────┐
          │ Phase 4: Impact Assessment & Safe Reporting      │
          └──────────────────────────────────────────────────┘

```

---

### Step-by-Step Methodology Flow

#### Phase 1: Target Discovery & Baseline Timing

* **Identify High-Risk Asynchronous Functions:** Target input forms where results are not reflected back to the user (e.g., feedback forms, contact support requests, email dispatch handlers, password resets, background processing features).
* **Establish Baseline Latency:** Send 5–10 legitimate HTTP requests in Burp Suite and record the average server response time (e.g., baseline = ~180ms).
* **Identify Operating System:** Check HTTP headers (`Server: Apache/Ubuntu` vs `Server: Microsoft-IIS`) or response stack traces to select OS-compatible sleep primitives.

---

#### Phase 2: Delimiter & Time-Delay Payload Injection

* **Conceptual Mechanism:** When an application executes backend system commands out-of-band (suppressing all direct text output and standard errors), the execution context can be inferred by forcing the operating system thread to sleep before returning an HTTP response.
* *Analogy:* Blind time-based injection is like sending a letter to an unlisted address and asking the recipient, *"If you receive this, wait exactly 10 minutes before dropping a receipt in the drop box."* You don't see what's happening inside the house, but the delay proves the letter was opened and read.


* **Inject Command Chaining Delimiters with Sleep Commands:**
* **Linux Primitives:**
* `sleep 10`
* `ping -c 10 127.0.0.1` *(1 ping per second = ~10-second delay)*


* **Windows Primitives:**
* `timeout /t 10`
* `ping -n 11 127.0.0.1` *(n-1 seconds = 10-second delay)*




* **Test Delimiter Combinations:**
* Inline execution: `email=test@example.com||sleep+10||`
* Sequential execution: `email=test@example.com;sleep+10`
* Background execution: `email=test@example.com&sleep+10&`
* Subshell injection: `email=test@example.com$(sleep+10)`
* Newline injection: `email=test@example.com%0asleep+10`



---

#### Phase 3: Differential Timing Verification

* **Execute Differential Timing Tests:** To rule out random network jitter or temporary server load, run two distinct timing tests:
* *Test A:* Inject a **3-second** delay payload -> Observe response time.
* *Test B:* Inject an **8-second** delay payload -> Observe response time.


* **Confirm Vulnerability:** If HTTP response durations strictly scale in proportion to your injected delay values (Baseline + Injected Delay), the command injection vulnerability is **100% confirmed**.

---

#### Phase 4: Impact Assessment & Safe Reporting

* **Pivot to Out-of-Band (OOB) Exfiltration:** Once time delay is confirmed, transition to OOB techniques (e.g., DNS queries via Burp Collaborator) to safely exfiltrate system metadata without hanging web server threads.
* **Document Proof of Concept (PoC):** Capture Burp Repeater timing logs demonstrating the time differential between baseline and injected requests.

---

### Real-World Response Matrix

| Payload Injected | HTTP Response Time | Server Execution State | Next Action Step |
| --- | --- | --- | --- |
| `email=x||sleep+10||` | ~10.2 seconds | **Blind Command Injection Confirmed.** | Conduct differential timing check (3s vs 8s) to eliminate false positives. |
| `email=x||sleep+10||` | ~0.2 seconds | Command failed, blocked by WAF, or executed asynchronously. | Test alternative delimiters (`%0a`, `$()`) or test OOB DNS exfiltration. |
| `email=x||sleep+10||` | `504 Gateway Timeout` | Reverse proxy cut the connection before backend finished sleeping. | Reduce delay value (`sleep 3`) to stay below proxy timeout limits. |
| `email=x;sleep+10` | ~10.2 seconds (Linux) | Linux shell interpreter executed sequential command. | Document PoC and check system privilege level via OOB exfiltration. |

---

### Critical Real-World Factors

* **Asynchronous Message Queues (The Blind Delay Trap):**
* Modern enterprise applications offload heavy operations (sending emails, processing feedback) to background task workers (e.g., RabbitMQ, Celery, Redis Queuing, AWS SQS).
* In these architectures, the web application returns `202 Accepted` or `200 OK` **immediately** to the user while the worker processes the queue in a separate thread.
* *Consequence:* Time-delay payloads (`sleep 10`) will execute inside the background worker, but **will not delay the HTTP response**.
* *Solution:* In queue-based architectures, time delays fail; you **must** use Out-of-Band (OOB) DNS interaction (`nslookup BURP-COLLABORATOR`) to verify execution.


* **Thread Exhaustion & Denial of Service (DoS):**
* Issuing long sleep payloads (e.g., `sleep 100`) on web applications with limited worker pools (such as PHP-FPM or Apache prefork setups) can lock all available worker threads, causing a Denial of Service for real users.
* *Best Practice:* Keep initial delay tests short (3 to 5 seconds max).


* **Network Jitter vs. True Execution:**
* High network latency or temporary database load can simulate a false delay. Always use differential timing (verifying that $N$ seconds of injected delay yields $N$ seconds of total latency) to confirm execution definitively.


* **Safe Ethical Hacking PoC Standard:**
* Do not execute destructive commands or attempt persistent backdoors on client infrastructure.
* Proving execution via controlled 5-second delays or benign OOB DNS pingbacks fully satisfies vulnerability reporting criteria.



---

### Related Next Steps to Explore

* **Out-of-Band (OOB) Data Exfiltration:** Extracting command outputs, usernames, and environment variables via DNS/HTTP requests using Burp Collaborator.
* **Bypassing Asynchronous Architecture Barriers:** Detecting blind command execution in background worker queues where HTTP time-delay feedback is suppressed.
* **Filter Evasion & Character Blacklist Bypasses:** Using environment variables (`$IFS`, `$PATH`) and base64 decoding to bypass input filters on blind injection endpoints.

---

> **Key Insight:** Blind command injection via time delays measures execution side-effects rather than direct output; validating it requires differential timing analysis to prove that application response latency varies in direct proportion to user-controlled delay parameters.
