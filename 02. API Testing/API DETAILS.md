## API Architectures: Technical Breakdown

### 1. REST (Representational State Transfer)
*   **Concept:** A stateless, resource-oriented architecture relying on standard HTTP methods (`GET`, `POST`, `PUT`, `DELETE`). Resources are treated as distinct entities manipulated via specific URIs.
*   **Example & Real-Life Use:** Standard public APIs and web applications. For example, a weather application fetching the current forecast, or a CRM retrieving customer records.
*   **How the URL Looks:** Path-based, targeting specific resources and collections.
    *   `https://api.example.com/v1/users/123/invoices`
*   **Cybersecurity Link:** REST APIs are primary targets for **Broken Object Level Authorization (BOLA/IDOR)**. Attackers frequently manipulate the resource ID in the URL (e.g., changing `/users/123/` to `/users/124/`) to access unauthorized data.
<img width="1210" height="848" alt="image" src="https://github.com/user-attachments/assets/4a0f55ce-3973-4346-a710-04724c836bc1" />
<img width="939" height="575" alt="image" src="https://github.com/user-attachments/assets/7a001563-d095-48ff-a0c5-b966d146f510" />


### 2. GraphQL
*   **Concept:** A data-query language that flips the REST model. Instead of hitting multiple endpoints, the client sends a highly specific query to a single endpoint, retrieving exactly the requested data—eliminating over-fetching and under-fetching.
*   **Example & Real-Life Use:** Complex frontends and mobile apps needing varied data points (e.g., fetching a user profile, their latest 5 posts, and associated comments all in a single request).
*   **How the URL Looks:** A single, unified endpoint (usually accepting `POST` requests containing the query payload).
    *   `https://api.example.com/graphql`
*   **Cybersecurity Link:** The sheer flexibility of GraphQL introduces **Denial of Service (DoS)** risks. Attackers can submit deeply nested, recursive queries (e.g., requesting a user, their friends, their friends' friends, infinitely) to exhaust backend resources and crash the database.
<img width="1280" height="800" alt="image" src="https://github.com/user-attachments/assets/566e14e2-5b99-4428-b07d-f46b22c709e5" />

### 3. gRPC (Google Remote Procedure Call)
*   **Concept:** A high-performance RPC framework running over HTTP/2. Instead of text-based JSON, it uses **Protocol Buffers (Protobuf)** for binary serialization, allowing it to execute functions on a remote server as if they were local function calls.
*   **Example & Real-Life Use:** Internal microservices and low-latency infrastructure. Used heavily by Netflix and Uber to rapidly route millions of internal server-to-server messages.
*   **How the URL Looks:** gRPC doesn't use standard RESTful HTTP URLs. It relies on a host address and invokes specific methods directly over the channel.
    *   `grpc://api.internal.network:50051` (Targeting method: `UserService/CreateUser`)
*   **Cybersecurity Link:** Because gRPC payloads are compiled binary data multiplexed over HTTP/2, traditional **Web Application Firewalls (WAFs)** often cannot inspect the traffic. Security requires specialized gRPC-aware proxies.
<img width="2072" height="2622" alt="image" src="https://github.com/user-attachments/assets/1c934585-1252-4fa3-b709-8a3141e28bba" />

### 4. SOAP (Simple Object Access Protocol)
*   **Concept:** A strict, legacy messaging protocol using heavily structured XML. It relies on formal contracts defined by a WSDL (Web Services Description Language) file and enforces rigid operational standards.
*   **Example & Real-Life Use:** High-stakes enterprise environments, banking systems, and legacy payment gateways where transaction reliability and built-in security (WS-Security) are non-negotiable.
*   **How the URL Looks:** Typically points to a specific service or action file rather than a resource.
    *   `https://api.bank.com/services/TransactionService.asmx`
*   **Cybersecurity Link:** The heavy reliance on XML parsing makes SOAP APIs highly susceptible to **XML External Entity (XXE) Injection**. Attackers can inject malicious XML to read local server files or execute Server-Side Request Forgery (SSRF).
<img width="1280" height="720" alt="image" src="https://github.com/user-attachments/assets/3fd5dccb-2ecd-4256-baaa-e21b11f96ef4" />

### 5. WebSockets
*   **Concept:** A stateful protocol providing full-duplex, bi-directional communication over a single, long-lived TCP connection. Both client and server can push data continuously without the overhead of HTTP handshakes.
*   **Example & Real-Life Use:** Real-time applications requiring instant updates. Think multiplayer gaming, live trading dashboards, or real-time chat applications (like Discord or Slack).
*   **How the URL Looks:** Uses custom WebSocket schemes instead of HTTP.
    *   `wss://chat.example.com/socket` (`wss://` is secure via TLS, `ws://` is unencrypted)
*   **Cybersecurity Link:** Weak authentication during the initial HTTP upgrade handshake can lead to **Cross-Site WebSocket Hijacking (CSWSH)**, allowing attackers to intercept real-time data streams.
<img width="1380" height="760" alt="image" src="https://github.com/user-attachments/assets/0e03b7bf-12e9-405a-9370-5e7dee59a93f" />

### 6. Webhooks (Event-Driven)
*   **Concept:** Often called a "reverse API." Instead of the client constantly polling the server for updates, the server automatically pushes an HTTP `POST` payload to the client the exact moment an event occurs.
*   **Example & Real-Life Use:** Payment gateways and CI/CD pipelines. For example, Stripe sending a webhook to your server the second a customer's credit card is successfully charged.
*   **How the URL Looks:** This URL is provided by *you* (the client) for the third-party server to hit.
    *   `https://your-app.com/api/webhooks/stripe-events`
*   **Cybersecurity Link:** Because anyone can send an HTTP `POST` to your public webhook endpoint, you must implement **Cryptographic Signature Verification** (usually HMAC) to prove the payload actually originated from the trusted service provider.
<img width="1200" height="696" alt="image" src="https://github.com/user-attachments/assets/d66749b7-ed16-4c2c-a999-744b65656f9b" />

**Visualizing the Efficiency (Polling vs. Event-Driven):**
```text
[REST Polling]                          [Webhook]
Client        Server                    Client        Server
  |---GET--->| (Any updates?)             |             |
  |<--No-----|                            |             |
  |---GET--->| (Any updates?)             |             |
  |<--No-----|                            |<--POST------| (Event Happened!)
  |---GET--->| (Any updates?)             |             |
  |<--Yes!---|                            |             |
