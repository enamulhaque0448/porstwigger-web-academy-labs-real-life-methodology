```text
┌────────────────────────────────────────────────────────────────────────┐
│                   POLYGLOT WEB SHELL TESTING FLOW                      │
└────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
          ┌──────────────────────────────────────────────────┐
          │ Phase 1: Deep Inspection Recon & Baseline Checks │
          └──────────────────────────────────────────────────┘
                                   │
                                   ▼
          ┌──────────────────────────────────────────────────┐
          │ Phase 2: Polyglot Payload Generation (Safe PoC)  │
          └──────────────────────────────────────────────────┘
                                   │
                                   ▼
          ┌──────────────────────────────────────────────────┐
          │ Phase 3: Upload & Extension Combination Testing  │
          └──────────────────────────────────────────────────┘
                                   │
                                   ▼
          ┌──────────────────────────────────────────────────┐
          │ Phase 4: Execution Context Verification & PoC    │
          └──────────────────────────────────────────────────┘

```

---

### Step-by-Step Methodology Flow

#### Phase 1: Deep Inspection Recon & Baseline Checks

* **Identify Deep Content Validation:** Upload a simple PHP file named `poc.jpg` (or containing fake magic bytes) to test if the server validates file structure.
* If rejected with `"Invalid image format"` or `"Corrupt image file"`, the server uses a deep inspection library (such as PHP's `getimagesize()`, ImageMagick, or GD Library) rather than just checking headers or extension strings.


* **Determine Execution Targets:** Confirm whether the application stores uploaded images with user-controlled extensions (`.php`, `.phtml`, `.php5`) or renames them automatically (e.g., `uuid.jpg`).
* **Identify the Web Server Engine:** Check HTTP response headers (`Server: Apache`, `Nginx`, `IIS`) to understand how file extensions and handlers interact in the target directory.

---

#### Phase 2: Polyglot Payload Generation (Safe PoC)

* **Conceptual Mechanism:** Polyglot files maintain a dual identity—they possess a valid binary structure (magic bytes, headers, dimensions) recognized by image parsers, while containing executable script directives in metadata or unused image blocks.
* *Analogy:* A polyglot file is like a official document containing text written in invisible ink. The image inspector scans the document, confirms the seal and paper are authentic (magic bytes/EXIF), and passes it. When the file reaches the script engine, the engine reads the invisible ink as executable command instructions.


* **Inject Script into EXIF Metadata:**
* Use `exiftool` to insert a deterministic, safe proof-of-concept into the `Comment` or `UserComment` EXIF field of a valid JPEG/PNG:
```bash
exiftool -Comment='<?php echo "POLYGLOT_SUCCESS_" . (3000 + 42); ?>' valid_input.jpg -o polyglot.php

```




* **Alternative GIF Header Injection (Minimal Polyglot):**
* Prepend GIF magic bytes to a script file:
```php
GIF89a;
<?php echo "POLYGLOT_TEST_OK"; ?>

```





---

#### Phase 3: Upload & Extension Combination Testing

* **Submit Polyglot File:** Upload `polyglot.php` via the target file upload endpoint while intercepting traffic in Burp Suite.
* **Evaluate Server Validation Response:**
* **HTTP 200/201 (Accepted):** The server passed the file through its image verification functions (`getimagesize()` returned valid width/height from the JPEG header) and saved the file on disk as `polyglot.php`.
* **HTTP 400/422 (Rejected - Corrupt File):** The image parser flagged the injected metadata or corrupted file structure.
* **HTTP 400/403 (Rejected - Extension Filter):** The server blocked the `.php` extension. Pivot to combining polyglot techniques with **Extension Bypasses** (`polyglot.phtml`, `polyglot.php%00.jpg`, `.htaccess` overrides).



---

#### Phase 4: Execution Context Verification & PoC

* **Locate the Saved File URI:** Identify the direct path where the polyglot file is served (e.g., `[https://example.com/uploads/avatars/polyglot.php](https://example.com/uploads/avatars/polyglot.php)`).
* **Issue Direct GET Request:** Request the file in Burp Repeater or a browser.
* **Verify Code Execution:**
* **HTTP 200 OK + `POLYGLOT_SUCCESS_3042` rendered:** The web server passed the file to the PHP interpreter, which executed the metadata payload while ignoring the surrounding binary image garbage. **Vulnerability Confirmed.**
* **HTTP 200 OK + Binary Garbage Output:** The file uploaded successfully and bypassed image validation, but the server served it as static binary data (or `.php` handler is disabled in `/uploads/`).
* **Image Re-encoded / Metadata Stripped:** The server accepted the file, but rendered text string disappeared from the response because the server re-processed the image via GD/ImageMagick (`imagecreatefromjpeg()`), stripping EXIF metadata during compression.



---

### Real-World Response Matrix

| Test Action | Upload Response | GET File Response | Root Cause | Next Action Step |
| --- | --- | --- | --- | --- |
| Upload `polyglot.php` | `200 OK` | `200 OK (Executed Code)` | Image parser validated binary structure + `.php` executed. | **Critical RCE Confirmed.** Document PoC and report. |
| Upload `polyglot.php` | `200 OK` | `200 OK (Renders Raw Binary)` | Polyglot passed validation, but execution is disabled in folder. | Pivot to **Path Traversal** (`../polyglot.php`) to reach an executable directory. |
| Upload `polyglot.php` | `200 OK` | `200 OK (Metadata Stripped)` | Application uses active image re-encoding (e.g., GD Library). | Attempt advanced polyglots that survive re-encoding (IDAT chunk injection). |
| Upload `polyglot.php` | `400 Bad Request` | N/A | Extension blocked by whitelist. | Combine polyglot file with **Obfuscated Extensions** (`polyglot.php;.jpg`). |

---

### Critical Real-World Factors

* **Image Re-Encoding & Compression Defenses:** Enterprise applications rarely save raw uploaded files directly to disk. They process images using libraries like PHP GD, ImageMagick, or Pillow.
* Standard `imagecreatefrompng()` or `imagecreatefromjpeg()` calls recreate the image pixel-by-pixel, stripping all EXIF metadata and destroying simple polyglot payloads.
* *Bypass Vector:* Injecting PHP payloads directly into PNG **IDAT chunks** or JPEG **Quantization Tables**, which survive image transformation and re-encoding.


* **Storage on Cloud Storage (AWS S3 / Azure Blobs):** If polyglot files are saved into cloud storage buckets, direct script execution on the web server is impossible.
* *Impact Shift:* Test if uploading polyglot HTML/SVG files allows **Stored Cross-Site Scripting (XSS)** when rendered in browser contexts.


* **Safe Ethical Hacking PoC Standard:**
* **Never** upload fully featured interactive web shells (`b374k`, `c99`, or `system($_GET['cmd'])`).
* Use deterministic, benign evaluation strings (`<?php echo "POLYGLOT_VERIFICATION_" . md5("Test123"); ?>`) to confirm execution safely without leaving high-risk backdoors on target infrastructure.



---

### Related Next Steps to Explore

* **PNG IDAT Chunk Payload Injection:** Constructing PNG polyglots that survive server-side image re-encoding and GD library compression.
* **ImageMagick Vulnerabilities (ImageTragick):** Exploiting delegate vulnerabilities in server-side image processing libraries via crafted image uploads.
* **SVG-Based Stored XSS & SSRF:** Exploiting XML parsing within Vector Graphics (.svg) uploads for client-side and server-side attacks.

---

> **Key Insight:** Polyglot web shells bypass deep content inspection by crafting a dual-format file that satisfies image parser validation while retaining valid executable script instructions for the web server handler.
