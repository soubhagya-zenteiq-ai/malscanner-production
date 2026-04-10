# 🛡️ Malscanner Production

A production-grade multi-layer malware and security interrogation engine for file uploads. Malscanner employs a "Defense in Depth" strategy, utilizing multiple scanning engines to ensure data integrity and security.

## 🏗️ Technical Architecture

Malscanner operates as a sequential security pipeline with four core phases:

1.  **Identity Check (Magic/MIME)**: Verifies that the file extension matches its actual binary content using `libmagic`. Prevents extension spoofing (e.g., an EXE disguised as a PDF).
2.  **Virus Scanning (ClamAV)**: Performs high-speed signature-based malware detection using the ClamAV daemon via Unix sockets and memory mapping.
3.  **Deep Inspection (YARA)**: Scans file payloads against 700+ advanced persistent threat (APT) and hack-tool rules to identify malicious byte patterns.
4.  **Heuristic Analysis**: Provides format-specific deep validation:
    *   **PDF**: Checks for JavaScript, OpenActions, and embedded malicious streams using `pdfid`.
    *   **ZST**: Protects against decompression bombs by checking compression ratios and absolute size limits.
    *   **Text/MD/XML**: Sanitizes content using `bleach` to prevent XSS payloads.
    *   **Data (CSV/JSON/Parquet)**: Row-by-row structural validation for schema integrity.

## 📁 Directory Structure

```text
malscanner-production/
├── config/
│   └── production.yml    # Centralized configuration (YAML)
├── src/
│   ├── core/             # Pipeline orchestration engine
│   ├── scanners/         # Modular security engines (ClamAV, YARA, etc.)
│   ├── utils/            # ConfigLoader and shared helpers
│   └── main.py           # CLI entry point
├── yara/                 # YARA rule repository
│   ├── rules/            # Core rule sets (700+ rules)
│   └── custom/           # Custom rule interface
├── tests/                # Integration and unit test suite
├── data/
│   ├── logs/             # Operational audit logs
│   └── samples/          # Test payload storage
└── scripts/              # Infrastructure and utility scripts
```

## 🚀 Getting Started

### Prerequisites
*   **System Dependencies**: `clamav-daemon`, `libmagic-dev`, `yara`
*   **Python**: 3.9+

### Installation
```bash
# Clone the repository
git clone <repo-url>
cd malscanner-production

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Configuration
Everything is managed via `config/production.yml`. You can modify:
*   **Limits**: File size caps (default 50MB) and decompression bomb protection.
*   **Whitelists**: Allowed extensions and their mapped MIME types.
*   **Scanner Paths**: ClamAV socket paths and YARA rule directories.
*   **Logging**: Log levels and output file paths.

## 💻 Usage

### Scan a File
```bash
python3 -m src.main <path_to_file>
```

### Run Pipeline Test
```bash
python3 -m tests.integration.test_pipeline
```

## 📊 Logging & Auditing
Detailed logs are generated in `data/logs/app.log` (configurable). The logs capture every phase of the security interrogation including:
*   Phase-by-phase progress.
*   Specific reasons for rejection.
*   MIME detection results.
*   YARA rule matches.

## 🔒 Security Policy
Malscanner defaults to a **Fail-Closed** policy. If any scanner engine is offline or fails to initialize, the entire analysis is rejected for safety.
