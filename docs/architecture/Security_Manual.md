# 🛡️ Security Manual & Threat Model

This document outlines the security philosophy and threat landscape handled by Malscanner.

## 1. Zero-Trust Philosophy
In Malscanner, **Zero-Trust** means no part of the input is trusted:
*   **Path**: Normalized immediately to prevent Traversal.
*   **Extension**: Ignored in favor of MIME sniffing (Magic Numbers).
*   **Size**: Strictly capped to prevent memory-based DoS.
*   **Content**: Sanitized even when signatures pass.

## 2. Threat Matrix
| Category | Vector | Layer of Defense |
| :--- | :--- | :--- |
| **Identity** | Extension Spoofing | Layer 1: Magic Scanner |
| **Signature** | Known Malware | Layer 2: ClamAV Daemon |
| **Tactic** | Shellcode / Reverse Shell | Layer 3: YARA Rules |
| **Active Content**| Weaponized PDF (JavaScript) | Layer 4: PDF Heuristics |
| **XSS** | Script Tags in Text/MD | Layer 5: Bleach Sanitizer |
| **Injection** | CSV/Formula Injection | Layer 6: Data Validator |
| **DoS** | ZST Decompression Bomb | Layer 7: ZST Ratio Guard |

## 3. Fail-Closed Principle
If any security dependency (like ClamAV or YARA) is offline, the system defaults to **REJECTED**. We never "pass-through" a file because a scanner failed to run.
