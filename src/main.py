import sys
import os
import json
from .core.engine import SecurityAnalyzer

def print_report(file_path, report):
    print("\n" + "="*60)
    print(f"🛡️  SECURITY ANALYSIS REPORT: {os.path.basename(file_path)}")
    print("="*60)
    print(f"File Size     : {round(os.path.getsize(file_path)/(1024*1024), 2)} MB")
    print(f"Extension     : {os.path.splitext(file_path)[1].lower()}")
    print(f"Detected MIME : {report.get('detected_mime', 'Unknown')}")
    print("-" * 60)
    print(f"OVERALL RESULT: {report['status']}")
    if report['status'] == "🔴 REJECTED" or report.get("reason"):
        print(f"REASON        : {report.get('reason', report.get('message', ''))}")
    else:
        print(f"MESSAGE       : {report.get('message', '')}")
    print("="*60 + "\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 -m src.main <path_to_file>")
    else:
        # Pre-Flight Check B: Path Sanitization (Traversal Guard)
        # Normalize path to absolute to neutralize traversal attempts
        file_to_scan = os.path.abspath(sys.argv[1])
        
        if not os.path.exists(file_to_scan):
            print(f"❌ Error: File not found: {file_to_scan}")
            sys.exit(1)
            
        analyzer = SecurityAnalyzer()
        res = analyzer.analyze(file_to_scan)
        print_report(file_to_scan, res)