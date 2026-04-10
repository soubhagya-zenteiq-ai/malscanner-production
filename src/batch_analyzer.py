import os
import sys
import json
import logging
from .core.engine import SecurityAnalyzer

def run_batch_scan(folder_path, output_json="scan_report.json"):
    if not os.path.isdir(folder_path):
        print(f"❌ Error: {folder_path} is not a valid directory.")
        return

    analyzer = SecurityAnalyzer()
    scan_results = []
    malware_found_in_batch = False
    
    print(f"\n🚀 Starting Batch Interrogation: {folder_path}")
    print("-" * 60)

    # Walk through files in the folder
    files = sorted([f for f in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, f))])
    
    for filename in files:
        if malware_found_in_batch:
            print(f"🛑 Skipping {filename} (Batch halted due to threat detection)")
            continue

        file_path = os.path.join(folder_path, filename)
        print(f"🔍 Scanning: {filename}...")
        
        result = analyzer.analyze(file_path)
        
        # Structure the report entry
        entry = {
            "filename": filename,
            "full_path": file_path,
            "size_mb": round(float(os.path.getsize(file_path)) / (1024 * 1024), 3),
            "detected_mime": result.get("detected_mime", "Unknown"),
            "status": result.get("status"),
            "reason": result.get("reason", ""),
            "is_malware": "REJECTED" in result.get("status", "")
        }
        
        scan_results.append(entry)

        if entry["is_malware"]:
            print(f"💥 THREAT DETECTED in {filename}. Halting batch operation.")
            malware_found_in_batch = True
            # We don't 'break' if we want to record that others were skipped, 
            # but the user said 'no further scanning'. 
            # I will break here to stop execution immediately.
            break

    # Final Batch Report
    final_report = {
        "batch_folder": folder_path,
        "malware_found_in_batch": malware_found_in_batch,
        "total_files_scanned": len(scan_results),
        "results": scan_results
    }

    with open(output_json, 'w') as f:
        json.dump(final_report, f, indent=4)
    
    print("-" * 60)
    print(f"✅ Batch Scan Complete. JSON Report saved to: {output_json}\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 -m src.batch_analyzer <folder_path> [output_json]")
    else:
        folder = sys.argv[1]
        output = sys.argv[2] if len(sys.argv) > 2 else "batch_report.json"
        run_batch_scan(folder, output)
