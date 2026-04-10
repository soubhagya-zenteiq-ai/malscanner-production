import os
import sys
from src.core.engine import SecurityAnalyzer

def run_all_tests():
    # Initialize engine once to avoid recompiling YARA rules for every file
    analyzer = SecurityAnalyzer()
    
    test_folders = ["tests/payloads/safe", "tests/payloads/malicious"]
    
    print("\n" + "🚀 STARTING GLOBAL SECURITY BATCH SCAN".center(60, "="))

    for folder in test_folders:
        print(f"\n📂 CATEGORY: {folder.upper()}")
        print("-" * 60)
        
        if not os.path.exists(folder):
            print(f"⚠️  Folder not found: {folder}")
            continue

        files = sorted(os.listdir(folder))
        for filename in files:
            file_path = os.path.join(folder, filename)
            
            # Analyze using the imported class directly
            result = analyzer.analyze(file_path)
            
            status_text = result.get('status', '⚠️ ERROR')
            if "SAFE" in status_text:
                status = "🟢 PASS"
            elif "REJECTED" in status_text:
                status = "🔴 BLOCKED"
            else:
                status = "⚠️  ERROR"

            print(f"{status.ljust(10)} | {filename.ljust(25)} | {result.get('reason', 'N/A')[:30]}...")
            
    print("\n" + "✅ BATCH SCAN COMPLETE".center(60, "=") + "\n")

if __name__ == "__main__":
    run_all_tests()
