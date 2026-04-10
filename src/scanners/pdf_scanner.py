import subprocess
import os

class PDFScanner:
    def scan(self, file_path):
        try:
            # We use the pdfid CLI tool installed via pip
            # pdfid is typically available as a module executable
            result = subprocess.run(["python3", "-m", "pdfid.pdfid", file_path], capture_output=True, text=True)
            if result.returncode != 0 and "No module named pdfid.pdfid" in result.stderr:
                # Fallback to pdfid CLI
                result = subprocess.run(["pdfid", file_path], capture_output=True, text=True)
                
            output = result.stdout

            DANGEROUS_TAGS = [
                "/JS", "/JavaScript",         # Inline Scripting
                "/AA", "/OpenAction",         # Automatic actions on open
                "/Launch",                    # Launching external commands/files
                "/AcroForm", "/XFA",          # Scripted form-fields
                "/Action",                    # Event-based actions
                "/RichMedia",                 # Embedded multimedia objects
                "/EmbeddedFile"               # Hidden internal file payloads
            ]

            for line in output.split('\n'):
                for tag in DANGEROUS_TAGS:
                    if line.strip().startswith(tag):
                        parts = line.split()
                        if len(parts) > 1 and parts[-1].isdigit():
                            count = int(parts[-1])
                            if count > 0:
                                return {"passed": False, "reason": f"Malicious PDF Tag Found: {tag}"}
            
            return {"passed": True}
        except Exception as e:
            return {"passed": False, "reason": f"PDFID Error: {str(e)}"}
