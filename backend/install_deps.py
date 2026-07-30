#!/usr/bin/env python3
import subprocess
import sys
import shutil
from pathlib import Path

def main():
    base_dir = Path(__file__).parent.resolve()
    
    print("[*] Installing Python dependencies...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", str(base_dir / "requirements.txt")])
    except subprocess.CalledProcessError:
        print("[!] Failed to install Python dependencies.")
        sys.exit(1)
        
    print("[*] Installing Node dependencies...")
    if shutil.which("npm"):
        try:
            subprocess.check_call(["npm", "install"], cwd=str(base_dir))
        except subprocess.CalledProcessError:
            print("[!] Failed to install Node dependencies.")
            sys.exit(1)
    else:
        print("[!] npm not found in PATH!")
        sys.exit(1)
        
    print("[*] Installing Playwright browsers...")
    if shutil.which("npx"):
        try:
            subprocess.check_call(["npx", "playwright", "install", "chromium"], cwd=str(base_dir))
        except subprocess.CalledProcessError:
            print("[!] Failed to install Playwright browsers.")
            sys.exit(1)
    else:
        print("[!] npx not found in PATH!")
        sys.exit(1)
        
    print("[*] Dependencies installed successfully.")

if __name__ == "__main__":
    main()
