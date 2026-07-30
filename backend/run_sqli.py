#!/usr/bin/env python3
"""
Robust wrapper for sqli_checker.py
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

# Get the directory where this script is located
SCRIPT_DIR = Path(__file__).parent.resolve()
SQALI_CHECKER = SCRIPT_DIR / "sqli_checker.py"

LOG_FILE = None

def log(msg):
    """Log message to console and file"""
    print(msg)
    sys.stdout.flush()
    if LOG_FILE:
        try:
            with open(LOG_FILE, 'a') as f:
                f.write(msg + '\n')
        except:
            pass

def main():
    global LOG_FILE
    
    args = sys.argv[1:]
    
    # Find scan directory
    scan_dir = None
    xml_path = None
    output_path = None
    cookie = None
    target_url = None
    payload_file = None
    verbose = False
    
    i = 0
    while i < len(args):
        if args[i] == '--xml' and i + 1 < len(args):
            xml_path = args[i + 1]
            scan_dir = Path(xml_path).parent
            i += 2
        elif args[i] == '--output' and i + 1 < len(args):
            output_path = args[i + 1]
            i += 2
        elif args[i] == '--cookie' and i + 1 < len(args):
            cookie = args[i + 1]
            i += 2
        elif args[i] == '--target-base-url' and i + 1 < len(args):
            target_url = args[i + 1]
            i += 2
        elif args[i] == '--payloads' and i + 1 < len(args):
            payload_file = args[i + 1]
            i += 2
        elif args[i] == '--verbose':
            verbose = True
            i += 1
        else:
            i += 1
    
    # Set up log file
    if scan_dir:
        LOG_FILE = scan_dir / "wrapper.log"
        log(f"Log file: {LOG_FILE}")
    
    log("=" * 60)
    log("WRAPPER STARTED")
    log(f"XML: {xml_path}")
    log(f"Output: {output_path}")
    log(f"Cookie: {cookie}")
    log(f"Target URL: {target_url}")
    log(f"Payload file: {payload_file}")
    log(f"Scan dir: {scan_dir}")
    log(f"Script dir: {SCRIPT_DIR}")
    log("=" * 60)
    
    # Build command for sqli_checker.py using absolute path
    if not SQALI_CHECKER.exists():
        log(f"ERROR: sqli_checker.py not found at: {SQALI_CHECKER}")
        sys.exit(1)
    
    cmd = ["python3", str(SQALI_CHECKER)]
    
    if xml_path:
        cmd.extend(["--xml", xml_path])
    if output_path:
        cmd.extend(["--output", output_path])
    if cookie:
        cmd.extend(["--cookie", cookie])
    if target_url:
        cmd.extend(["--target-base-url", target_url])
    if verbose:
        cmd.append("--verbose")
    
    # Handle payload file
    if payload_file and scan_dir:
        payload_path = Path(payload_file)
        log(f"Checking payload file: {payload_path}")
        if payload_path.exists():
            log(f"Payload file exists: {payload_path}")
            # Create payload directory structure
            payload_dir = scan_dir / "payloads" / "generic"
            payload_dir.mkdir(parents=True, exist_ok=True)
            log(f"Created payload directory: {payload_dir}")
            
            # Copy the payload file
            shutil.copy(payload_path, payload_dir / "union_based.txt")
            log(f"Copied payload to: {payload_dir / 'union_based.txt'}")
            
            # Use --payload-dir
            cmd.extend(["--payload-dir", str(scan_dir / "payloads")])
            log(f"Added --payload-dir: {scan_dir / 'payloads'}")
        else:
            log(f"WARNING: Payload file not found: {payload_path}")
    
    log(f"Final command: {' '.join(cmd)}")
    log("=" * 60)
    
    # Run the scanner
    try:
        result = subprocess.run(cmd, capture_output=False)
        log(f"Scanner completed with exit code: {result.returncode}")
        sys.exit(result.returncode)
    except Exception as e:
        log(f"ERROR: {e}")
        import traceback
        log(traceback.format_exc())
        sys.exit(1)

if __name__ == '__main__':
    main()
