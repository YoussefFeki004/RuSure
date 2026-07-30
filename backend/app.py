#!/usr/bin/env python3
"""
Burp Scanner Web Interface v1.0
SQLi + XSS unified scanner interface - Backend API
"""

import os
import json
import uuid
import subprocess
import threading
import shutil
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

from flask import Flask, render_template, request, jsonify, send_from_directory, abort
from flask_cors import CORS

app = Flask(__name__)

# Enable CORS for React frontend
CORS(app, origins=["http://localhost:3000", "http://localhost:5173", "http://localhost:5000"])

UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

# Track active scans in memory
active_scans = {}

# History file to track all scans
HISTORY_FILE = Path("scan_history.json")
if not HISTORY_FILE.exists():
    HISTORY_FILE.write_text("[]", encoding="utf-8")

# =============================================================================
# UTILS
# =============================================================================

def new_scan_id():
    return str(uuid.uuid4())[:8]

def scan_dir(scan_id):
    d = UPLOAD_DIR / scan_id
    d.mkdir(exist_ok=True)
    return d

def load_history():
    try:
        if HISTORY_FILE.exists():
            with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        return []
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def save_history(history):
    try:
        with open(HISTORY_FILE, 'w', encoding='utf-8') as f:
            json.dump(history, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"[!] Error saving history: {e}")

def add_to_history(scan_id, scan_type, status, files, timestamp=None):
    history = load_history()
    for entry in history:
        if entry["scan_id"] == scan_id:
            entry["status"] = status
            entry["files"] = files
            entry["timestamp"] = timestamp or datetime.now().isoformat()
            save_history(history)
            return history
    history.append({
        "scan_id": scan_id,
        "scan_type": scan_type,
        "status": status,
        "files": files,
        "timestamp": timestamp or datetime.now().isoformat(),
        "results": {"total": 0, "true_positives": 0, "false_positives": 0, "inconclusive": 0}
    })
    save_history(history)
    return history

def update_history_status(scan_id, status, results=None):
    history = load_history()
    for entry in history:
        if entry["scan_id"] == scan_id:
            entry["status"] = status
            if results:
                entry["results"] = results
            break
    save_history(history)
    return history

def parse_sqli_summary(xml_path):
    try:
        if not Path(xml_path).exists():
            print(f"[DEBUG] Results file not found: {xml_path}")
            return {"total": 0, "true_positives": 0, "false_positives": 0, "inconclusive": 0}
        tree = ET.parse(xml_path)
        root = tree.getroot()
        summary = {}
        for child in root.find("summary") or []:
            summary[child.tag] = child.text
        return {
            "total": int(summary.get("totalFindings", 0)),
            "true_positives": int(summary.get("truePositives", 0)),
            "false_positives": int(summary.get("falsePositives", 0)),
            "inconclusive": int(summary.get("inconclusive", 0))
        }
    except Exception as e:
        print(f"[DEBUG] Error parsing results: {e}")
        return {"total": 0, "true_positives": 0, "false_positives": 0, "inconclusive": 0}

def parse_xss_summary(xml_path):
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        summary = {}
        for child in root.find("summary") or []:
            summary[child.tag] = child.text
        return {
            "total": int(summary.get("totalFindings", 0)),
            "true_positives": int(summary.get("truePositives", 0)),
            "false_positives": int(summary.get("falsePositives", 0)),
            "inconclusive": int(summary.get("manualReviewRequired", 0)) + 
                           int(summary.get("storedXssUnclear", 0))
        }
    except:
        return {"total": 0, "true_positives": 0, "false_positives": 0, "inconclusive": 0}

def get_scan_summary(scan_id, scanner_type):
    d = scan_dir(scan_id)
    if scanner_type == "sqli":
        xml_path = d / "sqli_results.xml"
        if xml_path.exists():
            return parse_sqli_summary(xml_path)
    else:
        xml_path = d / "xss_results.xml"
        if xml_path.exists():
            return parse_xss_summary(xml_path)
    return {"total": 0, "true_positives": 0, "false_positives": 0, "inconclusive": 0}

# =============================================================================
# DEPENDENCY CHECK
# =============================================================================

def check_dependencies():
    missing = []
    if not shutil.which("node"):
        missing.append("Node.js (https://nodejs.org/)")
    if not shutil.which("npm"):
        missing.append("npm (comes with Node.js)")
    try:
        import flask
        import requests
    except ImportError:
        missing.append("Python packages: flask, requests")
    return missing

# =============================================================================
# API ROUTES
# =============================================================================

@app.route("/api/history")
def api_history():
    return jsonify(load_history())

@app.route("/api/history/<scan_id>")
def api_history_detail(scan_id):
    history = load_history()
    for entry in history:
        if entry["scan_id"] == scan_id:
            d = scan_dir(scan_id)
            results = {}
            sqli_xml = d / "sqli_results.xml"
            if sqli_xml.exists():
                try:
                    data = parse_results_xml(str(sqli_xml), "sqli")
                    results["sqli"] = data
                except:
                    pass
            xss_xml = d / "xss_results.xml"
            if xss_xml.exists():
                try:
                    data = parse_results_xml(str(xss_xml), "xss")
                    results["xss"] = data
                except:
                    pass
            entry["results_data"] = results
            return jsonify(entry)
    return jsonify({"error": "Scan not found"}), 404

@app.route("/api/upload", methods=["POST"])
def api_upload():
    scan_id = new_scan_id()
    d = scan_dir(scan_id)

    sqli_file = request.files.get("sqli_xml")
    xss_file = request.files.get("xss_xml")
    sqli_payloads = request.files.get("sqli_payloads_txt")
    xss_payloads = request.files.get("xss_payloads_txt")

    saved = {}
    files_uploaded = []
    
    if sqli_file and sqli_file.filename:
        path = d / "sqli_burp.xml"
        sqli_file.save(path)
        saved["sqli_xml"] = str(path)
        files_uploaded.append("SQLi XML")

    if xss_file and xss_file.filename:
        path = d / "xss_burp.xml"
        xss_file.save(path)
        saved["xss_xml"] = str(path)
        files_uploaded.append("XSS XML")

    if sqli_payloads and sqli_payloads.filename:
        path = d / "sqli_payloads.txt"
        sqli_payloads.save(path)
        saved["sqli_payloads"] = str(path)
        files_uploaded.append("SQLi Payloads")
    else:
        default_path = Path("payloads.txt")
        if default_path.exists():
            shutil.copy(default_path, d / "sqli_payloads.txt")
            saved["sqli_payloads"] = str(d / "sqli_payloads.txt")
        elif (Path("payloads") / "generic").exists():
            shutil.copytree("payloads", d / "payloads", dirs_exist_ok=True)
            saved["sqli_payloads_dir"] = str(d / "payloads")

    if xss_payloads and xss_payloads.filename:
        path = d / "xss_payloads.txt"
        xss_payloads.save(path)
        saved["xss_payloads"] = str(path)
        files_uploaded.append("XSS Payloads")
    else:
        default_path = Path("payloads.txt")
        if default_path.exists():
            shutil.copy(default_path, d / "xss_payloads.txt")
            saved["xss_payloads"] = str(d / "xss_payloads.txt")

    add_to_history(
        scan_id=scan_id,
        scan_type="Upload",
        status="uploaded",
        files=files_uploaded
    )

    return jsonify({
        "scan_id": scan_id, 
        "saved": saved    })

@app.route("/api/run/<scanner>", methods=["POST"])
def api_run_scanner(scanner):
    if scanner not in ("sqli", "xss"):
        abort(400)

    scan_id = request.form.get("scan_id")
    if not scan_id:
        abort(400)

    d = scan_dir(scan_id).resolve()

    cookie = request.form.get("cookie", "").strip()
    headers = request.form.get("headers", "").strip()
    proxy = request.form.get("proxy", "").strip()
    base_url = request.form.get("base_url", "").strip()
    payloads_path = request.form.get("payloads_path", "").strip()
    dbms = request.form.get("dbms", "").strip()

    verify_ssl = request.form.get("verify_ssl") == "on"
    no_early_exit = request.form.get("no_early_exit") == "on"
    allow_github = request.form.get("allow_github") == "on"
    refresh_payloads = request.form.get("refresh_payloads") == "on"
    include_secrets = request.form.get("include_secrets") == "on"

    headful = request.form.get("headful") == "on"
    all_inputs = request.form.get("all_inputs") == "on"
    dom_deep = request.form.get("dom_deep") == "on"
    strict_fp = request.form.get("strict_fp") == "on"
    screenshot_fp = request.form.get("screenshot_fp") == "on"
    no_save_http = request.form.get("no_save_http") == "on"
    verbose = request.form.get("verbose") == "on"

    cookie_file = None
    if cookie:
        cookie_file = d / "cookie.txt"
        cookie_file.write_text(cookie, encoding="utf-8")

    headers_file = None
    if headers:
        headers_file = d / "headers.txt"
        headers_file.write_text(headers, encoding="utf-8")

    app_dir = Path.cwd().resolve()
    
    print(f"[DEBUG] Scan ID: {scan_id}")
    print(f"[DEBUG] Cookie: {cookie}")
    print(f"[DEBUG] Base URL: {base_url}")
    print(f"[DEBUG] DBMS: {dbms}")
    print(f"[DEBUG] Verbose: {verbose}")
    
    if scanner == "sqli":
        xml_file = d / "sqli_burp.xml"
        output_xml = d / "sqli_results.xml"
        sqli_script = app_dir / "run_sqli.py"
        
        cmd = ["python3", str(sqli_script), "--xml", str(xml_file), "--output", str(output_xml)]
        
        if cookie:
            cmd += ["--cookie", cookie]
        
        if base_url:
            cmd += ["--target-base-url", base_url]
        
        if proxy:
            cmd += ["--proxy", proxy]
        
        if dbms:
            cmd += ["--dbms", dbms]
        
        if headers_file:
            for line in headers.strip().split("\n"):
                if line.strip():
                    cmd += ["--header", line.strip()]
        
        payload_file = d / "sqli_payloads.txt"
        if payload_file.exists():
            cmd += ["--payloads", str(payload_file)]
        elif (d / "payloads").exists():
            cmd += ["--payload-dir", str(d / "payloads")]
        
        if verify_ssl:
            cmd += ["--verify-ssl"]
        if no_early_exit:
            cmd += ["--no-early-exit"]
        if allow_github:
            cmd += ["--allow-github"]
        if refresh_payloads:
            cmd += ["--refresh-payloads"]
        if include_secrets:
            cmd += ["--include-secrets-in-report"]
        if verbose:
            cmd += ["--verbose"]
        
        print(f"[DEBUG] Final command: {' '.join(cmd)}")
        
        update_history_status(scan_id, f"sqli_running")

    else:
        xml_file = d / "xss_burp.xml"
        out_dir = d / "screenshots"
        out_dir.mkdir(exist_ok=True)
        output_xml = d / "xss_results.xml"
        xss_script = app_dir / "xss_checker_v8.js"
        cmd = ["node", str(xss_script), "--xml", str(xml_file), "--out", str(out_dir), "--results", str(output_xml)]
        
        if payloads_path:
            cmd += ["--payloads", payloads_path]
        elif (d / "xss_payloads.txt").exists():
            cmd += ["--payloads", str(d / "xss_payloads.txt")]
            
        if cookie_file:
            cmd += ["--cookie-file", str(cookie_file)]
        if proxy:
            cmd += ["--proxy", proxy]
        if base_url:
            cmd += ["--base-url", base_url]
        if headful:
            cmd += ["--headful"]
        if all_inputs:
            cmd += ["--all-inputs"]
        if dom_deep:
            cmd += ["--dom-deep"]
        if strict_fp:
            cmd += ["--strict-fp"]
        if screenshot_fp:
            cmd += ["--screenshot-fp"]
        if no_save_http:
            cmd += ["--no-save-http"]
        if verbose:
            cmd += ["--verbose"]

        update_history_status(scan_id, f"xss_running")

    def run():
        if scan_id not in active_scans:
            active_scans[scan_id] = {}
        active_scans[scan_id][scanner] = {"status": "running", "pid": None, "cmd": " ".join(cmd)}
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=str(d)
            )
            active_scans[scan_id][scanner]["pid"] = proc.pid
            stdout, stderr = proc.communicate()
            
            results = get_scan_summary(scan_id, scanner)
            
            # Always mark as complete if scanner ran successfully
            if proc.returncode == 0:
                # The scanner completed successfully even if no TPs were found
                status = f"{scanner}_complete"
                update_history_status(scan_id, status, results)
            else:
                # Only mark as failed if the scanner process itself failed
                update_history_status(scan_id, f"{scanner}_failed")
            
            active_scans[scan_id][scanner] = {
                "status": "done" if proc.returncode == 0 else "error",
                "returncode": proc.returncode,
                "stdout": stdout[-5000:] if len(stdout) > 5000 else stdout,
                "stderr": stderr[-2000:] if len(stderr) > 2000 else stderr,
                "output_xml": str(output_xml),
                "cmd": " ".join(cmd),
            }
        except Exception as e:
            update_history_status(scan_id, f"{scanner}_error")
            active_scans[scan_id][scanner] = {
                "status": "error",
                "error": str(e),
                "cmd": " ".join(cmd),
            }

    threading.Thread(target=run, daemon=True).start()

    return jsonify({"scan_id": scan_id, "scanner": scanner, "status": "started", "cmd": " ".join(cmd)})

@app.route("/api/status/<scan_id>/<scanner>")
def api_status(scan_id, scanner):
    info = active_scans.get(scan_id, {}).get(scanner, {"status": "unknown"})
    return jsonify(info)

@app.route("/api/results/<scan_id>/<scanner>")
def api_results(scan_id, scanner):
    d = scan_dir(scan_id)
    if scanner == "sqli":
        xml_path = d / "sqli_results.xml"
    else:
        xml_path = d / "xss_results.xml"

    if not xml_path.exists():
        return jsonify({"error": "Results not ready", "path": str(xml_path)}), 404

    try:
        data = parse_results_xml(str(xml_path), scanner)
        return jsonify(data)
    except Exception as e:
        import traceback
        return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500

@app.route("/api/screenshots/<scan_id>/<path:filename>")
def api_screenshots(scan_id, filename):
    d = scan_dir(scan_id) / "screenshots"
    return send_from_directory(str(d), filename)

@app.route("/api/logs/<scan_id>/<scanner>")
def api_logs(scan_id, scanner):
    info = active_scans.get(scan_id, {}).get(scanner, {})
    return jsonify({
        "stdout": info.get("stdout", ""),
        "stderr": info.get("stderr", ""),
        "cmd": info.get("cmd", ""),
    })

@app.route("/api/payloads/<scan_id>/<scanner>")
def api_payloads(scan_id, scanner):
    d = scan_dir(scan_id)
    if scanner == "sqli":
        payload_file = d / "sqli_payloads.txt"
    else:
        payload_file = d / "xss_payloads.txt"
    
    if payload_file.exists():
        with open(payload_file, 'r') as f:
            content = f.read()
        return jsonify({"payloads": content})
    return jsonify({"payloads": ""})

@app.route("/api/delete_scan/<scan_id>", methods=["DELETE"])
def api_delete_scan(scan_id):
    try:
        history = load_history()
        history = [entry for entry in history if entry["scan_id"] != scan_id]
        save_history(history)
        d = scan_dir(scan_id)
        if d.exists():
            shutil.rmtree(d)
        if scan_id in active_scans:
            del active_scans[scan_id]
        return jsonify({"success": True, "message": f"Scan {scan_id} deleted"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/delete_all_scans", methods=["DELETE"])
def api_delete_all_scans():
    try:
        save_history([])
        for d in UPLOAD_DIR.iterdir():
            if d.is_dir():
                shutil.rmtree(d)
        active_scans.clear()
        return jsonify({"success": True, "message": "All scans deleted"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# =============================================================================
# XML PARSERS
# =============================================================================

def parse_results_xml(xml_path, scanner_type):
    tree = ET.parse(xml_path)
    root = tree.getroot()
    if scanner_type == "sqli":
        return parse_sqli_xml(root)
    else:
        return parse_xss_xml(root)

def parse_sqli_xml(root):
    summary = {}
    for child in root.find("summary") or []:
        summary[child.tag] = child.text

    findings = []
    for f in root.find("findings") or []:
        finding = {
            "serialNumber": get_text(f, "serialNumber"),
            "url": get_text(f, "url"),
            "method": get_text(f, "method"),
            "parameter": get_text(f, "parameter"),
            "classification": get_text(f, "classification"),
            "verdict": get_text(f, "verdict"),
            "scoring": {},
            "payloads": [],
            "fingerprint": {},
            "baseline": {},
            "full_requests": [],
            "full_responses": [],
        }

        sc = f.find("scoring")
        if sc is not None:
            finding["scoring"] = {
                "evidenceScore": get_text(sc, "evidenceScore"),
                "reliabilityScore": get_text(sc, "reliabilityScore"),
                "confidence": get_text(sc, "confidence"),
                "testsCompleted": get_text(sc, "testsCompleted"),
                "enoughTestsCompleted": get_text(sc, "enoughTestsCompleted"),
            }

        fp = f.find("databaseFingerprint")
        if fp is not None:
            finding["fingerprint"] = {
                "dbms": get_text(fp, "dbms"),
                "confidence": get_text(fp, "confidence"),
                "source": get_text(fp, "source"),
                "version": get_text(fp, "version"),
            }

        bl = f.find("baseline")
        if bl is not None:
            finding["baseline"] = {
                "statusCode": get_text(bl, "statusCode"),
                "responseSize": get_text(bl, "responseSize"),
                "responseTimeSeconds": get_text(bl, "responseTimeSeconds"),
            }

        evidence = f.find("originalBurpEvidence")
        if evidence is not None:
            requests_node = evidence.find("requests")
            if requests_node is not None:
                for req in requests_node.findall("request"):
                    finding["full_requests"].append(req.text or "")
            responses_node = evidence.find("responses")
            if responses_node is not None:
                for resp in responses_node.findall("response"):
                    finding["full_responses"].append(resp.text or "")

        payloads = f.find("payloadsTested")
        if payloads is not None:
            for pt in payloads.findall("payloadTest"):
                finding["payloads"].append({
                    "category": get_text(pt, "category"),
                    "payload": get_text(pt, "payload"),
                    "statusCode": get_text(pt, "statusCode"),
                    "responseSize": get_text(pt, "responseSize"),
                    "responseTimeSeconds": get_text(pt, "responseTimeSeconds"),
                    "fullRequestSent": get_text(pt, "fullRequestSent"),
                    "responseSnippet": get_text(pt, "responseSnippet"),
                    "responseBody": get_text(pt, "responseBody"),
                    "error": get_text(pt, "error"),
                    "evidence": [e.text for e in (pt.find("evidence") or [])],
                })

        findings.append(finding)

    return {"summary": summary, "findings": findings}

def parse_xss_xml(root):
    summary = {}
    for child in root.find("summary") or []:
        summary[child.tag] = child.text

    findings = []
    for f in root.find("findings") or []:
        finding = {
            "id": f.get("id"),
            "xssType": f.get("xssType"),
            "name": get_text(f, "name"),
            "severity": get_text(f, "severity"),
            "confidence": get_text(f, "confidence"),
            "method": get_text(f, "method"),
            "url": get_text(f, "url"),
            "parameter": get_text(f, "parameter"),
            "marker": get_text(f, "marker"),
            "classification": get_text(f, "classification"),
            "classificationReason": get_text(f, "classificationReason"),
            "attempts": [],
        }

        attempts = f.find("attempts")
        if attempts is not None:
            for att in attempts.findall("attempt"):
                attempt = {
                    "index": att.get("index"),
                    "status": att.get("status"),
                    "statusReason": get_text(att, "statusReason"),
                    "payload": get_text(att, "payload"),
                    "screenshot": get_text(att, "screenshot"),
                    "finalUrl": get_text(att, "finalUrl"),
                    "request": {},
                    "response": {},
                    "contextAnalysis": {},
                    "proof": {},
                    "inputInjections": [],
                }

                req = att.find("request")
                if req is not None:
                    attempt["request"] = {
                        "url": get_text(req, "url"),
                        "method": get_text(req, "method"),
                        "headers": get_text(req, "headers"),
                        "body": get_text(req, "body"),
                        "fullRequest": get_text(req, "fullRequest") or get_text(req, "body"),
                    }

                resp = att.find("response")
                if resp is not None:
                    attempt["response"] = {
                        "statusCode": get_text(resp, "statusCode"),
                        "headers": get_text(resp, "headers"),
                        "body": get_text(resp, "body"),
                    }

                ctx = att.find("contextAnalysis")
                if ctx is not None:
                    attempt["contextAnalysis"] = {
                        "found": get_text(ctx, "found"),
                        "encoded": get_text(ctx, "encoded"),
                        "exploitable": get_text(ctx, "exploitable"),
                        "reason": get_text(ctx, "assessmentReason"),
                        "contexts": [c.text for c in (ctx.find("contexts") or [])],
                    }

                proof = att.find("proof")
                if proof is not None:
                    dialogs = []
                    for d in (proof.find("dialogs") or []):
                        dialogs.append({
                            "type": d.get("type"),
                            "message": d.text,
                        })
                    attempt["proof"] = {
                        "confirmed": get_text(proof, "confirmed"),
                        "markerInHtml": get_text(proof, "markerInHtml"),
                        "dialogs": dialogs,
                    }

                inj_node = att.find("inputInjections")
                if inj_node is not None:
                    for inj in inj_node.findall("inputInjection"):
                        injection = {
                            "selector": get_text(inj, "selector"),
                            "tagName": get_text(inj, "tagName"),
                            "inputType": get_text(inj, "inputType"),
                            "name": get_text(inj, "name"),
                            "id": get_text(inj, "id"),
                            "success": get_text(inj, "success"),
                            "error": get_text(inj, "error"),
                        }
                        restrictions = inj.find("restrictions")
                        if restrictions is not None:
                            injection["restrictions"] = {
                                "maxlength": get_text(restrictions, "maxlength"),
                                "pattern": get_text(restrictions, "pattern"),
                                "readonly": get_text(restrictions, "readonly"),
                                "disabled": get_text(restrictions, "disabled"),
                            }
                        attempt["inputInjections"].append(injection)

                attempt["verificationUrl"] = get_text(att, "verificationUrl")
                attempt["error"] = get_text(att, "error")
                finding["attempts"].append(attempt)

        findings.append(finding)

    return {"summary": summary, "findings": findings}

def get_text(parent, tag):
    el = parent.find(tag)
    return el.text if el is not None else ""

# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    missing = check_dependencies()
    if missing:
        print("[!] Missing dependencies:")
        for m in missing:
            print(f"    - {m}")
        print("[!] Run: python install_deps.py")
    else:
        print("[*] All dependencies found. Starting server...")
        
    history = load_history()
    print(f"[*] Loaded {len(history)} scan(s) from history")
    for entry in history:
        print(f"    - {entry.get('scan_id')}: {entry.get('status')} ({entry.get('timestamp')})")

    app.run(debug=True, host="0.0.0.0", port=5000)
