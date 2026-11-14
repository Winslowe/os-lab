#!/usr/bin/env python3
"""PENT-17 - browser-extension exfiltration endpoint and CSP analyzer (static, offline).

Reads an unpacked Chrome/Edge/Firefox extension (Manifest V2 or V3) and reports:

* every network destination the code or manifest *statically references*
  (fetch / XHR / sendBeacon / WebSocket / EventSource / importScripts / import() /
  .src / .href assignments, HTML tags, declarativeNetRequest redirects, URL literals);
* exfiltration heuristics (sensitive data source + outbound request in one file,
  beacons/pixels, cleartext or raw-IP endpoints, remote code, webRequest capture);
* CSP relaxations in ``content_security_policy`` (MV2 string, MV3 ``extension_pages``
  and ``sandbox``, MV2 ``sandbox.content_security_policy``; script-src/default-src plus the
  script-src-elem, script-src-attr and worker-src/child-src overrides) and security-header tampering through declarativeNetRequest rule
  files or ``webRequest.onHeadersReceived`` handlers.

The analysis is strictly static and offline: extension code is only read as text, never
executed; host names are classified lexically, never resolved; nothing is contacted. The
reported hosts are potential destinations, not observed network activity. The analyzer
never writes inside the analyzed tree, never follows symlinks, NTFS junctions or other
reparse points (and never re-enters a visited directory), caps the size of every file it
reads and the number of files it walks, uses only linear-time scanning on file contents, and
escapes control/bidi/invisible characters (and Markdown metacharacters in ``--format md``) in
every extension-supplied string it prints. Output never fails on the console encoding:
unencodable characters are written as \\uXXXX escapes. Standard library only; Python 3.9+.

Every file the manifest loads (background, content scripts, pages, sandbox pages, overrides,
web-accessible scripts) and every package file those pages/scripts load is scanned, wherever
it lives. node_modules/, coverage/ and .next/ are otherwise not walked (named under
Limitations; ``--include-vendored`` walks them); dist/ and build/ are always walked.

Usage:
    python scripts/analysis/ext_exfil.py <extension_dir | manifest.json>
        [--format text|md|json] [-o OUT] [--max-files N] [--include-vendored]

Exit codes: 0 = no medium/high findings, 1 = medium/high findings, 2 = usage/input/output
error (including an input the analyzer cannot process; never reported as a finding).

Related: source-lab's browser analyzer (``browser.manifest.csp-*``, ``browser.dnr-header-stripping``)
covers a subset of the CSP/DNR checks; this tool adds the destination inventory and
exfiltration heuristics. Use only on extensions you own or are authorized to assess.
"""

from __future__ import annotations

import argparse
import bisect
import html
import ipaddress
import json
import os
import posixpath
import re
import sys
from collections import deque
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

TOOL = "ext_exfil"
VERSION = "1.1.0"
DISCLAIMER = (
    "Static, offline analysis: hosts below are statically referenced in the extension package and are "
    "potential destinations only, not observed network activity. No extension code was executed, "
    "no host name was resolved and no host was contacted."
)

MANIFEST_CANDIDATES = ("manifest.json", "src/manifest.json", "extension/manifest.json", "app/manifest.json")
SOURCE_EXTS = {".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".html", ".htm", ".json"}
HTML_EXTS = (".html", ".htm")
# Never extension code: always pruned from the directory walk.
SKIP_DIRS = {".git", "__pycache__"}
# Development/tooling directories: pruned from the walk unless --include-vendored is given. A file
# the manifest (or a scanned page/script) references is scanned even inside such a directory, and
# the directory is then walked too. dist/ and build/ are always scanned: they often hold the
# extension's own runtime code.
VENDORED_DIRS = {"node_modules", "coverage", ".next"}
DEFAULT_MAX_FILES = 2000
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_RULE_FILE_BYTES = 8 * 1024 * 1024
MAX_RULE_RESOURCES = 1000
MAX_RULE_TOTAL_BYTES = 64 * 1024 * 1024
MAX_ENDPOINTS_IN_REPORT = 500
MIN_PYTHON = (3, 9)
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
# "//host/path" takes the scheme of the document it runs in (https/http on a web page for a
# content script, the extension scheme on an extension page); it is reported as a potential
# network destination with this pseudo-scheme.
PROTOCOL_RELATIVE = "protocol-relative"
NETWORK_SCHEMES = {"http", "https", "ws", "wss", "ftp", PROTOCOL_RELATIVE}
# WHATWG "special" schemes: any run of "/" or "\" after "scheme:" is skipped before the host
# ("https:host", "https:/\\host" and "https:////host" all reach host).
SPECIAL_SCHEMES = {"http", "https", "ws", "wss", "ftp", "file"}
EXTENSION_SCHEMES = {"chrome-extension", "moz-extension", "safari-web-extension", "extension"}
# A protocol-relative URL in an extension page or background script resolves against the
# extension's own origin (chrome-extension://<host>/...), not the network.
EXTENSION_ORIGIN_CLASS = "extension-origin"
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
FAILING_SEVERITIES = {"high", "medium"}

BROAD_MATCHES = {"<all_urls>", "*://*/*", "http://*/*", "https://*/*", "*://*", "file:///*", "ws://*/*", "wss://*/*"}
STORE_HOSTS = {
    "clients2.google.com", "clients2.googleusercontent.com", "chrome.google.com", "chromewebstore.google.com",
    "edge.microsoft.com", "microsoftedge.microsoft.com", "addons.mozilla.org", "versioncheck.addons.mozilla.org",
}
# RFC 2606 / RFC 6761 names and RFC 5737 / RFC 3849 documentation networks.
RESERVED_SUFFIXES = (".example", ".test", ".invalid")
RESERVED_DOMAINS = ("example.com", "example.net", "example.org")
NAT64_NETWORKS = (ipaddress.ip_network("64:ff9b::/96"), ipaddress.ip_network("64:ff9b:1::/48"))
DOC_NETWORKS = tuple(ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"))

SECURITY_RESPONSE_HEADERS = {
    "content-security-policy", "content-security-policy-report-only", "x-frame-options", "x-content-type-options",
    "cross-origin-opener-policy", "cross-origin-embedder-policy", "cross-origin-resource-policy",
    "permissions-policy", "strict-transport-security", "referrer-policy",
}
SENSITIVE_REQUEST_HEADERS = {"origin", "referer", "cookie"}

# Call sites whose first argument is the destination URL. Order matters: the pixel form
# must win over the generic .src assignment at the same position.
SINKS: Tuple[Tuple[str, "re.Pattern[str]"], ...] = (
    ("fetch", re.compile(r"\bfetch\s*\(")),
    ("xhr", re.compile(r"\.open\s*\(\s*['\"`][A-Za-z]+['\"`]\s*,")),
    ("beacon", re.compile(r"\bsendBeacon\s*\(")),
    ("websocket", re.compile(r"\bnew\s+WebSocket\s*\(")),
    ("eventsource", re.compile(r"\bnew\s+EventSource\s*\(")),
    ("importScripts", re.compile(r"\bimportScripts\s*\(")),
    ("dynamic-import", re.compile(r"(?<![\w.$])import\s*\(")),
    # Bounded and "(" excluded, so a long run of "new Image(" without ")" stays linear (no rescans).
    ("pixel", re.compile(r"\bnew\s+Image\s*\([^()]{0,64}\)\s*\.src\s*=(?!=)")),
    ("src-assign", re.compile(r"\.(?:src|href|action)\s*=(?!=)")),
)
REQUEST_KINDS = {"fetch", "xhr", "beacon", "websocket", "eventsource", "pixel", "src-assign", "html-form", "html-img", "html-iframe"}
CODE_KINDS = {"importScripts", "dynamic-import", "html-script"}
# Linear-time HTML handling: the tag body never crosses "<" or ">" and is length-capped, and
# attributes are parsed only inside that body (no lazy scan to end of file).
#   The body is quote-aware (">" inside a quoted value does not end the tag) and has no length
#   cap, so long padding attributes cannot push src= out of view. Every alternative starts with a
#   different character, so there is no backtracking; a match only fails to extend at an unclosed
#   quote, and finditer resumes after the match, so the total work stays linear.
#   A quote is a value quote only right after "=" (alt=it's stays plain text); comments and
#   raw-text element content are masked first (see _mask_html), so a stray quote there cannot
#   swallow the next tag.
HTML_TAG_RE = re.compile(r"<(script|iframe|frame|link|img|form)\b((?:[^<>=]|=\s*\"[^\"]*\"|=\s*'[^']*'|=)*)", re.I)
# Sequential attribute tokenizer: values are consumed as values, so text inside one attribute's
# value (alt=" src=...") is never read as another attribute.
#   The match starts at the name (finditer skips separators one character at a time, with no
#   rescan), and each whitespace run is read at most once, by the name before it: linear.
HTML_ATTR_RE = re.compile(r"([^\s\"'>/=]+)(?:\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s>]*)))?")
OPEN_TAG_RE = re.compile(r"<[A-Za-z][^\s/<>]*(?:[^<>=]|=\s*\"[^\"]*\"|=\s*'[^']*'|=)*>?")
RAW_TEXT_TAGS = ("script", "style", "textarea", "title", "xmp", "noscript", "iframe", "noembed", "noframes", "plaintext")
# The tag name must end at whitespace, "/" or ">" (so <script-x> is not <script>).
RAW_TEXT_OPEN_RE = re.compile(r"<(" + "|".join(RAW_TEXT_TAGS) + r")(?=[\s/>]|$)")
ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
URL_ATTRS = {"src", "href", "action"}
# Quoted URL literals, case-insensitive scheme, with JSON/JS-escaped slashes ("https:\/\/h").
URL_LITERAL_RE = re.compile(r"([\"'`])((?:https?|wss?|ftp):(?:\\?/|\\\\){2}[^\"'`\s<>]{0,2048})", re.I)
SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*):")
TAB_NEWLINE_RE = re.compile(r"[\t\n\r]")
AUTHORITY_END_RE = re.compile(r"[/?#\\]")
PCT_RE = re.compile(r"(?:%[0-9A-Fa-f]{2})+")
JS_ESCAPE_RE = re.compile(r"\\(?:x([0-9A-Fa-f]{2})|u\{([0-9A-Fa-f]{1,6})\}|u([0-9A-Fa-f]{4})|(.))", re.S)
IPV4_PART_RE = re.compile(r"0[xX][0-9A-Fa-f]*|[0-9]+")
# Relative module specifiers and injected-file lists; bounded and non-nesting, so linear.
STATIC_IMPORT_RE = re.compile(r"(?:\bfrom|\bimport)\s*([\"'])((?:\.{1,2})?/[^\"'\n]{0,512})\1")
INJECT_FILES_RE = re.compile(r"\b(?:files|js)\s*:\s*\[([^\[\]]{0,1024})\]")
# Other package-file references: workers, getURL(), MV2 executeScript({file}), offscreen
# documents ({url}), .src = 'x.js', and every string argument of importScripts(a, b, ...).
LOCAL_REF_RE = re.compile(r"(?:\bnew\s+(?:Shared)?Worker\s*\(\s*|\bnew\s+URL\s*\(\s*|\bgetURL\s*\(\s*"
                          r"|\b(?:file|url|path|page|popup|panel|default_popup|default_path)\s*:\s*"
                          r"|\.src\s*=\s*|\bsetAttribute\s*\(\s*[\"'](?:src|href)[\"']\s*,\s*|\bwindow\s*\.\s*open\s*\(\s*"
                          r"|\blocation(?:\s*\.\s*href)?\s*=\s*|\blocation\s*\.\s*(?:assign|replace)\s*\(\s*)"
                          r"([\"'`])([^\"'`\n]{1,512})\1")
# Calls whose every string argument may be a package file: importScripts(a, b, ...) and
# chrome.devtools.panels.create(title, icon, page).
IMPORT_SCRIPTS_ARGS_RE = re.compile(r"\b(?:importScripts|panels\s*\.\s*create)\s*\(([^()]{0,2048})\)")
MAX_ENDPOINTS_PER_FILE = 2000      # soft cap: past it only new (kind, host) pairs are kept
MAX_ENDPOINTS_HARD_CAP = 10000     # hard cap: past it nothing more is recorded (incomplete coverage)
STRING_ITEM_RE = re.compile(r"([\"'`])([^\"'`\n]{1,512})\1")
# C0/C1 controls, DEL and Unicode format/invisible characters that can reorder, hide or spoof
# terminal/Markdown text: bidi controls, zero-width characters, soft hyphen, Mongolian vowel
# separator, combining grapheme joiner, Hangul fillers, variation selectors, interlinear
# annotation controls and Unicode tag characters.
CONTROL_RE = re.compile(
    "[\x00-\x1f\x7f-\x9f\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180b-\u180f\u200b-\u200f\u2028-\u202e"
    "\u2060-\u206f\u3164\ufe00-\ufe0f\ufeff\uffa0\ufff9-\ufffb\U000e0000-\U000e007f\U000e0100-\U000e01ef]")
MD_SPECIAL_RE = re.compile(r"([\\`*_\[\]<>|~&#!])")

SOURCES: Tuple[Tuple[str, "re.Pattern[str]"], ...] = (
    ("cookies", re.compile(r"\b(?:chrome|browser)\s*\.\s*cookies\s*\.|\bdocument\s*\.\s*cookie\b")),
    ("history", re.compile(r"\b(?:chrome|browser)\s*\.\s*history\s*\.")),
    ("tabs", re.compile(r"\b(?:chrome|browser)\s*\.\s*tabs\s*\.\s*(?:query|get)\s*\(")),
    ("storage", re.compile(r"\blocalStorage\b|\bsessionStorage\b|\b(?:chrome|browser)\s*\.\s*storage\s*\.")),
    ("identity", re.compile(r"\b(?:chrome|browser)\s*\.\s*identity\s*\.")),
    ("credentials", re.compile(r"type\s*=\s*\\?[\"']?password|\[type=\\?[\"']?password")),
)
WEBREQUEST_LISTENER_RE = re.compile(r"\b(?:chrome|browser)\s*\.\s*webRequest\s*\.\s*(on\w+)\s*\.\s*addListener")
WEBREQUEST_CAPTURE_RE = re.compile(r"['\"](?:requestBody|requestHeaders|extraHeaders)['\"]")
HEADERS_RECEIVED_RE = re.compile(r"\bonHeadersReceived\b")
# 'blocking' extraInfoSpec, as a string or as the OnHeadersReceivedOptions.BLOCKING enum value.
BLOCKING_SPEC_RE = re.compile(r"[\"'`]blocking[\"'`]|\.\s*BLOCKING\b")
# A returned {responseHeaders} or a responseHeaders object built elsewhere (const r = {responseHeaders: x}; return r).
RETURNED_HEADERS_RE = re.compile(r"\breturn\b[^;]{0,200}?\bresponseHeaders\b|\bresponseHeaders\s*:")
HEADER_NAME_RE = re.compile(r"[\"'`](" + "|".join(re.escape(h) for h in sorted(SECURITY_RESPONSE_HEADERS, key=len, reverse=True)) + r")[\"'`]", re.I)
INTERNAL_URL_CALL_RE = re.compile(r"\s*(?:chrome|browser)\s*\.\s*(?:runtime|extension)\s*\.\s*getURL\s*\(")
DYNAMIC_DNR_RE = re.compile(r"declarativeNetRequest\s*\.\s*(updateDynamicRules|updateSessionRules)\s*\(")


class InputError(Exception):
    """The input path is not an analyzable extension."""


class Gap(str):
    """A limitation meaning some content was NOT analyzed (a cap or truncation). Marked by type,
    not by wording, so extension-controlled text (a file name) can never fake or hide one."""


def _blank(chunk: str) -> str:
    return "".join(c if c == "\n" else " " for c in chunk)


def _mask_html(text: str) -> str:
    """Same-length copy of ``text`` with HTML comments and raw-text element content (script,
    style, textarea, title, ...) replaced by spaces, so quotes there cannot open an attribute
    value that swallows the next real tag. Linear: one forward pass with bounded ``find`` calls.

    This only ever *adds* detections: scan_source runs the tag pass over both this masked copy and
    the raw text and merges the results, so a masking mistake cannot hide a tag the raw pass sees.
    """
    low = text.translate(ASCII_LOWER)  # ASCII-only lowering keeps offsets aligned (U+0130 etc.)
    out: List[str] = []
    i, n = 0, len(text)
    while i < n:
        lt = low.find("<", i)
        if lt == -1:
            out.append(text[i:])
            break
        out.append(text[i:lt])
        if low.startswith("<!--", lt):
            if low.startswith("<!-->", lt) or low.startswith("<!--->", lt):  # empty comments
                end = lt + (5 if low.startswith("<!-->", lt) else 6)
            else:
                ends = [(pos + size) for pos, size in ((low.find("-->", lt + 4), 3), (low.find("--!>", lt + 4), 4)) if pos != -1]
                end = min(ends) if ends else n
            out.append(_blank(text[lt:end]))
            i = end
            continue
        m = RAW_TEXT_OPEN_RE.match(low, lt)
        tag_m = OPEN_TAG_RE.match(text, lt) if m else None
        if m and tag_m:
            # The opening tag ends at the first ">" outside a quoted value (title="a>b" is one tag).
            tag_end = tag_m.end()
            if tag_end >= n or text[tag_end - 1] != ">":
                out.append(text[lt:tag_end])
                i = tag_end
                continue
            close = low.find("</" + m.group(1), tag_end)
            close = n if close == -1 else close
            out.append(text[lt:tag_end])
            out.append(_blank(text[tag_end:close]))
            i = close
            continue
        out.append("<")
        i = lt + 1
    return "".join(out)


# ----------------------------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------------------------

def _str_list(value: Any) -> List[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str)]
    return []


def _dict_list(value: Any) -> List[Dict[str, Any]]:
    """The dict items of a JSON list; any other shape (number, string, object) gives []."""
    return [v for v in value if isinstance(v, dict)] if isinstance(value, list) else []


def _json_scalar(value: Any) -> Any:
    """An int/str/bool/None as is; anything else (NaN/Infinity floats, lists, objects) as a string,
    so the JSON report stays valid JSON (json.loads accepts NaN, strict JSON does not)."""
    return value if value is None or isinstance(value, (int, str, bool)) else str(value)


def _as_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _read_capped(path: Path, cap: int, encoding: str = "utf-8") -> Optional[str]:
    """Reads at most ``cap`` bytes; None when the file is larger (bounded read, no TOCTOU on stat)."""
    with open(path, "rb") as fh:
        data = fh.read(cap + 1)
    if len(data) > cap:
        return None
    return data.decode(encoding, errors="replace")


def _within(path: Path, real_root: Path) -> bool:
    """True when ``path`` resolves (following symlinks and NTFS junctions) inside ``real_root``."""
    try:
        return Path(os.path.realpath(path)).is_relative_to(real_root)
    except (OSError, ValueError):
        return False


def _is_link_or_junction(path: str) -> bool:
    """True for a symlink, an NTFS junction or any other Windows reparse point.

    ``os.path.isjunction`` exists only on Python 3.12+, so the reparse-point attribute from
    ``lstat`` is checked as well; that works on every supported interpreter.
    """
    if os.path.islink(path):
        return True
    isjunction = getattr(os.path, "isjunction", None)
    if isjunction is not None and isjunction(path):
        return True
    try:
        st = os.lstat(path)
    except OSError:
        return True  # cannot be inspected: treat as a link, never descend
    return bool(getattr(st, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT)


def _clean(value: Any) -> str:
    """Escapes control, bidi/format and invisible characters so untrusted text cannot drive or
    spoof the terminal."""
    def esc(m: "re.Match[str]") -> str:
        c = ord(m.group())
        return f"\\x{c:02x}" if c <= 0xFF else (f"\\u{c:04x}" if c <= 0xFFFF else f"\\U{c:08x}")
    return CONTROL_RE.sub(esc, str(value))


def _md(value: Any) -> str:
    """_clean plus Markdown/HTML escaping, so untrusted text renders as literal text."""
    return MD_SPECIAL_RE.sub(r"\\\1", _clean(value))


class _Lines:
    """Maps a character offset to a 1-based line number and a short snippet."""

    def __init__(self, text: str):
        self.text = text
        self.starts = [0] + [m.end() for m in re.finditer("\n", text)]

    def line(self, pos: int) -> int:
        return bisect.bisect_right(self.starts, pos)

    def snippet(self, pos: int) -> str:
        ln = self.line(pos)
        lo = max(self.starts[ln - 1], pos - 60)
        hi = min(len(self.text), lo + 180)
        end = self.text.find("\n", lo, hi)  # bounded search: constant work per snippet, even on one-line files
        return " ".join(self.text[lo:hi if end == -1 else end].split())


def _pct_decode(value: str) -> str:
    """Percent-decodes runs of %XX as UTF-8 (WHATWG host parsing does this before IDNA)."""
    return PCT_RE.sub(lambda m: bytes(int(h, 16) for h in m.group()[1:].split("%")).decode("utf-8", "replace"), value)


def js_unescape(value: str) -> str:
    r"""Decodes JavaScript string escapes (\xHH, \uHHHH, \u{H..}, \/, \\, ...) in a literal body."""
    def rep(m: "re.Match[str]") -> str:
        hx = m.group(1) or m.group(2) or m.group(3)
        if hx:
            cp = int(hx, 16)
            return chr(cp) if cp <= 0x10FFFF else ""
        c = m.group(4)
        return {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v", "0": "\0", "\n": ""}.get(c, c)
    return JS_ESCAPE_RE.sub(rep, value) if "\\" in value else value


def _ipv4_number(part: str) -> Optional[int]:
    """One WHATWG IPv4 part, or None. Digit strings longer than any 32-bit value are rejected
    before int(), so a crafted 5000-digit "host" can neither hit Python's int-string limit nor
    cost quadratic conversion time."""
    if not IPV4_PART_RE.fullmatch(part):
        return None
    if part[:2].lower() == "0x":
        digits = part[2:].lstrip("0")
        return None if len(digits) > 8 else (int(digits, 16) if digits else 0)
    if len(part) > 1 and part[0] == "0":
        digits = part[1:].lstrip("0")
        if not all(c in "01234567" for c in digits) or len(digits) > 11:
            return None
        return int(digits, 8) if digits else 0
    return None if len(part) > 10 else int(part)


def whatwg_ipv4(host: str) -> Optional[ipaddress.IPv4Address]:
    """WHATWG IPv4 host parsing: decimal (3405803781), hex (0xcb007109), octal (0313.0.0.1)
    and short dotted (203.113.9) forms. None when ``host`` is not such a number."""
    parts = host.split(".")
    if len(parts) > 1 and parts[-1] == "":
        parts.pop()
    if not parts or len(parts) > 4 or not IPV4_PART_RE.fullmatch(parts[-1]):
        return None
    nums = [_ipv4_number(p) for p in parts]
    if any(n is None for n in nums) or any(n > 255 for n in nums[:-1]) or nums[-1] >= 256 ** (5 - len(nums)):
        return None
    value = nums[-1]
    for i, n in enumerate(nums[:-1]):
        value += n * 256 ** (3 - i)
    return ipaddress.IPv4Address(value)


def _parse_host(authority: str) -> str:
    auth = authority.rsplit("@", 1)[-1]
    if auth.startswith("["):
        host = auth[1:auth.find("]")] if "]" in auth else auth[1:]
        try:
            return ipaddress.IPv6Address(host).compressed
        except ValueError:
            return host.lower()
    host = _pct_decode(auth.split(":", 1)[0]).lower().rstrip(".")
    v4 = whatwg_ipv4(host)
    return str(v4) if v4 is not None else host


def split_url(url: str) -> Optional[Tuple[str, str]]:
    """Returns (scheme, host) for an absolute or scheme-relative URL, or None for a relative path.

    Pure string parsing after the WHATWG URL rules, no lookups: tab/newline characters are
    removed; for special schemes any run of "/" or "\\" follows "scheme:" ("https:h",
    "https:\\\\h"); a leading "//", "\\\\", "/\\" or "\\/" is scheme-relative; the host is
    percent-decoded, lower-cased and IPv4 numbers are normalized. The host is "" when the URL has
    no host (e.g. "data:", or a prefix like "https://" that is completed at runtime).
    """
    s = TAB_NEWLINE_RE.sub("", url).strip("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0c\x0e\x0f\x10\x11\x12\x13"
                                         "\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f ")
    m = SCHEME_RE.match(s)
    if m:
        scheme = m.group(1).lower()
        rest = s[m.end():]
        if scheme in SPECIAL_SCHEMES:
            rest = rest.lstrip("/\\")
        elif rest.startswith("//"):
            rest = rest[2:]
        else:
            return scheme, ""  # data:, javascript:, mailto:, about: ...
    elif len(s) >= 2 and s[0] in "/\\" and s[1] in "/\\":
        scheme = PROTOCOL_RELATIVE
        rest = s.lstrip("/\\")
    else:
        return None
    return scheme, _parse_host(AUTHORITY_END_RE.split(rest, 1)[0])


def _ip(host: str) -> Optional[ipaddress._BaseAddress]:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return None
    # IPv4-mapped (::ffff:a.b.c.d), 6to4 (2002:aabb:ccdd::), Teredo (2001:0::/32, client address)
    # and NAT64 (64:ff9b::/96, 64:ff9b:1::/48) addresses reach an embedded IPv4 address, so they
    # are classified as that address.
    if ip.version == 6:
        embedded = ip.ipv4_mapped or ip.sixtofour or (ip.teredo[1] if ip.teredo else None)
        if embedded is None and any(ip in net for net in NAT64_NETWORKS):
            embedded = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
        if embedded is not None:
            return embedded
    return ip


def is_reserved_example(host: str) -> bool:
    """True for RFC 2606/6761 example names and RFC 5737/3849 documentation addresses."""
    ip = _ip(host)
    if ip is not None:
        return any(ip in net for net in DOC_NETWORKS if net.version == ip.version)
    return host.endswith(RESERVED_SUFFIXES) or any(host == d or host.endswith("." + d) for d in RESERVED_DOMAINS)


def _vendor_domain(host: str) -> str:
    """The self-declared vendor scope of a homepage/update host: the exact host without a leading
    ``www.``. Never widened to the last two labels, which would turn ``attacker.github.io`` into
    every ``*.github.io`` host (or ``x.co.uk`` into every ``*.co.uk`` host)."""
    return host[4:] if host.startswith("www.") and host.count(".") >= 2 else host


def ascii_host(host: str) -> Tuple[str, bool]:
    """(ASCII form, was_non_ascii). Non-ASCII hosts become IDNA/punycode, as browsers send them;
    hosts that cannot be encoded keep their characters escaped as \\uXXXX."""
    if host.isascii():
        return host, False
    try:
        return host.encode("idna").decode("ascii"), True
    except UnicodeError:
        return host.encode("ascii", "backslashreplace").decode("ascii"), True


def classify_host(host: str, vendor_domains: Iterable[str] = ()) -> str:
    """Lexical class of a destination host: dynamic, local, browser-store, vendor or external."""
    if not host or "${" in host or host == "<dynamic>":
        return "dynamic"
    ip = _ip(host)
    if ip is not None:
        if any(ip in net for net in DOC_NETWORKS if net.version == ip.version):
            return "external"  # documentation range: treated as an outside destination
        if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_unspecified:
            return "local"
        return "external"
    if host == "localhost" or host.endswith((".localhost", ".local")):
        return "local"
    if host in STORE_HOSTS:
        return "browser-store"
    if any(host == d or host.endswith("." + d) for d in vendor_domains):
        return "vendor"
    return "external"


def is_outbound(cls: str) -> bool:
    return cls in {"external", "vendor"}


def _read_literal(text: str, pos: int) -> Tuple[Optional[str], int, bool]:
    """Reads a string/template literal starting at or after ``pos`` (whitespace skipped).

    Returns (value, start offset, partial) or (None, pos, False) when the argument is not a
    literal. JavaScript escapes are decoded. ``partial`` is True when the literal is only a
    prefix of the runtime value: a template literal cut at its first ``${``, or a string
    followed by ``+`` (concatenation). The closing-quote search is bounded (2 KiB), so a
    missing quote never makes the scan quadratic.
    """
    i = pos
    limit = min(len(text), pos + 64)
    while i < limit and text[i] in " \t\r\n(":
        i += 1
    if i >= len(text) or text[i] not in "\"'`":
        return None, pos, False
    quote = text[i]
    j = i + 1
    stop = min(len(text), i + 2049)
    while j < stop and text[j] != quote:
        j += 2 if text[j] == "\\" else 1
    if j >= stop:
        return None, pos, False
    value = text[i + 1:j]
    partial = False
    if quote == "`" and "${" in value:
        value = value[:value.index("${")]
        partial = True
    k = j + 1
    while k < len(text) and k < j + 64 and text[k] in " \t\r\n":
        k += 1
    if k < len(text) and text[k] == "+":
        partial = True
    return js_unescape(value), i, partial


def _looks_like_relative_path(value: str) -> bool:
    """A prefix that resolves inside the extension ("/api", "./x", "data.json"), as opposed to
    one whose host is still to be filled in ("", "//", "https://")."""
    v = value.strip()
    if not v:
        return False
    if v[0] in "/\\":
        return len(v) > 1 and v[1] not in "/\\"
    return SCHEME_RE.match(v) is None


# ----------------------------------------------------------------------------------------------
# Manifest, CSP and declarativeNetRequest
# ----------------------------------------------------------------------------------------------

def locate_manifest(path: Path) -> Path:
    if path.is_file():
        if path.name != "manifest.json":
            raise InputError(f"expected an extension directory or manifest.json, got {path.name}")
        return path
    if not path.is_dir():
        raise InputError(f"no such file or directory: {path}")
    real = Path(os.path.realpath(path))
    for name in MANIFEST_CANDIDATES:
        # A candidate reached through a symlink/junction leading outside the directory is ignored.
        if (path / name).is_file() and _within(path / name, real):
            return path / name
    raise InputError(f"no manifest.json found in {path} (looked at {', '.join(MANIFEST_CANDIDATES)})")


def parse_csp(policy: str) -> Dict[str, List[str]]:
    directives: Dict[str, List[str]] = {}
    for part in policy.split(";"):
        tokens = part.split()
        if tokens:
            directives.setdefault(tokens[0].lower(), [t for t in tokens[1:]])
    return directives


def _extension_source(token: str) -> bool:
    """chrome-extension://<id> (or another extension scheme): a source inside an installed
    extension, not the network."""
    return token.lower().split(":", 1)[0] in EXTENSION_SCHEMES and ":" in token


def _remote_source(token: str) -> bool:
    t = token.lower()
    if t.startswith("'") or t in {"data:", "blob:", "filesystem:", "mediastream:"} or _extension_source(t):
        return False
    if t in {"*", "http:", "https:", "ws:", "wss:"}:
        return True
    return "://" in t or "." in t


def _neutralizes_inline(lowered: List[str]) -> bool:
    """CSP Level 2+: a nonce or hash (or 'strict-dynamic') in the directive makes the browser
    ignore 'unsafe-inline' in it."""
    return any(t.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) or t == "'strict-dynamic'" for t in lowered)


SANDBOX_MV2_SOURCE = "sandbox.content_security_policy"
INLINE_EFFECTS = {
    "script": "inline scripts and event-handler attributes can run",
    "script-src-elem": "inline <script> blocks can run",
    "script-src-attr": "inline event-handler attributes (onclick=...) can run",
}


def analyze_csp(manifest: Dict[str, Any], limitations: Optional[List[str]] = None) -> Dict[str, Any]:
    notes = limitations if limitations is not None else []
    raw = manifest.get("content_security_policy")
    mv = manifest.get("manifest_version")
    policies: List[Tuple[str, str]] = []
    if isinstance(raw, str):
        policies.append(("content_security_policy", raw))
    elif isinstance(raw, dict):
        for k, v in sorted(raw.items()):
            if isinstance(v, str):
                policies.append((f"content_security_policy.{k}", v))
            else:
                notes.append(f"content_security_policy.{k} is not a string ({type(v).__name__}); not inspected")
    elif raw is not None:
        notes.append(f"content_security_policy has an unexpected shape ({type(raw).__name__}); not inspected")

    # MV2 sandboxed pages take their policy from sandbox.content_security_policy (ignored in MV3,
    # which uses content_security_policy.sandbox instead).
    sandbox_cfg = manifest.get("sandbox")
    if isinstance(sandbox_cfg, dict) and "content_security_policy" in sandbox_cfg:
        sp = sandbox_cfg["content_security_policy"]
        if mv == 3:
            notes.append(f"{SANDBOX_MV2_SOURCE} is ignored in Manifest V3 (use content_security_policy.sandbox); not inspected")
        elif not isinstance(sp, str):
            notes.append(f"{SANDBOX_MV2_SOURCE} is not a string ({type(sp).__name__}); not inspected")
        elif not _str_list(sandbox_cfg.get("pages")):
            notes.append(f"{SANDBOX_MV2_SOURCE} is declared but sandbox.pages lists no page; not inspected")
        else:
            policies.append((SANDBOX_MV2_SOURCE, sp))

    out_policies: List[Dict[str, Any]] = []
    relax: List[Dict[str, Any]] = []
    for source, policy in policies:
        sandbox = source.endswith(".sandbox") or source == SANDBOX_MV2_SOURCE
        declared_only = mv == 3 and not sandbox
        out_policies.append({"source": source, "policy": policy, "declared_only": declared_only})
        d = parse_csp(policy)
        script_dir = "script-src" if "script-src" in d else ("default-src" if "default-src" in d else None)
        seen: set = set()

        def add(rid: str, directive: str, token: str, severity: str, effect: str) -> None:
            if (rid, directive, token.lower()) in seen:
                return
            seen.add((rid, directive, token.lower()))
            if sandbox and severity == "high":
                severity = "medium"  # sandboxed pages have no extension API access
                effect += " (sandboxed page: runs in a unique origin without extension APIs)"
            if declared_only:
                effect += " (MV3: declared; the browser may reject this relaxation when loading the extension)"
            relax.append({"id": rid, "source": source, "directive": directive, "token": token,
                          "severity": severity, "effect": effect})

        # (directive, role): the script fallback plus every finer-grained directive that overrides it.
        # script-src-elem/-attr fall back to script-src; worker-src falls back to child-src, then script-src.
        checks: List[Tuple[str, str]] = [(script_dir, "script")] if script_dir else []
        checks += [(name, name) for name in ("script-src-elem", "script-src-attr") if name in d]
        worker_dir = "worker-src" if "worker-src" in d else ("child-src" if "child-src" in d else None)
        if worker_dir:
            checks.append((worker_dir, "worker"))
        for directive, role in checks:
            tokens = d.get(directive, [])
            lowered = [t.lower() for t in tokens]
            if role == "script" and "'unsafe-eval'" in lowered:
                add("csp.unsafe-eval", directive, "'unsafe-eval'", "high", "strings can be evaluated as code (eval/new Function)")
            if role in INLINE_EFFECTS and "'unsafe-inline'" in lowered:
                if _neutralizes_inline(lowered):
                    add("csp.unsafe-inline", directive, "'unsafe-inline'", "low",
                        "declared, but ignored by CSP Level 2+ browsers because the directive also lists a "
                        "nonce, hash or 'strict-dynamic'")
                elif mv == 2 and not sandbox:
                    add("csp.unsafe-inline", directive, "'unsafe-inline'", "low",
                        "declared in an MV2 extension-page policy; Chromium documents that 'unsafe-inline' has no "
                        "effect there (inline scripts stay blocked); other engines may differ")
                else:
                    add("csp.unsafe-inline", directive, "'unsafe-inline'", "high", INLINE_EFFECTS[role])
            if role == "script" and "'wasm-unsafe-eval'" in lowered:
                add("csp.wasm-unsafe-eval", directive, "'wasm-unsafe-eval'", "low", "WebAssembly modules can be compiled")
            if role == "script-src-attr":
                continue  # -attr governs inline handlers only; source URLs have no meaning there
            for token in tokens:
                low = token.lower()
                if role == "worker":
                    if _remote_source(token):
                        add("csp.remote-worker-source", directive, token, "high",
                            "workers can be loaded from outside the package and run code that was not reviewed")
                    elif low in {"data:", "blob:"}:
                        add("csp.data-blob-worker-source", directive, token, "medium",
                            "workers can be built from data:/blob: URLs at runtime")
                elif _remote_source(token):
                    add("csp.remote-script-source", directive, token, "high",
                        "scripts can be loaded from outside the package, so the code that runs can differ from what was reviewed")
                elif _extension_source(token):
                    add("csp.other-extension-script-source", directive, token, "low",
                        "scripts can be loaded from another installed extension's package (not from the network)")
                elif low in {"data:", "blob:"}:
                    add("csp.data-blob-script-source", directive, token, "medium", "scripts can be built from data:/blob: URLs at runtime")
        if script_dir and "object-src" not in d and "default-src" not in d:
            add("csp.missing-object-src", "object-src", "(absent)", "low", "the declared policy does not restrict plugin/object sources")
        connect_dir = "connect-src" if "connect-src" in d else ("default-src" if "default-src" in d else None)
        if connect_dir:
            wide = [t for t in d[connect_dir] if t.lower() in {"*", "http:", "https:", "ws:", "wss:"}]
            for token in wide:
                add("csp.wildcard-connect", connect_dir, token, "medium",
                    "fetch/XHR/WebSocket may reach any origin, an unrestricted outbound channel")
    relax.sort(key=lambda r: (SEVERITY_ORDER[r["severity"]], r["source"], r["id"], r["token"]))
    return {"policies": out_policies, "relaxations": relax}


def _safe_child(root: Path, rel: str) -> Optional[Path]:
    """Resolves ``rel`` under ``root``; None when it escapes the tree or is not a regular file."""
    try:
        candidate = (root / rel)
        resolved = candidate.resolve()
        # realpath-based containment also catches NTFS junctions in intermediate directories.
        if (not _within(candidate, Path(os.path.realpath(root))) or candidate.is_symlink()
                or not resolved.is_file()):
            return None
        return resolved
    except (OSError, ValueError):
        return None


def analyze_dnr(manifest: Dict[str, Any], root: Path, limitations: List[str]
                ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[str], List[Dict[str, Any]]]:
    """Returns (header tampering entries, redirect endpoints, rule file paths, scheme downgrades)
    from declared DNR rule files.

    Only a file that parses as a JSON array of rules is returned as a rule file (and so left out
    of the URL-literal source scan); any other declared path is scanned as an ordinary file.
    """
    tampering: List[Dict[str, Any]] = []
    redirects: List[Dict[str, Any]] = []
    rule_files: List[str] = []
    downgrades: List[Dict[str, Any]] = []
    resources = _as_dict(manifest.get("declarative_net_request")).get("rule_resources")
    if resources is not None and not isinstance(resources, list):
        limitations.append("declarative_net_request.rule_resources is not a list; not analyzed")
    resource_list = _dict_list(resources)
    if len(resource_list) > MAX_RULE_RESOURCES:
        limitations.append(Gap(f"declarative_net_request declares {len(resource_list)} rule resources; only the first "
                               f"{MAX_RULE_RESOURCES} were analyzed, so header tampering or redirects in the rest are NOT reported"))
    budget = MAX_RULE_TOTAL_BYTES
    seen_paths: set = set()
    for resource in resource_list[:MAX_RULE_RESOURCES]:
        rel = resource.get("path")
        if not isinstance(rel, str):
            limitations.append(f"declarativeNetRequest rule resource without a string path ({type(rel).__name__}); skipped")
            continue
        path = _safe_child(root, rel.lstrip("/"))
        if path is None:
            limitations.append(f"declarativeNetRequest rule file not readable inside the package: {rel}")
            continue
        rel_posix = path.relative_to(root.resolve()).as_posix()
        if rel_posix in seen_paths:
            continue
        seen_paths.add(rel_posix)
        if budget <= 0:
            limitations.append(Gap(f"declarativeNetRequest rule file {rel_posix} not analyzed: the total rule-file budget of "
                                   f"{MAX_RULE_TOTAL_BYTES} bytes is used up; its header tampering or redirects are NOT reported"))
            continue
        try:
            text = _read_capped(path, min(MAX_RULE_FILE_BYTES, budget))
        except OSError as exc:
            limitations.append(f"declarativeNetRequest rule file {rel_posix} is not readable: {exc}")
            continue
        if text is None:
            limitations.append(Gap(f"declarativeNetRequest rule file {rel_posix} is larger than {min(MAX_RULE_FILE_BYTES, budget)} "
                                   "bytes; not analyzed as rules (scanned as a source file instead, within the source size cap)"))
            continue
        budget -= len(text)
        try:
            rules = json.loads(text)
        except (ValueError, RecursionError) as exc:
            limitations.append(f"declarativeNetRequest rule file {rel_posix} is not valid JSON: {exc}; "
                               "scanned as a source file instead")
            continue
        if not isinstance(rules, list):
            limitations.append(f"declarativeNetRequest rule file {rel_posix} is not a JSON array of rules; not analyzed as rules "
                               "(scanned as a source file instead)")
            continue
        rule_files.append(rel_posix)
        for idx, rule in enumerate(rules):
            if not isinstance(rule, dict):
                continue
            action = _as_dict(rule.get("action"))
            rule_id = rule.get("id", idx)
            if not isinstance(rule_id, (int, str)) or isinstance(rule_id, bool):
                rule_id = idx
            for direction, names in (("response", SECURITY_RESPONSE_HEADERS), ("request", SENSITIVE_REQUEST_HEADERS)):
                for h in _dict_list(action.get(f"{direction}Headers")):
                    header = h.get("header").lower() if isinstance(h.get("header"), str) else ""
                    op = h.get("operation") if isinstance(h.get("operation"), str) else ""
                    if header in names and op in {"remove", "set", "append"}:
                        weaken = direction == "response"
                        if weaken and op == "append" and header.startswith("content-security-policy"):
                            # An added policy is enforced on top of the page's own: it can only tighten.
                            severity, effect = "info", f"append of {header} adds a policy; this can only tighten the page's CSP"
                        elif weaken:
                            severity = "high" if op == "remove" else "medium"
                            effect = f"{op} of response header {header} weakens the page's own defences"
                        else:
                            severity = "medium"
                            effect = f"{op} of request header {header} rewrites identity/credential headers sent to servers"
                        tampering.append({
                            "id": "csp.dnr-header-tampering" if weaken else "exfil.dnr-request-header-tampering",
                            "source": "declarativeNetRequest", "file": rel_posix, "line": None, "rule": rule_id,
                            "direction": direction, "header": header, "operation": op,
                            "severity": severity, "effect": effect,
                        })
            redirect = _as_dict(action.get("redirect")) if action.get("type") == "redirect" else {}
            if redirect:
                url = redirect.get("url") if isinstance(redirect.get("url"), str) else redirect.get("regexSubstitution")
                transform = _as_dict(redirect.get("transform"))
                t_host = transform.get("host") if isinstance(transform.get("host"), str) else ""
                t_scheme = transform.get("scheme").lower() if isinstance(transform.get("scheme"), str) else ""
                if isinstance(url, str) and split_url(url):
                    redirects.append({"file": rel_posix, "line": None, "kind": "dnr-redirect", "url": url,
                                      "snippet": f"rule {rule_id}: redirect -> {url}"[:180]})
                elif t_host:
                    # Without transform.scheme the request keeps its own scheme: shown scheme-relative.
                    shown = f"{t_scheme}://{t_host}/" if t_scheme else f"//{t_host}/"
                    redirects.append({"file": rel_posix, "line": None, "kind": "dnr-redirect", "url": shown,
                                      "snippet": f"rule {rule_id}: redirect transform host -> {t_host}"
                                                 + (f" (scheme {t_scheme})" if t_scheme else "")})
                if t_scheme in {"http", "ws", "ftp"}:
                    downgrades.append({"file": rel_posix, "line": None, "rule": rule_id, "scheme": t_scheme,
                                       "snippet": f"rule {rule_id}: redirect transform scheme -> {t_scheme}"})
    return tampering, redirects, rule_files, downgrades


# ----------------------------------------------------------------------------------------------
# Source scanning
# ----------------------------------------------------------------------------------------------

CODE_ROLES = ("background", "content", "page")


def manifest_code_refs(manifest: Dict[str, Any]) -> List[Tuple[str, str]]:
    """(relative path, role) for every package file the manifest loads as code or as a page.

    role: "background" (service worker / background scripts or page), "content" (content
    scripts, which run in web pages), "page" (popup, options, devtools, side panel, overrides,
    sandbox pages) or "resource" (web_accessible_resources entries without wildcards).
    """
    refs: List[Tuple[str, str]] = []

    def add(value: Any, role: str) -> None:
        for v in _str_list(value):
            v = v.split("#", 1)[0].split("?", 1)[0].strip().lstrip("/")
            if v and "*" not in v and split_url(v) is None:
                refs.append((v, role))

    bg = _as_dict(manifest.get("background"))
    add(bg.get("service_worker"), "background")
    add(bg.get("scripts"), "background")
    add(bg.get("page"), "background")
    for cs in _dict_list(manifest.get("content_scripts")):
        add(cs.get("js"), "content")
    for key in ("action", "browser_action", "page_action"):
        add(_as_dict(manifest.get(key)).get("default_popup"), "page")
    add(manifest.get("options_page"), "page")
    add(_as_dict(manifest.get("options_ui")).get("page"), "page")
    add(manifest.get("devtools_page"), "page")
    add(_as_dict(manifest.get("side_panel")).get("default_path"), "page")
    add(_as_dict(manifest.get("sidebar_action")).get("default_panel"), "page")
    add(list(_as_dict(manifest.get("chrome_url_overrides")).values()), "page")
    add(_as_dict(manifest.get("sandbox")).get("pages"), "page")
    add(_as_dict(manifest.get("user_scripts")).get("api_script"), "content")
    war = manifest.get("web_accessible_resources")
    if isinstance(war, list):
        for item in war:
            add(item if isinstance(item, str) else _as_dict(item).get("resources"), "resource")
    return refs


# Manifest fields that name network destinations (not package files).
MANIFEST_URL_FIELDS: Tuple[Tuple[Tuple[str, ...], str], ...] = (
    (("homepage_url",), "manifest-homepage-url"),
    (("update_url",), "manifest-update-url"),
    (("chrome_settings_overrides", "search_provider", "search_url"), "manifest-search-url"),
    (("chrome_settings_overrides", "search_provider", "suggest_url"), "manifest-suggest-url"),
    (("chrome_settings_overrides", "search_provider", "instant_url"), "manifest-search-url"),
    (("chrome_settings_overrides", "search_provider", "image_url"), "manifest-search-url"),
    (("chrome_settings_overrides", "search_provider", "new_tab_url"), "manifest-search-url"),
    (("chrome_settings_overrides", "search_provider", "favicon_url"), "manifest-favicon-url"),
    (("chrome_settings_overrides", "homepage"), "manifest-homepage-override"),
    (("chrome_settings_overrides", "startup_pages"), "manifest-startup-page"),
    (("author",), "manifest-author-url"),
    (("developer", "url"), "manifest-developer-url"),
    (("chrome_settings_overrides", "search_provider", "alternate_urls"), "manifest-search-url"),
    (("browser_specific_settings", "gecko", "update_url"), "manifest-update-url"),
    (("applications", "gecko", "update_url"), "manifest-update-url"),
)


def manifest_url_endpoints(manifest: Dict[str, Any], manifest_rel: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for path, kind in MANIFEST_URL_FIELDS:
        node: Any = manifest
        for key in path:
            node = _as_dict(node).get(key)
        for u in _str_list(node):
            parsed = split_url(u)
            if parsed and parsed[0] in NETWORK_SCHEMES and parsed[1]:
                out.append({"file": manifest_rel, "line": None, "kind": kind, "url": u,
                            "snippet": f"{'.'.join(path)}: {u}"[:180]})
    return out


def iter_source_files(root: Path, max_files: int, skip: Iterable[str], limitations: List[str],
                      include_vendored: bool = False, unskip_dirs: Iterable[str] = ()) -> Tuple[List[Path], int]:
    """Walks the package for source files, at most ``max_files`` of them (the walk stops there).

    Pruned: links/junctions/reparse points, directories resolving outside the root, already
    visited directories (by device and inode), .git/__pycache__, and the VENDORED_DIRS unless
    ``include_vendored`` is set or the directory is (an ancestor of) one in ``unskip_dirs``.
    Every pruned vendored directory is named in ``limitations``.
    """
    files: List[Path] = []
    skipped = 0
    skip_set = set(skip)
    unskip = set(unskip_dirs)
    real_root = Path(os.path.realpath(root))
    visited: set = set()
    capped = False
    try:
        st = os.stat(root)
        visited.add((st.st_dev, st.st_ino))
    except OSError:
        pass
    # os.walk(followlinks=False) still descends into NTFS junctions (they are not symlinks), so
    # every directory is pruned when it is a link/junction or resolves outside the extension root.
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        kept = []
        for d in sorted(dirnames):
            full = os.path.join(dirpath, d)
            rel_dir = Path(full).relative_to(root).as_posix()
            if d in SKIP_DIRS:
                skipped += 1
                continue
            if d in VENDORED_DIRS and not include_vendored and not any(u == rel_dir or u.startswith(rel_dir + "/") for u in unskip):
                skipped += 1
                limitations.append(f"{rel_dir}: vendored/tooling directory not walked (files it holds that the manifest "
                                   "or a scanned file references are still scanned; use --include-vendored to walk it)")
                continue
            if _is_link_or_junction(full) or not _within(Path(full), real_root):
                skipped += 1
                limitations.append(f"{rel_dir}: symlink/junction directory, not followed")
                continue
            try:
                dst = os.stat(full)
                key = (dst.st_dev, dst.st_ino)
            except OSError:
                skipped += 1
                continue
            if dst.st_ino and key in visited:
                skipped += 1
                limitations.append(f"{rel_dir}: directory already visited (link loop), not walked again")
                continue
            visited.add(key)
            kept.append(d)
        dirnames[:] = kept
        for name in sorted(filenames):
            p = Path(dirpath) / name
            if p.suffix.lower() not in SOURCE_EXTS:
                continue
            rel = p.relative_to(root).as_posix()
            if rel in skip_set:
                continue
            if p.is_symlink() or not _within(p, real_root):
                skipped += 1
                limitations.append(f"{rel}: symlink or link resolving outside the package, not read")
                continue
            try:
                size = p.stat().st_size
            except OSError:
                skipped += 1
                continue
            if size > MAX_FILE_BYTES:
                skipped += 1
                limitations.append(Gap(f"{rel}: larger than {MAX_FILE_BYTES} bytes, not scanned"))
                continue
            if len(files) >= max_files:
                capped = True
                break
            files.append(p)
        if capped:
            break
    if capped:
        limitations.append(Gap(f"--max-files cap reached: the walk stopped after {max_files} source file(s); "
                               "files after that point were NOT scanned and their findings are not reported"))
    if skipped:
        limitations.append(f"{skipped} path(s) skipped (vendored directories, links, size cap)")
    return files, skipped


def _endpoint(rel: str, lines: _Lines, pos: int, kind: str, value: Optional[str]) -> Dict[str, Any]:
    return {"file": rel, "line": lines.line(pos), "kind": kind, "url": value if value is not None else "<dynamic>",
            "snippet": lines.snippet(pos)}


def scan_source(rel: str, text: str, as_code: bool = False) -> Dict[str, Any]:
    """Extracts endpoints, sensitive sources, header-tampering leads and package-local code
    references from one file's text. ``as_code`` scans a ``.json`` file as JavaScript (the
    manifest loads it as a script)."""
    lines = _Lines(text)
    endpoints: List[Dict[str, Any]] = []
    local_refs: List[str] = []
    inject_refs: List[str] = []  # chrome.scripting.executeScript({files}) / registerContentScripts({js})
    consumed: set = set()
    claimed_pos: set = set()
    is_html = rel.lower().endswith(HTML_EXTS)
    is_json = rel.lower().endswith(".json") and not as_code
    dropped = 0        # distinct (kind, host) references beyond the hard cap: content NOT recorded
    collapsed = 0      # repeats of an already-recorded (kind, host), or runtime-built ones, past the soft cap
    seen_keys: set = set()

    def add_endpoint(pos: int, kind: str, value: Optional[str]) -> None:
        # Bounded per file: a minified file with 10^5 call sites must not cost unbounded memory/time.
        # Past the soft cap only references to a (kind, host) not seen yet are kept, so a beacon
        # after 2000 dynamic fetch(x) calls, or a bundle with thousands of docs links to one host,
        # neither hides a new destination nor looks incomplete.
        nonlocal dropped, collapsed
        parsed = split_url(value) if value is not None else None
        key = (kind, parsed[1] if parsed else "<dynamic>")
        if len(endpoints) >= MAX_ENDPOINTS_PER_FILE:
            if key in seen_keys or value is None:
                collapsed += 1
                return
            if len(endpoints) >= MAX_ENDPOINTS_HARD_CAP:
                dropped += 1
                return
        seen_keys.add(key)
        endpoints.append(_endpoint(rel, lines, pos, kind, value))

    if not is_json:
        for kind, regex in SINKS:
            for m in regex.finditer(text):
                if m.start() in claimed_pos or (m.end() - 1) in claimed_pos:
                    continue
                claimed_pos.update({m.start(), m.end() - 1})
                value, lit_pos, partial = _read_literal(text, m.end())
                if value is not None:
                    consumed.add(lit_pos)
                    parsed = split_url(value)
                    if parsed is None:
                        if partial and not _looks_like_relative_path(value):
                            value = None  # `${base}/x`, '//' + host: the destination is built at runtime
                        else:
                            if kind in {"importScripts", "dynamic-import"} and not partial:
                                local_refs.append(value)
                            continue  # relative path: resolved against the extension origin
                    elif parsed[0] not in NETWORK_SCHEMES:
                        continue  # chrome-extension:, data:, blob:, javascript: ...
                    elif not parsed[1]:
                        value = None  # 'https://' + host: scheme known, host built at runtime
                elif kind in {"src-assign", "pixel"}:
                    continue  # unknown right-hand side of an assignment: too noisy to report
                elif INTERNAL_URL_CALL_RE.match(text, m.end()):
                    continue  # chrome.runtime.getURL(...): a package-internal resource

                add_endpoint(m.start(), kind, value)
        for m in STATIC_IMPORT_RE.finditer(text):
            local_refs.append(js_unescape(m.group(2)))
        for m in LOCAL_REF_RE.finditer(text):
            local_refs.append(js_unescape(m.group(2)))
        for m in IMPORT_SCRIPTS_ARGS_RE.finditer(text):
            local_refs.extend(js_unescape(s.group(2)) for s in STRING_ITEM_RE.finditer(m.group(1)))
        for m in INJECT_FILES_RE.finditer(text):
            inject_refs.extend(js_unescape(s.group(2)) for s in STRING_ITEM_RE.finditer(m.group(1)))
    if is_html or not is_json:
        # HTML pages: comments/raw-text content masked (same offsets). Scripts: tags inside JS
        # strings (document.write('<script src=...>')) contribute package references only.
        # HTML runs twice, masked and raw, merged by value offset (same length, same offsets): the
        # masked pass survives stray quotes in comments/scripts, the raw pass survives any masking
        # mistake, so together they never see less than the plain v1.0.0-style scan.
        seen_values: set = set()
        tag_hits = ((m, a) for markup in ([_mask_html(text), text] if is_html else [text])
                    for m in HTML_TAG_RE.finditer(markup) for a in HTML_ATTR_RE.finditer(m.group(2)))
        for m, a in tag_hits:
            tag = m.group(1).lower()
            group = 2 if a.group(2) is not None else (3 if a.group(3) is not None else (4 if a.group(4) is not None else 0))
            if not group:
                continue  # attribute without a value
            if a.group(1).lower() not in URL_ATTRS:
                continue
            value_pos = m.start(2) + a.start(group)
            if value_pos in seen_values:
                continue
            seen_values.add(value_pos)
            value = html.unescape(a.group(group)).strip()
            parsed = split_url(value)
            if not is_html:
                if parsed is None and tag in {"script", "iframe", "frame"} and value:
                    local_refs.append(value)
                continue
            consumed.add(m.start(2) + a.start(group) - 1)  # the quote: the literal scan skips this value
            if parsed and parsed[0] in NETWORK_SCHEMES and parsed[1]:
                add_endpoint(m.start(), f"html-{'iframe' if tag == 'frame' else tag}", value)
            elif parsed is None and tag in {"script", "iframe", "frame"} and value:
                local_refs.append(value)
    for m in URL_LITERAL_RE.finditer(text):
        if m.start() in consumed:
            continue
        value = js_unescape(m.group(2))
        if value.lower().startswith(("http://www.w3.org/", "https://www.w3.org/")):
            continue  # XML/SVG namespace identifiers, not destinations
        add_endpoint(m.start(), "literal", value)

    sources: List[Dict[str, Any]] = []
    tampering: List[Dict[str, Any]] = []
    capture: Optional[Dict[str, Any]] = None
    dynamic_dnr: List[Dict[str, Any]] = []
    if not is_json:
        for name, regex in SOURCES:
            m = regex.search(text)
            if m:
                sources.append({"source": name, "file": rel, "line": lines.line(m.start()), "snippet": lines.snippet(m.start())})
        cap = WEBREQUEST_CAPTURE_RE.search(text)
        listeners = list(WEBREQUEST_LISTENER_RE.finditer(text)) if cap else []
        # The listener the capture option belongs to is the last one registered before it.
        listener = next((lm for lm in reversed(listeners) if lm.start() < cap.start()), listeners[0] if listeners else None)
        if listener and cap:
            capture = {"file": rel, "line": lines.line(listener.start()), "snippet": lines.snippet(listener.start())}
        if HEADERS_RECEIVED_RE.search(text) and "responseHeaders" in text:
            # Only a blocking listener ('blocking' in extraInfoSpec) can change headers, and it does so
            # by returning {responseHeaders}. A non-blocking listener can only read them.
            blocking = BLOCKING_SPEC_RE.search(text) is not None
            returns = RETURNED_HEADERS_RE.search(text) is not None
            if blocking and returns:
                severity, op, how = "high", "rewrite", "a blocking listener that returns responseHeaders"
            elif blocking:
                severity, op, how = "medium", "possible rewrite", "a blocking listener (no returned responseHeaders seen)"
            elif returns:
                # The 'blocking' spec may be built elsewhere (another file, a variable): still a lead.
                severity, op, how = "medium", "possible rewrite", "a listener that returns responseHeaders (no 'blocking' spec seen in this file)"
            else:
                severity, op, how = "low", "read", "a non-blocking listener, which can read but not change headers"
            seen_headers: set = set()
            for hm in HEADER_NAME_RE.finditer(text):
                name = hm.group(1).lower()
                if name in seen_headers:
                    continue
                seen_headers.add(name)
                tampering.append({
                    "id": "csp.webrequest-header-tampering", "source": "webRequest.onHeadersReceived", "file": rel,
                    "line": lines.line(hm.start()), "rule": None, "direction": "response", "header": name,
                    "operation": op, "severity": severity,
                    "effect": f"onHeadersReceived code references {name} in {how}"
                              + (", a pattern used to strip or rewrite the page's security headers" if severity != "low" else ""),
                })
        for dm in DYNAMIC_DNR_RE.finditer(text):
            dynamic_dnr.append({"file": rel, "line": lines.line(dm.start()), "snippet": lines.snippet(dm.start()), "api": dm.group(1)})
    return {"endpoints": endpoints, "sources": sources, "tampering": tampering, "capture": capture,
            "dynamic_dnr": dynamic_dnr, "local_refs": local_refs, "inject_refs": inject_refs,
            "dropped_endpoints": dropped, "collapsed_endpoints": collapsed}


# ----------------------------------------------------------------------------------------------
# Analysis
# ----------------------------------------------------------------------------------------------

def _finding(fid: str, severity: str, confidence: float, message: str, evidence: List[Dict[str, Any]],
             alternatives: List[str]) -> Dict[str, Any]:
    ev: List[Dict[str, Any]] = []
    for e in evidence:
        item = {"file": e["file"], "line": e.get("line"), "snippet": e.get("snippet", "")}
        if item not in ev:
            ev.append(item)
    return {"id": fid, "severity": severity, "confidence": confidence, "message": message,
            "evidence": ev, "alternatives": alternatives}


def analyze(path: Any, max_files: int = DEFAULT_MAX_FILES, include_vendored: bool = False) -> Dict[str, Any]:
    """Statically analyzes an unpacked extension and returns the report as a dict.

    Raises InputError when the path is not an extension directory or manifest.json.
    """
    manifest_path = locate_manifest(Path(path))
    root = manifest_path.parent
    limitations: List[str] = [
        "Static analysis only: URLs built at runtime, minified or obfuscated code and remotely loaded code are not resolved.",
    ]
    try:
        text = _read_capped(manifest_path, MAX_MANIFEST_BYTES, encoding="utf-8-sig")
    except OSError as exc:
        raise InputError(f"manifest.json is not readable: {exc}") from exc
    if text is None:
        raise InputError(f"manifest.json is larger than {MAX_MANIFEST_BYTES} bytes")
    try:
        manifest = json.loads(text)
    except (ValueError, RecursionError) as exc:
        raise InputError(f"manifest.json is not valid JSON: {exc}") from exc
    if not isinstance(manifest, dict):
        raise InputError("manifest.json is not a JSON object")

    permissions = sorted(set(_str_list(manifest.get("permissions")) + _str_list(manifest.get("optional_permissions"))))
    host_perms = sorted(set(_str_list(manifest.get("host_permissions")) + _str_list(manifest.get("optional_host_permissions"))))
    content_scripts = manifest.get("content_scripts")
    if content_scripts is not None and not isinstance(content_scripts, list):
        limitations.append(f"content_scripts has an unexpected shape ({type(content_scripts).__name__}); ignored")
    cs_matches = sorted({m for cs in _dict_list(content_scripts) for m in _str_list(cs.get("matches"))})
    every = permissions + host_perms + cs_matches
    broad = sorted({p for p in every if p in BROAD_MATCHES or re.match(r"^(\*|https?|wss?)://\*/", p)})
    ext_conn = _as_dict(manifest.get("externally_connectable"))

    vendor_domains = sorted({_vendor_domain(ascii_host(p[1])[0])
                             for u in _str_list(manifest.get("homepage_url")) + _str_list(manifest.get("update_url"))
                             for p in [split_url(u)] if p and p[0] in NETWORK_SCHEMES and p[1] and p[1] not in STORE_HOSTS
                             and "." in p[1].strip(".") and _ip(p[1]) is None})  # never a bare TLD such as "com"

    csp = analyze_csp(manifest, limitations)
    tampering, dnr_redirects, rule_files, downgrades = analyze_dnr(manifest, root, limitations)
    manifest_rel = manifest_path.relative_to(root).as_posix()
    real_root = root.resolve()

    # Files to scan: first every file the manifest loads (wherever it lives, vendored or not),
    # then the files those reference, then the directory walk, then what the walked files reference.
    queue: "deque[Tuple[Path, str, bool]]" = deque()
    queued: set = set()
    cap_missed: List[str] = []
    content_files: set = set()
    background_files: set = set()

    def enqueue(p: Path, rel: str, as_code: bool) -> None:
        if rel in queued:
            return
        if len(queued) >= max_files:
            cap_missed.append(rel)
            return
        queued.add(rel)
        queue.append((p, rel, as_code))

    def resolve_ref(base_dir: str, ref: str) -> Optional[Tuple[Path, str]]:
        ref = _pct_decode(ref.split("#", 1)[0].split("?", 1)[0].strip()).replace("\\", "/")
        if not ref or split_url(ref) is not None:
            return None
        if ref.startswith("/"):
            candidates = [ref.lstrip("/")]
        else:  # relative to the referencing file; package-root-relative as a fallback (getURL, executeScript)
            candidates = [posixpath.join(base_dir, ref), ref] if base_dir else [ref]
        p = None
        for c in candidates:
            p = _safe_child(root, posixpath.normpath(c))
            if p is not None:
                break
        if p is None:
            return None
        try:
            return p, p.relative_to(real_root).as_posix()
        except ValueError:
            return None

    for ref, role in manifest_code_refs(manifest):
        r = resolve_ref("", ref)
        if r is None:
            if role != "resource":
                limitations.append(f"manifest {role} file {ref} is not a regular file inside the package; not scanned")
            continue
        p, rel = r
        if role == "resource" and p.suffix.lower() not in SOURCE_EXTS:
            continue
        (content_files if role == "content" else background_files if role == "background" else set()).add(rel)
        enqueue(p, rel, role in ("background", "content") and not rel.lower().endswith(HTML_EXTS))

    per_file: Dict[str, Dict[str, Any]] = {}

    def drain() -> None:
        while queue:
            p, rel, as_code = queue.popleft()
            try:
                text = _read_capped(p, MAX_FILE_BYTES)
            except OSError as exc:
                limitations.append(f"{rel}: not readable ({exc})")
                continue
            if text is None:
                limitations.append(Gap(f"{rel}: larger than {MAX_FILE_BYTES} bytes, not scanned"))
                continue
            res = scan_source(rel, text, as_code=as_code)
            per_file[rel] = res
            if res["dropped_endpoints"]:
                limitations.append(Gap(f"{rel}: more than {MAX_ENDPOINTS_HARD_CAP} distinct endpoint references; "
                                       f"{res['dropped_endpoints']} further references NOT recorded"))
            if res["collapsed_endpoints"]:
                limitations.append(f"{rel}: more than {MAX_ENDPOINTS_PER_FILE} endpoint references; "
                                   f"{res['collapsed_endpoints']} repeats of already-listed (kind, host) pairs or "
                                   "runtime-built destinations were collapsed (every distinct host is still listed)")
            base = posixpath.dirname(rel)
            refs = dict.fromkeys([(x, False) for x in res["local_refs"]] + [(x, True) for x in res["inject_refs"]])
            for ref, injected in refs:
                r = resolve_ref(base if not injected else "", ref)
                if r is None or (r[0].suffix.lower() not in SOURCE_EXTS and r[0].suffix):
                    continue
                if injected:
                    content_files.add(r[1])
                enqueue(r[0], r[1], not r[1].lower().endswith(HTML_EXTS))

    drain()
    unskip = {posixpath.dirname(rel) for rel in queued}
    files, skipped = iter_source_files(root, max(0, max_files - len(queued)), [manifest_rel] + rule_files + sorted(queued),
                                       limitations, include_vendored=include_vendored, unskip_dirs=unskip)
    for f in files:
        enqueue(f, f.relative_to(root).as_posix(), False)
    drain()
    if cap_missed:
        limitations.append(Gap(f"--max-files cap ({max_files}) reached: {len(cap_missed)} referenced file(s) NOT scanned, e.g. "
                               + ", ".join(sorted(set(cap_missed))[:5])))

    endpoints: List[Dict[str, Any]] = list(dnr_redirects)
    dynamic_dnr: List[Dict[str, Any]] = []
    for rel in sorted(per_file):
        res = per_file[rel]
        endpoints.extend(res["endpoints"])
        tampering.extend(res["tampering"])
        dynamic_dnr.extend(res["dynamic_dnr"])
    endpoints.extend(manifest_url_endpoints(manifest, manifest_rel))

    def extension_origin_file(rel: str) -> bool:
        """Protocol-relative URLs here resolve against chrome-extension://, not the network."""
        return rel.lower().endswith(HTML_EXTS) or (rel in background_files and rel not in content_files)

    # Classify every endpoint (lexically) and drop non-network ones.
    classified: List[Dict[str, Any]] = []
    for e in endpoints:
        parsed = None if e["url"] == "<dynamic>" else split_url(e["url"])
        if e["url"] == "<dynamic>" or (parsed and parsed[0] in NETWORK_SCHEMES and not parsed[1]):
            e.update(scheme=parsed[0] if parsed else None, host="<dynamic>", **{"class": "dynamic"},
                     reserved_example=False, unicode_host=None)
            classified.append(e)
            continue
        if not parsed or parsed[0] not in NETWORK_SCHEMES:
            continue
        scheme, raw_host = parsed
        host, non_ascii = ascii_host(raw_host)
        cls = classify_host(host, vendor_domains)
        if scheme == PROTOCOL_RELATIVE and is_outbound(cls) and extension_origin_file(e["file"]):
            cls = EXTENSION_ORIGIN_CLASS
        e.update(scheme=scheme, host=host, **{"class": cls}, reserved_example=is_reserved_example(host),
                 unicode_host=raw_host if non_ascii else None)
        classified.append(e)
    classified.sort(key=lambda e: (e["file"], e["line"] or 0, e["kind"], e["url"]))

    # Host inventory (potential destinations, never observed traffic).
    hosts: Dict[str, Dict[str, Any]] = {}
    for e in classified:
        if e["host"] == "<dynamic>":
            continue
        h = hosts.setdefault((e["host"], e["class"]), {
            "host": e["host"], "class": e["class"], "reserved_example": e["reserved_example"],
            "unicode_host": e["unicode_host"], "schemes": set(), "kinds": set(), "references": 0,
            "first_reference": f"{e['file']}:{e['line'] or '-'}"})
        h["schemes"].add(e["scheme"])
        h["kinds"].add(e["kind"])
        h["references"] += 1
    host_list = [dict(h, schemes=sorted(h["schemes"]), kinds=sorted(h["kinds"])) for h in hosts.values()]
    host_list.sort(key=lambda h: (0 if is_outbound(h["class"]) else 1, h["host"], h["class"]))
    if any(h["unicode_host"] for h in host_list):
        limitations.append("Some hosts contain non-ASCII characters; they are listed in their IDNA (punycode) form, as "
                           "browsers send them. Check them for look-alike (homoglyph) names.")

    findings = _heuristics(classified, per_file, broad, dynamic_dnr, downgrades)
    # A capped/truncated analysis must not look clean: content was left unread, so report it as a
    # medium finding (exit 1) instead of letting a Limitations line accompany exit 0.
    gaps = [lim for lim in limitations if isinstance(lim, Gap)]
    if gaps:
        findings.append(_finding(
            "analysis.incomplete-coverage", "medium", 1.0,
            f"{len(gaps)} part(s) of the package were not analyzed because of size/count caps; findings there are "
            "unknown, so this result is not a clean bill of health.",
            [{"file": "(analysis)", "line": None, "snippet": g[:180]} for g in gaps[:3]],
            ["Raise --max-files, or review the listed files manually"]))
        findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["id"], f["evidence"][0]["file"] if f["evidence"] else "",
                                     f["evidence"][0]["line"] or 0 if f["evidence"] else 0, f["message"]))
    tampering.sort(key=lambda t: (SEVERITY_ORDER[t["severity"]], t["file"], t["line"] or 0, t["header"]))

    if len(classified) > MAX_ENDPOINTS_IN_REPORT:
        limitations.append(f"{len(classified)} endpoint references found; the report lists the first {MAX_ENDPOINTS_IN_REPORT}.")

    return {
        "tool": TOOL,
        "version": VERSION,
        "offline": True,
        "observed_network_activity": False,
        "disclaimer": DISCLAIMER,
        "target": {
            "path": str(path),
            "manifest": manifest_rel,
            "name": manifest.get("name") if isinstance(manifest.get("name"), str) else None,
            "version": manifest.get("version") if isinstance(manifest.get("version"), str) else None,
            "manifest_version": _json_scalar(manifest.get("manifest_version")),
            "permissions": permissions,
            "host_permissions": host_perms,
            "broad_host_access": broad,
            "externally_connectable": {"matches": sorted(_str_list(ext_conn.get("matches"))), "ids": sorted(_str_list(ext_conn.get("ids")))},
            "vendor_domains": vendor_domains,
        },
        "hosts": host_list,
        "endpoints": classified[:MAX_ENDPOINTS_IN_REPORT],
        "findings": findings,
        "csp": csp,
        "header_tampering": tampering,
        "limitations": limitations,
        "stats": {"files_scanned": len(per_file), "files_skipped": skipped, "endpoint_references": len(classified)},
    }


def _heuristics(endpoints: List[Dict[str, Any]], per_file: Dict[str, Dict[str, Any]], broad: List[str],
                dynamic_dnr: List[Dict[str, Any]], downgrades: Iterable[Dict[str, Any]] = ()) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    by_file: Dict[str, List[Dict[str, Any]]] = {}
    for e in endpoints:
        by_file.setdefault(e["file"], []).append(e)
    outbound_requests = [e for e in endpoints if is_outbound(e["class"]) and (e["kind"] in REQUEST_KINDS or e["kind"] == "dnr-redirect")]

    for rel in sorted(per_file):
        info = per_file[rel]
        sinks = [e for e in by_file.get(rel, []) if is_outbound(e["class"]) and e["kind"] in REQUEST_KINDS]
        if info["sources"] and sinks:
            names = {s["source"] for s in info["sources"]}
            kinds = ", ".join(sorted(names))
            hosts = ", ".join(sorted({s["host"] for s in sinks}))
            # Extension/web storage alone is ordinary settings state: a weaker lead than cookies,
            # history, tabs, identity tokens or password fields.
            storage_only = names == {"storage"}
            findings.append(_finding(
                "exfil.sensitive-source-to-external-sink", "medium" if storage_only else "high", 0.4 if storage_only else 0.6,
                f"{rel} reads {'stored extension/page data' if storage_only else 'sensitive data'} ({kinds}) and also "
                f"contains requests to {hosts}; the data may be sent to these potential destinations.",
                info["sources"][:3] + sinks[:3],
                ["Sync or backup service run by the vendor", "Unrelated code paths bundled in one file"]
                + (["Settings read from storage to configure an API call"] if storage_only else [])))
        if info["sources"] and not sinks:
            # const u = 'https://host/c'; fetch(u, {body: secret}): the sink's argument is a variable,
            # so link the file's outbound URL literals to its runtime-built requests.
            literals = [e for e in by_file.get(rel, []) if is_outbound(e["class"]) and e["kind"] == "literal"]
            dyn_sinks = [e for e in by_file.get(rel, []) if e["class"] == "dynamic" and e["kind"] in REQUEST_KINDS]
            if literals and dyn_sinks:
                findings.append(_finding(
                    "exfil.sensitive-source-to-possible-sink", "medium", 0.4,
                    f"{rel} reads sensitive data ({', '.join(sorted({s['source'] for s in info['sources']}))}), makes "
                    f"requests whose URL is a variable, and contains URL literals for "
                    f"{', '.join(sorted({e['host'] for e in literals})[:5])}; the data may be sent there.",
                    info["sources"][:2] + dyn_sinks[:2] + literals[:2],
                    ["URL literals used for links or documentation only", "Requests to the page's own origin"]))
        if info["capture"] and sinks:
            findings.append(_finding(
                "exfil.webrequest-capture", "high", 0.55,
                f"{rel} registers a webRequest listener that reads request bodies or headers and also contains requests "
                f"to {', '.join(sorted({s['host'] for s in sinks}))}.",
                [info["capture"]] + sinks[:3],
                ["Privacy or debugging tool that inspects traffic locally"]))
        dyn = [e for e in by_file.get(rel, []) if e["class"] == "dynamic" and e["kind"] in REQUEST_KINDS]
        if dyn and broad:
            findings.append(_finding(
                "exfil.dynamic-endpoint", "low", 0.3,
                f"{rel} makes {len(dyn)} request(s) whose destination is computed at runtime, while the extension has "
                f"broad host access ({', '.join(broad[:3])}); the destination cannot be determined statically.",
                dyn[:3], ["Configurable API base URL", "Requests to the page's own origin"]))

    for e in outbound_requests:
        if e["kind"] in {"beacon", "pixel"}:
            findings.append(_finding(
                "exfil.beacon-or-pixel", "medium", 0.55,
                f"{e['kind']} request to {e['host']}: a fire-and-forget channel commonly used for tracking or data exfiltration.",
                [e], ["Analytics or crash telemetry"]))
        if e["scheme"] in {"http", "ws", "ftp"}:
            findings.append(_finding(
                "exfil.cleartext-endpoint", "medium", 0.6,
                f"Cleartext {e['scheme']}:// destination {e['host']}: anything sent there can be read or altered in transit.",
                [e], ["Legacy endpoint that redirects to HTTPS"]))
        if _ip(e["host"]) is not None:
            findings.append(_finding(
                "exfil.raw-ip-endpoint", "medium", 0.5,
                f"Destination is a literal IP address ({e['host']}) rather than a named host.",
                [e], ["Self-hosted test server"]))
        if e["kind"] == "dnr-redirect":
            findings.append(_finding(
                "exfil.dnr-redirect-external", "high", 0.65,
                f"A declarativeNetRequest rule redirects matching requests to {e['host']}.",
                [e], ["Privacy redirector to an alternative front-end"]))
    for e in endpoints:
        if is_outbound(e["class"]) and e["kind"] in CODE_KINDS:
            findings.append(_finding(
                "exfil.remote-code", "high", 0.7,
                f"Code is loaded from {e['host']} ({e['kind']}), so the code that runs can differ from the reviewed package "
                "and may change what is sent where.",
                [e], ["Vendor-hosted library (still violates store remote-code policies in MV3)"]))
    for e in endpoints:
        if is_outbound(e["class"]) and e["kind"] in {"manifest-search-url", "manifest-suggest-url"}:
            findings.append(_finding(
                "exfil.search-provider-override", "medium", 0.6,
                f"chrome_settings_overrides.search_provider sends address-bar search queries to {e['host']} "
                f"({e['kind'].replace('manifest-', '')}).",
                [e], ["Legitimate search-engine extension"]))
    for d in downgrades:
        findings.append(_finding(
            "exfil.dnr-scheme-downgrade", "medium", 0.6,
            f"A declarativeNetRequest redirect transform switches matching requests to cleartext {d['scheme']}://, "
            "so their content can be read or altered in transit.",
            [d], ["Redirect for a legacy local service"]))
    for d in dynamic_dnr:
        findings.append(_finding(
            "exfil.dnr-dynamic-rules", "info", 0.3,
            f"declarativeNetRequest.{d['api']} builds rules at runtime; their headers/redirects are not analyzed statically.",
            [d], ["Rules mirrored from user settings"]))

    findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["id"], f["evidence"][0]["file"] if f["evidence"] else "",
                                 f["evidence"][0]["line"] or 0 if f["evidence"] else 0, f["message"]))
    return findings


def has_failing_findings(report: Dict[str, Any]) -> bool:
    items = report["findings"] + report["csp"]["relaxations"] + report["header_tampering"]
    return any(i["severity"] in FAILING_SEVERITIES for i in items)


# ----------------------------------------------------------------------------------------------
# Rendering
# ----------------------------------------------------------------------------------------------

def _loc(item: Dict[str, Any]) -> str:
    return f"{item['file']}:{item['line']}" if item.get("line") else str(item["file"])


def render(report: Dict[str, Any], fmt: str = "text") -> str:
    """Renders the report. Every value that may come from the extension is escaped: control and
    bidi characters in all human formats, plus Markdown/HTML metacharacters in ``md``."""
    if fmt == "json":
        return json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n"
    md = fmt == "md"
    s = _md if md else _clean
    out: List[str] = []
    t = report["target"]

    def heading(text: str, level: int = 2) -> None:
        out.append("")
        out.append(("#" * level + " " + text) if md else (text + "\n" + ("=" if level == 1 else "-") * len(text)))

    def table(headers: List[str], rows: List[List[Any]]) -> None:
        if md:
            out.append("| " + " | ".join(headers) + " |")
            out.append("|" + "---|" * len(headers))
            out.extend("| " + " | ".join(_md(c) for c in r) + " |" for r in rows)
        else:
            out.extend("  " + " | ".join(_clean(c) for c in r) for r in rows)

    def joined(values: List[Any], empty: str) -> str:
        return ", ".join(s(v) for v in values) or empty

    heading(f"Extension exfiltration & CSP report: {s(t['name']) if t['name'] else '(unnamed)'}", 1)
    out.append("")
    out.append(("> " if md else "NOTE: ") + report["disclaimer"])
    heading("Target")
    out.append(f"- Path: {s(t['path'])}")
    out.append(f"- Manifest: {s(t['manifest'])} (manifest_version {s(t['manifest_version'])}), version {s(t['version'])}")
    out.append(f"- Permissions: {joined(t['permissions'], '(none)')}")
    out.append(f"- Host permissions: {joined(t['host_permissions'], '(none)')}")
    out.append(f"- Broad host access: {joined(t['broad_host_access'], 'no')}")
    if t["vendor_domains"]:
        out.append(f"- Vendor domains (self-declared by homepage_url/update_url; a label, not a trust signal): "
                   f"{joined(t['vendor_domains'], '(none)')}")
    out.append(f"- Files scanned: {report['stats']['files_scanned']}, endpoint references: {report['stats']['endpoint_references']}")

    def host_label(h: Dict[str, Any]) -> str:
        return h["host"] + (" [non-ASCII IDN, shown as punycode]" if h.get("unicode_host") else "")

    heading("External hosts statically referenced (potential destinations, not observed traffic)")
    outbound = [h for h in report["hosts"] if is_outbound(h["class"])]
    if outbound:
        table(["Host", "Class", "Schemes", "Reference kinds", "Refs", "First reference", "Reserved example"],
              [[host_label(h), h["class"], ",".join(h["schemes"]), ",".join(h["kinds"]), h["references"], h["first_reference"],
                "yes" if h["reserved_example"] else "no"] for h in outbound])
    else:
        out.append("No external hosts are statically referenced.")
    other = [h for h in report["hosts"] if not is_outbound(h["class"])]
    if other:
        out.append("")
        out.append("Other referenced hosts (local / browser store / extension-origin = protocol-relative URL in an extension "
                   "page or background script, which resolves to chrome-extension://, not the network): "
                   + ", ".join(f"{s(host_label(h))} ({h['class']})" for h in other))

    heading("Exfiltration findings (static leads, not proof)")
    if report["findings"]:
        for f in report["findings"]:
            out.append(f"- [{f['severity'].upper()}] {s(f['id'])} (confidence {f['confidence']}): {s(f['message'])}")
            for e in f["evidence"]:
                out.append(f"    - {s(_loc(e))}: {s(e['snippet'])}")
            if f["alternatives"]:
                out.append(f"    - Alternative explanations: {s('; '.join(f['alternatives']))}")
    else:
        out.append("No exfiltration heuristics matched.")

    heading("CSP relaxations")
    if report["csp"]["policies"]:
        for p in report["csp"]["policies"]:
            out.append(f"- {s(p['source'])}: {s(p['policy'])}")
    else:
        out.append("- No content_security_policy declared (the browser default policy applies).")
    if report["csp"]["relaxations"]:
        out.append("")
        table(["Severity", "Check", "Policy", "Directive", "Token", "Effect"],
              [[r["severity"], r["id"], r["source"], r["directive"], r["token"], r["effect"]] for r in report["csp"]["relaxations"]])
    else:
        out.append("No CSP relaxations found.")

    heading("Security-header tampering")
    if report["header_tampering"]:
        table(["Severity", "Check", "Location", "Direction", "Header", "Operation"],
              [[x["severity"], x["id"], _loc(x) + (f" (rule {x['rule']})" if x.get("rule") is not None else ""),
                x["direction"], x["header"], x["operation"]] for x in report["header_tampering"]])
    else:
        out.append("No security-header tampering found.")

    heading("Limitations")
    out.extend(f"- {s(lim)}" for lim in report["limitations"])
    return "\n".join(out).lstrip("\n") + "\n"


# ----------------------------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------------------------

def _emit(stream: Any, text: str) -> None:
    """Writes ``text`` to a text stream without ever raising UnicodeEncodeError: characters the
    stream's encoding (e.g. cp1252/cp1254 on a Windows console or redirect) cannot represent are
    written as \\uXXXX escapes instead."""
    encoding = getattr(stream, "encoding", None) or "utf-8"
    try:
        data = text.encode(encoding, errors="backslashreplace")
    except LookupError:
        encoding, data = "ascii", text.encode("ascii", errors="backslashreplace")
    buffer = getattr(stream, "buffer", None)
    if buffer is not None:
        stream.flush()
        buffer.write(data)
        buffer.flush()
    else:
        stream.write(data.decode(encoding, errors="replace"))
        stream.flush()


def _error(message: str) -> int:
    """One sanitized line on stderr; always exit 2 (never 1, which means findings)."""
    try:
        _emit(sys.stderr, f"error: {_clean(message)}\n")
    except (OSError, ValueError, AttributeError):
        pass
    return 2


def main(argv: Optional[List[str]] = None) -> int:
    if sys.version_info < MIN_PYTHON:
        return _error(f"Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ is required (running {sys.version.split()[0]})")
    parser = argparse.ArgumentParser(
        prog="ext_exfil.py",
        description="Static, offline extension exfiltration-endpoint and CSP analyzer (PENT-17). "
                    "Reports statically referenced hosts (potential destinations, not observed traffic).")
    parser.add_argument("target", help="unpacked extension directory or its manifest.json")
    parser.add_argument("--format", choices=("text", "md", "json"), default="text", help="report format (default: text)")
    parser.add_argument("-o", "--output", help="write the report to this file instead of stdout (outside the analyzed tree)")
    parser.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES, help=f"source file cap (default {DEFAULT_MAX_FILES})")
    parser.add_argument("--include-vendored", action="store_true",
                        help=f"also walk {', '.join(sorted(VENDORED_DIRS))} (referenced files there are always scanned)")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return 0 if exc.code == 0 else 2
    if args.max_files < 1:
        return _error("--max-files must be >= 1")
    try:
        target = Path(args.target)
        roots = {locate_manifest(target).parent.resolve()} | ({target.resolve()} if target.is_dir() else set())
        if args.output and any(Path(args.output).resolve().is_relative_to(r) for r in roots):
            return _error("refusing to write the report inside the analyzed extension tree")
        report = analyze(args.target, max_files=args.max_files, include_vendored=args.include_vendored)
        text = render(report, args.format)
    except InputError as exc:
        return _error(str(exc))
    except Exception as exc:  # malformed input the checks above did not anticipate: never exit 1 ("findings")
        return _error(f"cannot analyze this input ({type(exc).__name__}: {exc})")
    try:
        if args.output:
            # backslashreplace: a lone surrogate from the manifest cannot abort the write half-way.
            with open(args.output, "w", encoding="utf-8", errors="backslashreplace") as fh:
                fh.write(text)
        else:
            _emit(sys.stdout, text)
    except (OSError, ValueError, AttributeError) as exc:  # BrokenPipeError, a closed or missing stdout
        return _error(f"cannot write the report to {args.output or 'stdout'}: {exc}")
    return 1 if has_failing_findings(report) else 0


if __name__ == "__main__":
    sys.exit(main())
