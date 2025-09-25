# pip install ttkbootstrap requests pillow

import os
import io
import ttkbootstrap as ttk
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog, BOTH
from ttkbootstrap.constants import *
import re
import base64
import time
import ipaddress
from urllib.parse import urlparse
from queue import Queue, Empty
import threading
import requests
from requests.adapters import HTTPAdapter
import traceback
from concurrent.futures import ThreadPoolExecutor
from PIL import Image, ImageTk

try:
    from urllib3.util.retry import Retry
except Exception:
    Retry = None  # Fallback handled in build_session()


# =============================
# Networking: session with retries/timeouts
# =============================
def build_session():
    s = requests.Session()
    s.headers.update({"User-Agent": "IOC-Scanner/2.8"})
    if Retry:
        retry = Retry(
            total=5,
            backoff_factor=0.6,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset(["GET", "POST"])
        )
        s.mount("https://", HTTPAdapter(max_retries=retry))
        s.mount("http://", HTTPAdapter(max_retries=retry))
    return s

session = build_session()


# =============================
# Tkinter + ttkbootstrap setup
# =============================
style = ttk.Style("journal")
root = style.master
root.title("Threat Desk — IOC Scanner")
root.geometry("1280x860")
root.minsize(1120, 760)


# =============================
# API Key Dialog (single modal) — includes urlscan.io
# =============================
class APIKeyDialog(tk.Toplevel):
    def __init__(self, master, vt_val, abuse_val, vpn_val, urlscan_val):
        super().__init__(master)
        self.title("Enter API Keys")
        self.resizable(False, False)
        self.result = None
        self.transient(master)
        self.grab_set()

        # macOS: bring to front
        self.lift()
        self.attributes('-topmost', True)
        self.after(200, lambda: self.attributes('-topmost', False))
        self.focus_force()

        # Center the dialog
        self.update_idletasks()
        w, h = 600, 260
        try:
            sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
            x = max(0, (sw - w) // 2)
            y = max(0, (sh - h) // 3)
            self.geometry(f"{w}x{h}+{x}+{y}")
        except Exception:
            pass

        frm = ttk.Frame(self, padding=18)
        frm.pack(fill=tk.BOTH, expand=True)

        row = 0
        ttk.Label(frm, text="API keys are required to scan indicators.", font=("Segoe UI", 12, "bold")).grid(row=row, column=0, columnspan=3, sticky="w")
        row += 1

        def add_row(label, prefill):
            nonlocal row
            ttk.Label(frm, text=label).grid(row=row, column=0, sticky="e", pady=(12 if row == 1 else 4, 4), padx=(0, 8))
            entry = ttk.Entry(frm, width=56, show="•")
            entry.grid(row=row, column=1, sticky="we", pady=(12 if row == 1 else 4, 4))
            entry.insert(0, prefill or "")
            show = ttk.Checkbutton(frm, text="Show", command=lambda e=entry: e.configure(show="" if e.cget("show") else "•"))
            show.grid(row=row, column=2, sticky="w")
            row += 1
            return entry

        self.vt_entry = add_row("VirusTotal", vt_val)
        self.abuse_entry = add_row("AbuseIPDB", abuse_val)
        self.vpn_entry = add_row("VPNAPI.io", vpn_val)
        self.urlscan_entry = add_row("urlscan.io", urlscan_val)

        btn_row = ttk.Frame(frm)
        btn_row.grid(row=row, column=0, columnspan=3, pady=(16, 0))
        ttk.Button(btn_row, text="OK", width=12, command=self._on_ok).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(btn_row, text="Cancel", width=12, command=self._on_cancel).pack(side=tk.LEFT)

        frm.columnconfigure(1, weight=1)
        self.bind("<Return>", lambda e: self._on_ok())
        self.bind("<Escape>", lambda e: self._on_cancel())
        self.vt_entry.focus_set()

    def _on_ok(self):
        vt = self.vt_entry.get().strip()
        abuse = self.abuse_entry.get().strip()
        vpn = self.vpn_entry.get().strip()
        urlscan = self.urlscan_entry.get().strip()
        self.result = (vt, abuse, vpn, urlscan)
        self.destroy()

    def _on_cancel(self):
        self.result = None
        self.destroy()

# Keys: single popup (prefill from env if present)
env_vt = os.getenv("VIRUSTOTAL_API_KEY", "")
env_abuse = os.getenv("ABUSEIPDB_API_KEY", "")
env_vpn = os.getenv("VPNAPI_IO_KEY", "")
env_urlscan = os.getenv("URLSCAN_API_KEY", "")

dlg = APIKeyDialog(root, env_vt, env_abuse, env_vpn, env_urlscan)
root.wait_window(dlg)

# Limited mode: proceed even if some or all keys are missing
if not dlg.result:
    vt_api_key, abuse_api_key, vpnapi_key, urlscan_api_key = ("", "", "", "")
else:
    vt_api_key, abuse_api_key, vpnapi_key, urlscan_api_key = dlg.result

missing = [name for name, val in [
    ("VirusTotal", vt_api_key),
    ("AbuseIPDB", abuse_api_key),
    ("VPNAPI.io", vpnapi_key),
    ("urlscan.io", urlscan_api_key),
] if not val]
if missing:
    messagebox.showwarning(
        "Limited mode",
        "Missing API keys: " + ", ".join(missing) +
        "\n\nParsing works normally. Lookups for missing services will be skipped."
    )

# =============================
# Theme colors
# =============================
THEME = {
    "body": "#e0e0e0",
    "muted": "#9aa0a6",
    "info": "#0dcaf0",
    "danger": "#dc3545",
    "success": "#198754",
    "warning": "#ffc107",
    "primary": "#0d6efd",
    "separator": "—",
}


# =============================
# Layout: AppBar + Content (no sidebar)
# =============================
# AppBar
appbar = ttk.Frame(root, padding=(16, 12))
appbar.pack(fill=X)
ttk.Label(appbar, text="Threat Desk", font=("Segoe UI", 20, "bold"), foreground="#ffffff").pack(side=tk.LEFT)
ttk.Label(appbar, text=" IOC Scanner • VT • AbuseIPDB • VPNAPI.io • urlscan.io", bootstyle=SECONDARY, foreground="#b0bec5").pack(side=tk.LEFT, padx=(8, 0))

# Main area (content only, no sidebar)
content = ttk.Frame(root, padding=12)
content.pack(fill=BOTH, expand=True)

# Tabs in content area
tabs = ttk.Notebook(content, bootstyle="primary")
tabs.pack(fill=BOTH, expand=True)

scan_tab = ttk.Frame(tabs, padding=10)
settings_tab = ttk.Frame(tabs, padding=10)
tabs.add(scan_tab, text=" Scan ")
tabs.add(settings_tab, text=" Settings ")


# =============================
# Scan tab UI
# =============================
# Input Card
input_card = ttk.Labelframe(scan_tab, text="Indicators", padding=12, bootstyle="dark")
input_card.pack(fill=X, expand=False)

ttk.Label(
    input_card,
    text="Paste RAW LOGS or plain IPv4 / IPv6 / URLs / File Hashes — any order. (Comma/space ok.)",
    font=("Segoe UI", 11, "bold")
).grid(row=0, column=0, sticky="w", columnspan=6)

ioc_text = tk.Text(input_card, height=6, font=("Segoe UI", 10), foreground="#e0e0e0", background="#121212", insertbackground="#ffffff")
ioc_text.grid(row=1, column=0, sticky="ew", pady=(4, 10), columnspan=6)
input_card.columnconfigure(0, weight=1)

btn_row = ttk.Frame(input_card)
btn_row.grid(row=2, column=0, sticky="w", columnspan=6)

scan_btn = ttk.Button(btn_row, text="Run Scan", bootstyle="primary", width=16)
scan_btn.pack(side=tk.LEFT, padx=(0, 8))
test_btn = ttk.Button(btn_row, text="Quick Demo", bootstyle="secondary", width=12)
test_btn.pack(side=tk.LEFT)
clear_btn = ttk.Button(btn_row, text="Clear", bootstyle="secondary", width=10)
clear_btn.pack(side=tk.LEFT, padx=(8, 0))
copy_all_btn = ttk.Button(btn_row, text="Copy Results", bootstyle="info", width=14)
copy_all_btn.pack(side=tk.LEFT, padx=(8, 0))
upload_file_btn = ttk.Button(btn_row, text="Upload File to VT", bootstyle="warning", width=18)
upload_file_btn.pack(side=tk.LEFT, padx=(8, 0))
screenshot_btn = ttk.Button(btn_row, text="Sandbox Browser Screenshot", bootstyle="secondary", width=26)
screenshot_btn.pack(side=tk.LEFT, padx=(8, 0))

progress = ttk.Progressbar(input_card, mode="indeterminate", bootstyle="striped-info")
progress.grid(row=3, column=0, sticky="ew", pady=(10, 0), columnspan=6)

# Summary Card
summary_card = ttk.Labelframe(scan_tab, text="Summary", padding=12, bootstyle="dark")
summary_card.pack(fill=BOTH, expand=True, pady=(10, 0))

columns = ("type", "indicator", "vt_malicious", "abuse_score", "vpn", "proxy", "tor", "relay")
summary = ttk.Treeview(summary_card, columns=columns, show="headings", height=8, bootstyle="info")
for col, hdr, width, anchor in [
    ("type", "Type", 120, "w"),
    ("indicator", "Indicator", 420, "w"),
    ("vt_malicious", "VT Malicious", 110, "center"),
    ("abuse_score", "Abuse Score", 110, "center"),
    ("vpn", "VPN", 70, "center"),
    ("proxy", "Proxy", 70, "center"),
    ("tor", "Tor", 70, "center"),
    ("relay", "Relay", 70, "center"),
]:
    summary.heading(col, text=hdr)
    summary.column(col, width=width, anchor=anchor)
summary.tag_configure('even', background='#1f2430', foreground='#ffffff')
summary.tag_configure('odd', background='#1a1f2a', foreground='#ffffff')
try:
    ttk.Style().configure('Treeview', rowheight=24)
except Exception:
    pass
summary.pack(fill=BOTH, expand=False)

# Details Card (log only)
details_card = ttk.Labelframe(scan_tab, text="Details", padding=12, bootstyle="dark")
details_card.pack(fill=BOTH, expand=True)
output_box = scrolledtext.ScrolledText(details_card, height=14, font=("Consolas", 10), foreground="#e0e0e0", background="#121212", insertbackground="#ffffff")
output_box.pack(fill=BOTH, expand=True)

# Status + toast
status_bar = ttk.Frame(scan_tab)
status_bar.pack(fill=X, pady=(8, 0))
status_var = tk.StringVar(value="Idle")
ttk.Label(status_bar, textvariable=status_var, anchor="w", bootstyle=SECONDARY).pack(side=tk.LEFT)
badge = ttk.Label(status_bar, text="READY", bootstyle="success-inverse")
badge.pack(side=tk.RIGHT)

def show_toast(message, title="Scan Complete", duration=3500):
    try:
        tw = tk.Toplevel(root)
        tw.overrideredirect(True)
        tw.attributes('-topmost', True)
        frm = ttk.Frame(tw, padding=(12, 8), bootstyle="dark")
        frm.pack(fill=tk.BOTH, expand=True)
        ttk.Label(frm, text=title, font=("Segoe UI", 10, "bold")).pack(anchor="w")
        ttk.Label(frm, text=message, bootstyle=SECONDARY).pack(anchor="w")
        tw.update_idletasks()
        sw, sh = tw.winfo_screenwidth(), tw.winfo_screenheight()
        ww, wh = tw.winfo_reqwidth(), tw.winfo_reqheight()
        x = sw - ww - 24
        y = sh - wh - 60
        tw.geometry(f"{ww}x{wh}+{x}+{y}")
        tw.after(200, lambda: tw.attributes('-topmost', False))
        tw.after(duration, tw.destroy)
    except Exception:
        set_status(message, "DONE", "success-inverse")


# =============================
# Settings tab
# =============================
appearance_card = ttk.Labelframe(settings_tab, text="Appearance", padding=12, bootstyle="dark")
appearance_card.pack(fill=X, expand=False, pady=(0, 10))

ttk.Label(appearance_card, text="Font Scale", bootstyle=SECONDARY).grid(row=0, column=0, sticky="w", padx=(0, 8))
font_scale = ttk.Scale(appearance_card, from_=0.9, to=1.3, value=1.0, length=220, bootstyle="info")
font_scale.grid(row=0, column=1, sticky="w")

def apply_fontscale(val=None):
    # Scale the main input & output fonts live
    try:
        scale = float(font_scale.get())
        # These names exist below; they will be resolved at call-time.
        ioc_text.configure(font=("Segoe UI", int(10 * scale)))
        output_box.configure(font=("Consolas", int(10 * scale)))
    except Exception:
        pass

font_scale.configure(command=apply_fontscale)


set_card = ttk.Labelframe(settings_tab, text="About", padding=12, bootstyle="dark")
set_card.pack(fill=BOTH, expand=True)

# Scrollable About content
about_text = scrolledtext.ScrolledText(
    set_card,
    height=18,
    wrap="word",
    font=("Segoe UI", 12),
    foreground="#000000",
    background="#ffffff",
    insertbackground="#000000"
)
about_text.pack(fill=BOTH, expand=True)

about_body = (
    "\n\n"
    "What this tool does\n"
    "Threat Desk — IOC Scanner helps you triage Indicators of Compromise quickly and locally. "
    "Paste RAW SIEM logs or clean IOCs (IPv4/IPv6, URLs, file hashes: MD5/SHA-1/SHA-256) and hit Run Scan. "
    "The parser auto-extracts indicators, safely refangs hxxp/[.] patterns, and de-duplicates results.\n\n"
    "How to use\n"
    "\t1.\tPaste: Drop raw logs or a plain list of IOCs into the input box. Commas, spaces, and newlines are fine.\n"
    "\t2.\tRefang: Obfuscated indicators like hxxp[:]//example[.]com are automatically normalized.\n"
    "\t3.\tRun: Click Run Scan to extract IOCs and (optionally) enrich via VT/AbuseIPDB/VPNAPI.io/urlscan.io based on your toggles.\n"
    "\t4.\tReview: See the Summary table for IOC types and counts; expand Details for per-IOC evidence and links.\n"
    "\t5.\tExport: Use Copy Results to copy normalized IOCs or open enrichment links for deeper analysis.\n\n"
    "Security & Privacy\n"
    "\t•\tLocal-first design: All parsing, refanging, and IOC extraction occur fully within the local application before any network communication is initiated.\n"
    "\t•\tNo silent data transmission: The tool performs no hidden or automatic web lookups—all analysis is explicitly user-triggered.\n"
    "\t•\tStrict user control: External enrichment (VirusTotal, AbuseIPDB, VPNAPI.io, urlscan.io) is invoked only when you click and only with API keys you provide.\n"
    "\t•\tNo bulk log exposure: Entire SIEM logs remain confined to your system. If you choose to query an indicator, only that single IOC is transmitted to the respective API.\n"
    "\t•\tZero data retention: The tool stores nothing locally or remotely between sessions unless you intentionally export results.\n"
    "\t•\tTrusted security APIs: Integrates solely with well-known, reputable threat intelligence providers; no analytics, tracking scripts, or third-party advertising endpoints are present.\n"
    "\t•\tIPv6-safe by design: Implements rigorous normalization, validation, and private-range detection for both IPv4 and IPv6 to prevent accidental exposure of internal network addresses.\n\n"
    "Licensing & API Use\n"
    "\t•\tDefault lookups use public/free API access for personal or test environments.\n"
    "\t•\tCommercial or high-volume usage requires proper licensed API keys from the respective vendors (e.g., VirusTotal, AbuseIPDB).\n"
    "\t•\tThe tool itself does not supply API keys or subscriptions—it only uses those securely provided by the user.\n\n"
    "Technology\n"
    "\t•\tDeveloped in Python and designed for secure, local execution.\n\n"
    "Credits & Contact\n"
    "\t•\tDeveloped by: Srinidhi Kowshik\n"
    "\t•\tSuggestions / feedback: srinidhikowshik@gmail.com\n"
)

about_text.insert(tk.END, about_body)
about_text.configure(state=tk.DISABLED)


# =============================
# Text tags & UI queue
# =============================
output_box.tag_config("bold", font=("Segoe UI", 10, "bold"))
output_box.tag_config("danger", foreground=THEME["danger"])
output_box.tag_config("ok", foreground=THEME["success"])

ui_queue = Queue()
def post_to_ui(func, *args, **kwargs):
    ui_queue.put((func, args, kwargs))

def ui_pump():
    try:
        while True:
            try:
                func, args, kwargs = ui_queue.get_nowait()
            except Empty:
                break
            try:
                func(*args, **kwargs)
            except Exception as e:
                try:
                    output_box.insert(tk.END, f"\n[UI error] {e}\n", "danger")
                    output_box.see(tk.END)
                except Exception:
                    pass
    finally:
        root.after(50, ui_pump)
root.after(50, ui_pump)


# =============================
# UI helpers
# =============================
def insert_text(txt: str, tag: str = None, newline=True):
    def _do():
        output_box.insert(tk.END, txt + ("\n" if newline else ""), tag)
        output_box.see(tk.END)
    post_to_ui(_do)

def insert_colored_line(txt: str, color="body", underline=False):
    color_map = {
        "body": THEME["body"],
        "muted": THEME["muted"],
        "info": THEME["info"],
        "danger": THEME["danger"],
        "success": THEME["success"],
        "warning": THEME["warning"],
        "primary": THEME["primary"],
    }
    fg = color_map.get(color, color)
    tag = f"c_{hash((fg, underline))}"
    def _do():
        if tag not in output_box.tag_names():
            output_box.tag_config(tag, foreground=fg, underline=underline)
        output_box.insert(tk.END, txt + "\n", tag)
        output_box.see(tk.END)
    post_to_ui(_do)

def set_status(msg: str, badge_text="READY", badge_style="success-inverse"):
    def _do():
        status_var.set(msg)
        badge.configure(text=badge_text, bootstyle=badge_style)
    post_to_ui(_do)

def set_running(running: bool):
    def _do():
        scan_btn.configure(state=DISABLED if running else NORMAL)
        test_btn.configure(state=DISABLED if running else NORMAL)
        clear_btn.configure(state=DISABLED if running else NORMAL)
        copy_all_btn.configure(state=DISABLED if running else NORMAL)
        try:
            upload_file_btn.configure(state=DISABLED if running else NORMAL)
            screenshot_btn.configure(state=DISABLED if running else NORMAL)
        except Exception:
            pass
        if running:
            progress.start(12)
        else:
            progress.stop()
    post_to_ui(_do)

_anim = {"on": False, "tick": 0}
def start_anim(msg="Scanning"):
    _anim["on"] = True
    _anim["tick"] = 0
    def loop():
        if not _anim["on"]:
            return
        dots = "." * ((_anim["tick"] % 3) + 1)
        set_status(f"{msg}{dots}", "WORKING", "info-inverse")
        _anim["tick"] += 1
        root.after(450, loop)
    loop()

def stop_anim():
    _anim["on"] = False


# =============================
# Double-click: select whole URL in the log for copying
# =============================
def select_full_url(event):
    w = event.widget
    idx = w.index("@%s,%s" % (event.x, event.y))
    line = idx.split(".")[0]
    line_start, line_end = f"{line}.0", f"{line}.end"
    pos = line_start
    pattern = r"https?://\S+"
    while True:
        start = w.search(pattern, pos, stopindex=line_end, regexp=True)
        if not start:
            break
        end = w.search(r"\s", start, stopindex=line_end, regexp=True)
        if not end:
            end = line_end
        if w.compare(idx, ">=", start) and w.compare(idx, "<=", end):
            w.tag_remove("sel", "1.0", "end")
            w.tag_add("sel", start, end)
            return "break"
        pos = end
    return None

output_box.bind("<Double-Button-1>", select_full_url)


# =============================
# IOC extraction from RAW logs
# =============================
MD5_RE    = re.compile(r"\b[A-Fa-f0-9]{32}\b")
SHA1_RE   = re.compile(r"\b[A-Fa-f0-9]{40}\b")
SHA256_RE = re.compile(r"\b[A-Fa-f0-9]{64}\b")
SHA512_RE = re.compile(r"\b[A-Fa-f0-9]{128}\b")  # NEW

URL_RE_SCHEME = re.compile(r"\bhttps?://[^\s<>\]\)\"']+", re.I)
URL_RE_WWW    = re.compile(r"\bwww\.[^\s<>\]\)\"']+", re.I)
# Bare domain/path (fallback)
URL_RE_BARE   = re.compile(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+(?:[A-Za-z]{2,})(?::\d{1,5})?(?:/[^\s<>\)\]]*)?")

IPV4_CAND = re.compile(r"(?<![\d])(?:\d{1,3}\.){3}\d{1,3}(?![\d])")
IPV6_BRKT = re.compile(r"\[[0-9A-Fa-f:%\.]+\]")
IPV6_CAND = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?:%\w+)?(?![:0-9A-Fa-f])")

FC00_7   = ipaddress.ip_network("fc00::/7")
DB8_32   = ipaddress.ip_network("2001:db8::/32")
FE80_10  = ipaddress.ip_network("fe80::/10")

def refang(text: str) -> str:
    t = text
    # Schemes
    t = re.sub(r"\bhxxps\b", "https", t, flags=re.I)
    t = re.sub(r"\bhxxp\b", "http", t, flags=re.I)
    # :// variants like hxxps[:]//
    t = re.sub(r"\[\s*:\s*\]//", "://", t)
    # IPv6 [:] everywhere -> :
    t = re.sub(r"\[\s*:\s*\]", ":", t)
    t = re.sub(r"\(\s*:\s*\)", ":", t)
    t = re.sub(r"\(\s*::\s*\)", "::", t)
    # Defanged dots
    t = re.sub(r"\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|(?:\(|\[|\{)\s*dot\s*(?:\)|\]|\})", ".", t, flags=re.I)
    # Remove harmless wrappers around tokens
    t = t.replace("<", " ").replace(">", " ")
    return t

def add_unique(seq, seen, item):
    key = item.strip()
    if not key:
        return
    if key.lower() not in seen:
        seen.add(key.lower())
        seq.append(key)

def extract_iocs(raw_text: str):
    text = refang(raw_text)
    found = []
    seen = set()

    # URLs
    for m in URL_RE_SCHEME.finditer(text):
        add_unique(found, seen, m.group(0).rstrip(".,);]>\"'"))
    for m in URL_RE_WWW.finditer(text):
        add_unique(found, seen, m.group(0).rstrip(".,);]>\"'"))
    for m in URL_RE_BARE.finditer(text):
        add_unique(found, seen, m.group(0).rstrip(".,);]>\"'"))

    # IPv6 first (to keep bracketed hosts)
    for m in IPV6_BRKT.finditer(text):
        add_unique(found, seen, m.group(0))
    for m in IPV6_CAND.finditer(text):
        add_unique(found, seen, m.group(0))

    # IPv4
    for m in IPV4_CAND.finditer(text):
        add_unique(found, seen, m.group(0))

    # Hashes
    for m in MD5_RE.finditer(text): add_unique(found, seen, m.group(0))
    for m in SHA1_RE.finditer(text): add_unique(found, seen, m.group(0))
    for m in SHA256_RE.finditer(text): add_unique(found, seen, m.group(0))
    for m in SHA512_RE.finditer(text): add_unique(found, seen, m.group(0))  # NEW

    return found


# =============================
# Classifiers
# =============================
HASH32  = re.compile(r"^[A-Fa-f0-9]{32}$")
HASH40  = re.compile(r"^[A-Fa-f0-9]{40}$")
HASH64  = re.compile(r"^[A-Fa-f0-9]{64}$")
HASH128 = re.compile(r"^[A-Fa-f0-9]{128}$")  # NEW

def is_hash(token: str) -> bool:
    t = token.strip()
    if ":" in t or "." in t or "/" in t:
        return False
    return bool(HASH32.fullmatch(t) or HASH40.fullmatch(t) or HASH64.fullmatch(t) or HASH128.fullmatch(t))  # NEW

def normalize_url(s: str) -> str:
    s = s.strip()
    if not s.startswith(("http://", "https://")):
        s = "http://" + s
    return s

def is_ip(token: str) -> bool:
    s = token.strip().strip("[]")
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False

def is_nonroutable_ip(s: str) -> bool:
    ip = ipaddress.ip_address(s)
    if ip.version == 4:
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved
    else:
        return (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or
                ip in FC00_7 or ip in DB8_32 or ip in FE80_10)

def is_url(token: str) -> bool:
    s = token.strip()
    if is_ip(s):
        return False
    u = urlparse(normalize_url(s))
    return bool(u.scheme in ("http", "https") and u.netloc and "." in u.netloc) or s.lower().startswith("www.")

def classify_token(token: str):
    raw = token.strip().strip(",")
    if not raw:
        return ("unknown", raw)
    unbracketed = raw.strip("[]")
    if is_ip(unbracketed):
        try:
            return ("PRIVATE IP", unbracketed) if is_nonroutable_ip(unbracketed) else ("ip", unbracketed)
        except Exception:
            return ("ip", unbracketed)
    if is_url(raw):
        return ("url", raw)
    if is_hash(raw):
        return ("hash", raw.lower())
    return ("unknown", raw)

def vt_url_id(url_str: str) -> str:
    return base64.urlsafe_b64encode(url_str.encode()).decode().rstrip("=")


# =============================
# API wrappers
# =============================
def vt_get_ip(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": vt_api_key}
    return session.get(url, headers=headers, timeout=12)

def abuse_check_ip(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": abuse_api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    return session.get(url, headers=headers, params=params, timeout=12)

def vpnapi_check_ip(ip):
    url = f"https://vpnapi.io/api/{ip}"
    params = {"key": vpnapi_key}
    return session.get(url, params=params, timeout=12)

def vt_submit_url_for_analysis(url_str):
    submit = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": vt_api_key, "Content-Type": "application/x-www-form-urlencoded"}
    r = session.post(submit, headers=headers, data=f"url={url_str}", timeout=12)
    if r.status_code == 200:
        analysis_id = r.json().get("data", {}).get("id")
        if analysis_id:
            return vt_wait_analysis(analysis_id)
    return None, r

def vt_wait_analysis(analysis_id, timeout_sec=20):
    headers = {"x-apikey": vt_api_key}
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    deadline = time.time() + timeout_sec
    last_resp = None
    while time.time() < deadline:
        last_resp = session.get(url, headers=headers, timeout=12)
        if last_resp.status_code == 200:
            j = last_resp.json()
            st = j.get("data", {}).get("attributes", {}).get("status")
            if st == "completed":
                return j, last_resp
        time.sleep(1.2)
    return None, last_resp

def vt_get_file(hash_value):
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {"x-apikey": vt_api_key}
    return session.get(url, headers=headers, timeout=12)

# urlscan.io API
def urlscan_submit(url_str):
    headers = {"API-Key": urlscan_api_key, "Content-Type": "application/json"}
    data = {"url": url_str, "visibility": "public"}
    return session.post("https://urlscan.io/api/v1/scan/", json=data, headers=headers, timeout=15)

def urlscan_result(uuid):
    return session.get(f"https://urlscan.io/api/v1/result/{uuid}/", timeout=15)


# =============================
# Core processing
# =============================
def process_inputs(tokens):
    set_running(True)
    progress.start(12)
    start_anim("Scanning")
    start_ts = time.time()
    summary_rows = []
    pool = ThreadPoolExecutor(max_workers=5)

    try:
        for raw in tokens:
            kind, val = classify_token(raw)
            if not val:
                continue

            insert_text(f"▶ {kind.upper()}: {val}", "bold")
            insert_text(THEME["separator"] * 60)

            vt_mal = "-"
            abuse_score = "-"
            vpn_vals = {"vpn": "-", "proxy": "-", "tor": "-", "relay": "-"}

            try:
                if kind == "ip":
                    # Parallel queries
                    vt_future = pool.submit(vt_get_ip, val) if vt_api_key else None
                    abuse_future = pool.submit(abuse_check_ip, val) if abuse_api_key else None
                    vpn_future = pool.submit(vpnapi_check_ip, val) if vpnapi_key else None

                    # VirusTotal IP
                    if vt_future is None:
                        insert_colored_line("VirusTotal: key not set — lookup skipped.", "muted")
                    else:
                        try:
                            vt_resp = vt_future.result()
                            if vt_resp.status_code == 200:
                                data = vt_resp.json()
                                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                                vt_mal = int(stats.get("malicious", 0))
                                color = "danger" if vt_mal > 0 else "success"
                                insert_colored_line(f"VirusTotal: {vt_mal} malicious reports", color)
                                insert_colored_line(f"https://www.virustotal.com/gui/ip-address/{val}", "info",
                                                    underline=True)
                            else:
                                insert_colored_line(f"VirusTotal Error: {vt_resp.status_code} {vt_resp.text[:200]}",
                                                    "danger")
                        except requests.exceptions.RequestException as e:
                            insert_colored_line(f"VirusTotal Request Error: {e}", "danger")

                    # AbuseIPDB
                    if abuse_future is None:
                        insert_colored_line("AbuseIPDB: key not set — lookup skipped.", "muted")
                    else:
                        try:
                            abuse_resp = abuse_future.result()
                            if abuse_resp.status_code == 200:
                                d = abuse_resp.json().get("data", {})
                                abuse_score = int(d.get("abuseConfidenceScore", 0))
                                color = "danger" if abuse_score > 0 else "success"
                                insert_colored_line(f"AbuseIPDB: {abuse_score}% confidence", color)
                                insert_colored_line(f"Domain: {d.get('domain', 'N/A')}", "muted")
                                insert_colored_line(f"https://www.abuseipdb.com/check/{val}", "info", underline=True)
                            else:
                                insert_colored_line(
                                    f"AbuseIPDB Error: {abuse_resp.status_code} {abuse_resp.text[:200]}", "danger")
                        except requests.exceptions.RequestException as e:
                            insert_colored_line(f"AbuseIPDB Request Error: {e}", "danger")
                    # VPNAPI.io (IPv6-safe)
                    if vpn_future is None:
                        insert_colored_line("VPNAPI.io: key not set — lookup skipped.", "muted")
                    else:
                        try:
                            vpn_resp = vpn_future.result()
                            if vpn_resp.status_code == 200:
                                d = vpn_resp.json() or {}
                                if not isinstance(d, dict):
                                    d = {}
                                location = (d.get("location") or {}).get("country", "Unknown")
                                sec = d.get("security") or {}
                                insert_colored_line(f"Location: {location}", "muted")
                                for flag in ("vpn", "proxy", "tor", "relay"):
                                    flag_val = bool(sec.get(flag, False))
                                    vpn_vals[flag] = str(flag_val)
                                    insert_colored_line(f"{flag.upper()}: {flag_val}",
                                                        "danger" if flag_val else "success")
                            else:
                                insert_colored_line(f"VPNAPI.io Error: {vpn_resp.status_code} {vpn_resp.text[:200]}",
                                                    "danger")
                        except requests.exceptions.RequestException as e:
                            insert_colored_line(f"VPNAPI.io Request Error: {e}", "danger")

                elif kind == "PRIVATE IP":
                    insert_colored_line("Private / non-routable IP — external lookups skipped.", "muted")

                elif kind == "url":
                    norm = val if val.startswith(("http://", "https://")) else "http://" + val
                    if not vt_api_key:
                        insert_colored_line("VirusTotal (URL): key not set — lookup skipped.", "muted")
                    else:
                        try:
                            url_id = vt_url_id(norm)
                            info = session.get(
                                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                                headers={"x-apikey": vt_api_key},
                                timeout=12
                            )
                            if info.status_code == 200:
                                j = info.json()
                                stats = j.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                                vt_mal = int(stats.get("malicious", 0))
                                color = "danger" if vt_mal > 0 else "success"
                                insert_colored_line(f"VirusTotal: {vt_mal} malicious reports", color)
                                insert_colored_line(f"https://www.virustotal.com/gui/url/{url_id}", "info", underline=True)
                            else:
                                analysis_json, submit_resp = vt_submit_url_for_analysis(norm)
                                if analysis_json:
                                    stats = analysis_json.get("data", {}).get("attributes", {}).get("stats", {})
                                    vt_mal = int(stats.get("malicious", 0))
                                    color = "danger" if vt_mal > 0 else "success"
                                    insert_colored_line(f"VirusTotal: {vt_mal} malicious reports", color)
                                    insert_colored_line(f"https://www.virustotal.com/gui/url/{url_id}", "info", underline=True)
                                else:
                                    insert_colored_line("VirusTotal: queued (analysis not completed yet)", "warning")
                                    insert_colored_line(f"https://www.virustotal.com/gui/url/{url_id}", "info", underline=True)
                        except requests.exceptions.RequestException as e:
                            insert_colored_line(f"VirusTotal URL Request Error: {e}", "danger")

                elif kind == "hash":
                    # Skip VT lookup for SHA-512 to avoid 404s, or when VT key is missing
                    if HASH128.fullmatch(val):
                        insert_colored_line("SHA-512 detected — VirusTotal file lookup skipped.", "muted")
                    elif not vt_api_key:
                        insert_colored_line("VirusTotal (file): key not set — lookup skipped.", "muted")
                    else:
                        try:
                            vt_resp = vt_get_file(val)
                            if vt_resp.status_code == 200:
                                data = vt_resp.json()
                                attrs = data.get("data", {}).get("attributes", {}) if data else {}
                                stats = attrs.get("last_analysis_stats", {})
                                vt_mal = int(stats.get("malicious", 0))
                                names = attrs.get("names", []) or []
                                color = "danger" if vt_mal > 0 else "success"
                                insert_colored_line(f"VirusTotal: {vt_mal} malicious reports", color)
                                if names:
                                    preview = ", ".join(names[:20]) + (" ..." if len(names) > 20 else "")
                                    insert_colored_line("File Names: " + preview, "muted")
                                insert_colored_line(f"https://www.virustotal.com/gui/file/{val}", "info", underline=True)
                            else:
                                insert_colored_line(f"VirusTotal Error: {vt_resp.status_code} {vt_resp.text[:200]}", "danger")
                        except requests.exceptions.RequestException as e:
                            insert_colored_line(f"VirusTotal Request Error: {e}", "danger")

                else:
                    insert_colored_line("Unrecognized input.", "danger")

            finally:
                insert_text("")  # spacing

            # Add to summary table
            row_values = (
                kind.upper(),
                val,
                str(vt_mal),
                str(abuse_score),
                vpn_vals["vpn"],
                vpn_vals["proxy"],
                vpn_vals["tor"],
                vpn_vals["relay"],
            )
            summary_rows.append(row_values)
            idx = len(summary_rows)

            def _add_row(row, tag):
                summary.insert("", "end", values=row, tags=(tag,))
            post_to_ui(_add_row, row_values, 'even' if idx % 2 == 0 else 'odd')

    except Exception:
        insert_colored_line("Unexpected error (traceback below):", "danger")
        insert_text(traceback.format_exc())
    finally:
        elapsed = time.time() - start_ts
        stop_anim()
        set_status(f"Done in {elapsed:.1f}s", "DONE", "success-inverse")
        set_running(False)
        show_toast(f"{len(summary_rows)} item(s) processed in {elapsed:.1f}s")


# =============================
# File upload to VirusTotal
# =============================
def upload_file_to_vt():
    if not vt_api_key:
        messagebox.showerror("Missing key", "VirusTotal API key is required for file uploads.")
        return
    path = filedialog.askopenfilename(title="Choose file to upload to VirusTotal")
    if not path:
        return
    def work():
        set_running(True)
        start_anim("Uploading")
        insert_text(f"▶ FILE UPLOAD: {path}", "bold")
        insert_text(THEME["separator"] * 60)
        try:
            with open(path, "rb") as f:
                files = {"file": (os.path.basename(path), f)}
                headers = {"x-apikey": vt_api_key}
                r = session.post("https://www.virustotal.com/api/v3/files", headers=headers, files=files, timeout=120)
            if r.status_code in (200, 202):
                analysis_id = r.json().get("data", {}).get("id")
                insert_colored_line(f"Upload accepted: analysis id {analysis_id}", "muted")
                deadline = time.time() + 45
                sha256 = None
                while time.time() < deadline:
                    ar = session.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                                     headers={"x-apikey": vt_api_key}, timeout=15)
                    if ar.status_code == 200:
                        aj = ar.json()
                        st = aj.get("data", {}).get("attributes", {}).get("status")
                        meta = aj.get("meta", {}).get("file_info", {})
                        if meta:
                            sha256 = meta.get("sha256") or sha256
                        if st == "completed":
                            stats = aj.get("data", {}).get("attributes", {}).get("stats", {})
                            mal = int(stats.get("malicious", 0))
                            color = "danger" if mal > 0 else "success"
                            insert_colored_line(f"VirusTotal: {mal} malicious reports", color)
                            if sha256:
                                insert_colored_line(f"https://www.virustotal.com/gui/file/{sha256}", "info", underline=True)
                            break
                    time.sleep(1.2)
                else:
                    insert_colored_line("Analysis still queued (timeout). Check link below if available.", "warning")
                    if sha256:
                        insert_colored_line(f"https://www.virustotal.com/gui/file/{sha256}", "info", underline=True)
            else:
                insert_colored_line(f"Upload error: {r.status_code} {r.text[:200]}", "danger")
        except Exception as e:
            insert_colored_line(f"Upload exception: {e}", "danger")
            insert_text(traceback.format_exc())
        finally:
            stop_anim()
            set_running(False)
    threading.Thread(target=work, daemon=True).start()


# =============================
# Web Screenshot (urlscan.io) — opens in a NEW POPUP window
# =============================
def on_screenshot():
    sel = summary.selection()
    if not sel:
        messagebox.showwarning("No selection", "Select a URL or IP row in the Summary table first.")
        return
    vals = summary.item(sel[0], "values")
    if not vals:
        return
    itype, indicator = vals[0], vals[1]
    if itype not in ("URL", "IP"):
        messagebox.showwarning("Not a URL/IP", "Screenshot works for URL or IP rows only.")
        return
    if not urlscan_api_key:
        messagebox.showerror("Missing urlscan.io key", "Add your urlscan.io API key to use Web Screenshot.")
        return

    target = indicator
    if not target.startswith(("http://", "https://")):
        target = "http://" + target

    win = tk.Toplevel(root)
    win.title(f"Web Screenshot — {indicator}")
    win.geometry("1100x820")
    win.minsize(900, 700)
    win.lift(); win.attributes('-topmost', True); win.after(200, lambda: win.attributes('-topmost', False))

    outer = ttk.Frame(win, padding=12)
    outer.pack(fill=BOTH, expand=True)

    # Top bar
    topbar = ttk.Frame(outer)
    topbar.pack(fill=X, pady=(0, 6))
    ttk.Label(topbar, text=indicator, font=("Segoe UI", 12, "bold")).pack(side=tk.LEFT)
    resolved_var = tk.StringVar(value="Resolved IP: —")
    ttk.Label(topbar, textvariable=resolved_var, bootstyle=SECONDARY).pack(side=tk.LEFT, padx=(12, 0))
    report_lbl = ttk.Label(topbar, text="", bootstyle=INFO)
    report_lbl.pack(side=tk.RIGHT)

    # Headers table
    headers_box = ttk.Labelframe(outer, text="Response Headers", padding=8, bootstyle="dark")
    headers_box.pack(fill=X, pady=(0, 8))
    hdr_cols = ("header", "value")
    hdr_tree = ttk.Treeview(headers_box, columns=hdr_cols, show="headings", height=6, bootstyle="info")
    hdr_tree.heading("header", text="Header")
    hdr_tree.heading("value", text="Value")
    hdr_tree.column("header", width=220, anchor="w")
    hdr_tree.column("value", width=800, anchor="w")
    hdr_tree.pack(fill=X)

    # Screenshot area
    shot_box = ttk.Labelframe(outer, text="Screenshot", padding=8, bootstyle="dark")
    shot_box.pack(fill=BOTH, expand=True)
    shot_label = ttk.Label(shot_box)
    shot_label.pack(fill=BOTH, expand=True)
    shot_label._photo_ref = None
    shot_label._pil_ref = None

    # Actions
    actions = ttk.Frame(outer)
    actions.pack(fill=X, pady=(8, 0))
    status_lbl = ttk.Label(actions, text="Submitting to urlscan.io…", bootstyle=SECONDARY)
    status_lbl.pack(side=tk.LEFT)
    save_btn = ttk.Button(actions, text="Save Screenshot", bootstyle="success", state=DISABLED)
    save_btn.pack(side=tk.RIGHT)

    def do_save():
        img = shot_label._pil_ref
        if img is None:
            return
        safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", indicator)[:60] or "screenshot"
        ts = time.strftime("%Y%m%d_%H%M%S")
        default = f"{safe_name}_{ts}.png"
        path = filedialog.asksaveasfilename(
            title="Save Screenshot",
            defaultextension=".png",
            initialfile=default,
            filetypes=[("PNG Image", "*.png")]
        )
        if not path:
            return
        try:
            img.save(path, format="PNG")
            messagebox.showinfo("Saved", f"Screenshot saved to:\n{path}")
        except Exception as e:
            messagebox.showerror("Save failed", str(e))

    save_btn.configure(command=do_save)

    def urlscan_submit(url_str):
        headers = {"API-Key": urlscan_api_key, "Content-Type": "application/json"}
        data = {"url": url_str, "visibility": "public"}
        return session.post("https://urlscan.io/api/v1/scan/", json=data, headers=headers, timeout=15)

    def urlscan_result(uuid):
        return session.get(f"https://urlscan.io/api/v1/result/{uuid}/", timeout=15)

    def worker():
        try:
            # submit
            sub = urlscan_submit(target)
            if sub.status_code not in (200, 201):
                post_to_ui(status_lbl.configure, text=f"Submission error: {sub.status_code} {sub.text[:120]}")
                return

            js = {}
            try:
                js = sub.json() or {}
            except Exception:
                js = {}

            uuid = js.get("uuid")
            # expose report link as early as we can
            early_report = js.get("result") or js.get("api") or js.get("url")
            if early_report:
                post_to_ui(report_lbl.configure, text=early_report)

            if not uuid:
                post_to_ui(status_lbl.configure, text="No UUID returned by urlscan.io")
                return

            # poll up to 75s, show progress
            POLL_TOTAL = 75
            deadline = time.time() + POLL_TOTAL
            result = None
            last_status = None

            while time.time() < deadline:
                r = urlscan_result(uuid)
                # handle rate limiting
                if r.status_code == 429:
                    ra = 3
                    try:
                        ra = int(r.headers.get("Retry-After", "3"))
                    except Exception:
                        ra = 3
                    post_to_ui(status_lbl.configure, text=f"Rate limited… waiting {ra}s")
                    time.sleep(max(1, ra))
                    continue

                if r.status_code == 200:
                    j = {}
                    try:
                        j = r.json() or {}
                    except Exception:
                        j = {}
                    ready = bool(j.get("page") or j.get("lists") or (j.get("task", {}) or {}).get("screenshotURL"))
                    if ready:
                        result = j
                        break

                    now_left = int(deadline - time.time())
                    msg = f"Waiting for analysis… {now_left}s left"
                    if msg != last_status:
                        post_to_ui(status_lbl.configure, text=msg)
                        last_status = msg
                else:
                    post_to_ui(status_lbl.configure, text=f"Status {r.status_code} … retrying")

                time.sleep(1.2)

            if not result:
                # final attempt: screenshot might exist even if JSON not fully ready
                ss_fallback = f"https://urlscan.io/screenshots/{uuid}.png"
                ir = session.get(ss_fallback, timeout=20)
                if ir.status_code == 200:
                    img = Image.open(io.BytesIO(ir.content))
                    img.thumbnail((1600, 1000))
                    photo = ImageTk.PhotoImage(img)
                    def _set_img():
                        shot_label.configure(image=photo)
                        shot_label._photo_ref = photo
                        shot_label._pil_ref = img
                        status_lbl.configure(text="Screenshot loaded (fallback)")
                        save_btn.configure(state=NORMAL)
                    post_to_ui(_set_img)
                    return

                post_to_ui(status_lbl.configure, text="Result not ready (timed out)")
                return

            # Resolved IP
            resolved_ip = result.get("page", {}).get("ip")
            if not resolved_ip:
                ips = (result.get("lists", {}) or {}).get("ips") or []
                resolved_ip = ips[0] if ips else None
            if resolved_ip:
                post_to_ui(lambda v=f"Resolved IP: {resolved_ip}": resolved_var.set(v))

            # Report link (final)
            report = result.get("task", {}).get("reportURL") or early_report
            if report:
                post_to_ui(report_lbl.configure, text=report)

            # Headers extraction
            headers_map = {}
            try:
                reqs = (result.get("data", {}) or {}).get("requests") or []
                doc = None
                for q in reqs:
                    rt = (q.get("request", {}) or {}).get("request", {}).get("resourceType")
                    if rt == "Document" and q.get("response", {}):
                        doc = q
                        break
                if not doc and reqs:
                    for q in reqs:
                        if q.get("response", {}):
                            doc = q
                            break
                if doc:
                    res = doc.get("response", {}) or {}
                    raw_hdrs = ((res.get("response", {}) or {}).get("headers") or res.get("headers") or {})
                    if isinstance(raw_hdrs, dict):
                        headers_map = raw_hdrs
                    elif isinstance(raw_hdrs, list):
                        headers_map = {h.get("name", ""): h.get("value", "") for h in raw_hdrs if isinstance(h, dict)}
            except Exception:
                pass

            def _fill_headers():
                hdr_tree.delete(*hdr_tree.get_children())
                preferred = [
                    "server", "content-type", "x-powered-by", "x-frame-options",
                    "x-content-type-options", "content-security-policy"
                ]
                seen = set()
                for key in preferred:
                    for k, v in headers_map.items():
                        if k.lower() == key:
                            hdr_tree.insert("", "end", values=(k, v))
                            seen.add(k)
                for k in sorted(headers_map.keys(), key=lambda x: x.lower()):
                    if k in seen:
                        continue
                    hdr_tree.insert("", "end", values=(k, headers_map[k]))
                if not headers_map:
                    hdr_tree.insert("", "end", values=("—", "No headers found"))
            post_to_ui(_fill_headers)

            # Screenshot (final)
            ss_url = result.get("task", {}).get("screenshotURL") or f"https://urlscan.io/screenshots/{uuid}.png"
            ir = session.get(ss_url, timeout=20)
            if ir.status_code == 200:
                img = Image.open(io.BytesIO(ir.content))
                img.thumbnail((1600, 1000))
                photo = ImageTk.PhotoImage(img)
                def _set():
                    shot_label.configure(image=photo)
                    shot_label._photo_ref = photo
                    shot_label._pil_ref = img
                    status_lbl.configure(text="Screenshot loaded")
                    save_btn.configure(state=NORMAL)
                post_to_ui(_set)
            else:
                post_to_ui(status_lbl.configure, text="No screenshot available")
        except Exception as e:
            post_to_ui(status_lbl.configure, text=f"Error: {e}")
    threading.Thread(target=worker, daemon=True).start()


# =============================
# Event handlers
# =============================
def on_scan():
    output_box.delete(1.0, tk.END)
    for item in summary.get_children():
        summary.delete(item)

    set_running(True)
    set_status("Preparing…", "WORKING", "info-inverse")

    raw = ioc_text.get("1.0", tk.END)
    tokens = extract_iocs(raw)

    t = threading.Thread(target=process_inputs, args=(tokens,), daemon=True)
    t.start()

def on_demo():
    demo = """
User clicked hxxps[:]//[2606[:]4700[:]4700::1111]/foo
Connection to [fe80[:][:]1%lo0]:443 succeeded
Allowlist: 2001:db8::, 2607:f8b0:4005:80a::200e
Blocked -> hxxp[:]//[2001[:]4860[:]4860::8888]
Plain IPv6: 2606:4700:4700::1111 and IPv4: 142.119.12.187
Indicators: google.com, facebook.com, www.example.org/path
Hashes: e3b0c44298fc1c149afbf4c8996fb924  da39a3ee5e6b4b0d3255bfef95601890afd80709
         9c1185a5c5e9fc54612808977ee8f548b2258d31aa249cbe0f9a3ed2e9efc3f7
"""
    ioc_text.delete("1.0", tk.END)
    ioc_text.insert(tk.END, demo)
    on_scan()

def on_clear():
    ioc_text.delete("1.0", tk.END)
    output_box.delete("1.0", tk.END)
    for item in summary.get_children():
        summary.delete(item)
    set_status("Cleared.", "READY", "success-inverse")

def on_copy_all():
    data = output_box.get("1.0", tk.END)
    root.clipboard_clear()
    root.clipboard_append(data)
    set_status("Results copied to clipboard.", "COPIED", "primary-inverse")

def on_summary_select(event=None):
    sel = summary.selection()
    if not sel:
        screenshot_btn.configure(state=DISABLED)
        return
    vals = summary.item(sel[0], "values")
    screenshot_btn.configure(state=(NORMAL if vals and vals[0] in ("URL", "IP") else DISABLED))

scan_btn.configure(command=on_scan)
test_btn.configure(command=on_demo)
clear_btn.configure(command=on_clear)
copy_all_btn.configure(command=on_copy_all)
upload_file_btn.configure(command=upload_file_to_vt)
screenshot_btn.configure(command=on_screenshot)
summary.bind("<<TreeviewSelect>>", on_summary_select)
on_summary_select()


# =============================
# Run
# =============================
root.mainloop()
