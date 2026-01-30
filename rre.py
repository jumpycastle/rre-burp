# -*- coding: utf-8 -*-
"""
RRE (Recursive Request Exploits) + Stream Search — Burp Extension
------------------------------------------------------------------------------------

Jython / Python 2.7 friendly (no f-strings).

Track A “BApp-quality” hardening:
- Runs RRE trace work in background threads to keep Burp responsive.
- Adds clean unload handling (stop flag) via IExtensionStateListener.
- Adds max-history window & max-depth limits to cope with large projects.
- Parents dialogs to Burp Suite frame when available.
- Restricts "Open in system browser" to safe schemes (http/https).
- Adds basic log locking + output truncation safeguards.

Note: This is still the legacy (non-Montoya) API, suitable for manual loading.
"""

from burp import IBurpExtender, ITab, IContextMenuFactory, IHttpListener, IExtensionStateListener
from javax.swing import (JPanel, JButton, JTable, JScrollPane, JMenuItem,
                         JPopupMenu, JLabel, Box, JCheckBox, JSpinner,
                         SpinnerNumberModel, JDialog, BoxLayout, JTabbedPane,
                         JTextArea, JSplitPane)
from javax.swing.table import DefaultTableModel
from javax.swing import SwingUtilities
from java.awt import BorderLayout, Toolkit, Desktop
from java.awt.datatransfer import StringSelection
from java.net import URI, URL
import re
import json
import math
import collections
import traceback
import threading
import time

# ---------------- Stream Scout defaults ----------------
LIVE_ON_BY_DEFAULT = True
SCAN_REPEATER_TOO  = False
MAX_BODY_KB        = 1024
MAX_DEDUP_ENTRIES  = 8000

# ---------------- RRE defaults (project safety) ----------------
DEFAULT_MAX_HISTORY_ITEMS = 10000   # scan last N history items (0 = all)
DEFAULT_MAX_DEPTH         = 25      # recursion cap
DEFAULT_TIME_BUDGET_SEC   = 20      # stop a trace after N seconds (best-effort)

TYPE_GROUPS = {
    "Manifests & Playlists": [
        "mpd", "m3u8", "m3u", "pls", "asx", "smil", "ismc", "ism", "ram"
    ],
    "Schemes": [
        "rtsp", "rtp", "udp", "rtmp", "mms", "mmst", "mmsh", "icecast", "icy"
    ],
    "Segments / Progressive": [
        "mp4", "ts", "m4s"
    ]
}

TYPE_DESCRIPTIONS = {
    "mpd":  "MPEG-DASH manifest",
    "m3u8": "HLS (HTTP Live Streaming) manifest",
    "m3u":  "Playlist (M3U)",
    "pls":  "SHOUTcast/Icecast playlist",
    "asx":  "Windows Media playlist",
    "smil": "SMIL playlist",
    "ismc": "Smooth Streaming client manifest",
    "ism":  "Smooth Streaming manifest",
    "ram":  "RealAudio/playlist",
    "rtsp": "RTSP camera/stream",
    "rtp":  "RTP stream",
    "udp":  "UDP (unicast/multicast)",
    "rtmp": "RTMP (legacy)",
    "mms":  "Microsoft Media Server (legacy)",
    "mmst": "MMS over TCP",
    "mmsh": "MMS over HTTP",
    "icecast": "Icecast/SHOUTcast",
    "icy":  "SHOUTcast/ICY",
    "mp4": "MP4 (progressive/DASH)",
    "ts":  "MPEG-TS (HLS segment)",
    "m4s": "ISO-BMFF (DASH segment)"
}

DEFAULT_ENABLED = dict((t, True) for g in TYPE_GROUPS for t in TYPE_GROUPS[g])
for t in ["mp4", "ts", "m4s"]:
    DEFAULT_ENABLED[t] = False

SCHEME_TYPES = {
    r'^rtsp://':   ('rtsp',  TYPE_DESCRIPTIONS['rtsp']),
    r'^rtp://':    ('rtp',   TYPE_DESCRIPTIONS['rtp']),
    r'^udp://':    ('udp',   TYPE_DESCRIPTIONS['udp']),
    r'^rtmp://':   ('rtmp',  TYPE_DESCRIPTIONS['rtmp']),
    r'^mms://':    ('mms',   TYPE_DESCRIPTIONS['mms']),
    r'^mmst://':   ('mmst',  TYPE_DESCRIPTIONS['mmst']),
    r'^mmsh://':   ('mmsh',  TYPE_DESCRIPTIONS['mmsh']),
    r'^icecast://':('icecast',TYPE_DESCRIPTIONS['icecast']),
    r'^icy://':    ('icy',   TYPE_DESCRIPTIONS['icy']),
}

EXT_TYPES = {
    r'\.m3u8($|\?)':           ('m3u8', TYPE_DESCRIPTIONS['m3u8']),
    r'\.m3u($|\?)':            ('m3u',  TYPE_DESCRIPTIONS['m3u']),
    r'\.mpd($|\?)':            ('mpd',  TYPE_DESCRIPTIONS['mpd']),
    r'\.pls($|\?)':            ('pls',  TYPE_DESCRIPTIONS['pls']),
    r'\.asx($|\?)':            ('asx',  TYPE_DESCRIPTIONS['asx']),
    r'\.ism/Manifest($|\?)':   ('ism',  TYPE_DESCRIPTIONS['ism']),
    r'\.ismc($|\?)':           ('ismc', TYPE_DESCRIPTIONS['ismc']),
    r'\.smil($|\?)':           ('smil', TYPE_DESCRIPTIONS['smil']),
    r'\.ram($|\?)':            ('ram',  TYPE_DESCRIPTIONS['ram']),
    r'\.ts($|\?)':             ('ts',   TYPE_DESCRIPTIONS['ts']),
    r'\.m4s($|\?)':            ('m4s',  TYPE_DESCRIPTIONS['m4s']),
    r'\.mp4($|\?)':            ('mp4',  TYPE_DESCRIPTIONS['mp4']),
}

CT_HINTS = {
    'application/vnd.apple.mpegurl': ('m3u8', TYPE_DESCRIPTIONS['m3u8']),
    'application/x-mpegurl':         ('m3u8', TYPE_DESCRIPTIONS['m3u8']),
    'application/dash+xml':          ('mpd',  TYPE_DESCRIPTIONS['mpd']),
    'application/vnd.ms-sstr+xml':   ('ism',  TYPE_DESCRIPTIONS['ism']),
    'audio/x-scpls':                 ('pls',  TYPE_DESCRIPTIONS['pls']),
    'video/mp2t':                    ('ts',   TYPE_DESCRIPTIONS['ts']),
    'application/json':              None,
    'application/xml':               None,
    'text/plain':                    None,
    'text/html':                     None,
    'application/javascript':        None,
    'text/javascript':               None,
    'application/x-javascript':      None,
}

ABS_EXTS_FOR_BODY = ["mpd","m3u8","m3u","pls","asx","smil","ismc","ram","mp4","ts","m4s"]
BASEURL_MP4_RE = re.compile(r'<BaseURL>\s*([^<>\s]+?\.mp4(?:\?[^\s<"]*)?)\s*</BaseURL>', re.I)

def classify_url(url_str, content_type=None):
    for pat, td in SCHEME_TYPES.items():
        if re.search(pat, url_str, re.I):
            return td
    for pat, td in EXT_TYPES.items():
        if re.search(pat, url_str, re.I):
            return td
    if content_type:
        ct = content_type.split(';', 1)[0].strip().lower()
        if ct in CT_HINTS and CT_HINTS[ct] is not None:
            return CT_HINTS[ct]
    return (None, None)

def should_scan_body(content_type, url):
    if url and re.search(r'\.mpd($|\?)', url, re.I):
        return True
    if not content_type:
        return False
    ct = content_type.split(';', 1)[0].strip().lower()
    return (ct in CT_HINTS) or ct.startswith('text/') or ct.endswith('json') or ct.endswith('xml') or ct.endswith('javascript')

def find_absolute_stream_links(text):
    if not text:
        return set()
    hits = set()
    base = r'[^ \t\r\n"\'<>]'
    per_type_pattern = {
        "mpd": r'https?://{b}+\.mpd{b}*'.format(b=base),
        "m3u8": r'https?://{b}+\.m3u8{b}*'.format(b=base),
        "m3u": r'https?://{b}+\.m3u{b}*'.format(b=base),
        "pls": r'https?://{b}+\.pls{b}*'.format(b=base),
        "asx": r'https?://{b}+\.asx{b}*'.format(b=base),
        "smil": r'https?://{b}+\.smil{b}*'.format(b=base),
        "ismc": r'https?://{b}+\.ismc{b}*'.format(b=base),
        "ram": r'https?://{b}+\.ram{b}*'.format(b=base),
        "mp4": r'https?://{b}+\.mp4{b}*'.format(b=base),
        "ts":  r'https?://{b}+\.ts{b}*'.format(b=base),
        "m4s": r'https?://{b}+\.m4s{b}*'.format(b=base),
    }
    pat_ism = r'https?://{b}+\.ism/Manifest{b}*'.format(b=base)
    try:
        for u in re.findall(pat_ism, text, re.I):
            hits.add(("ism", u))
    except:
        pass
    for t in ABS_EXTS_FOR_BODY:
        pat = per_type_pattern.get(t)
        if not pat:
            continue
        try:
            for u in re.findall(pat, text, re.I):
                hits.add((t, u))
        except:
            pass
    return hits

def resolve_relative(base_url, rel):
    try:
        return str(URL(URL(base_url), rel).toString())
    except:
        return None

def find_relative_mp4s_in_mpd(text, base_url):
    hits = set()
    if not text or not base_url:
        return hits
    try:
        rels = BASEURL_MP4_RE.findall(text)
        for r in rels:
            if r.lower().startswith('http'):
                hits.add(("mp4", r))
            else:
                absu = resolve_relative(base_url, r)
                if absu:
                    hits.add(("mp4", absu))
    except:
        pass
    return hits

class BoundedSet(object):
    def __init__(self, cap):
        self.cap = cap
        self.deque = collections.deque()
        self.set = set()
    def add(self, item):
        if item in self.set:
            return False
        self.set.add(item)
        self.deque.append(item)
        if len(self.deque) > self.cap:
            old = self.deque.popleft()
            self.set.discard(old)
        return True
    def remove(self, item):
        if item in self.set:
            try:
                self.deque.remove(item)
            except:
                pass
            self.set.discard(item)
            return True
        return False


class BurpExtender(IBurpExtender, ITab, IContextMenuFactory, IHttpListener, IExtensionStateListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("RRE")

        # stop flag for unload + long operations
        self._stop = False

        # best-effort Burp frame (for dialog parenting)
        try:
            self._suite_frame = callbacks.getSuiteFrame()
        except:
            self._suite_frame = None

        # thread tracking (optional; useful for debugging)
        self._threads = []
        self._threads_lock = threading.Lock()

        # console state + lock
        self._console_out = []
        self._console_err = []
        self._log_lock = threading.Lock()

        self._root = JPanel(BorderLayout())
        self._tabs = JTabbedPane()

        self._console_panel = self._build_console_panel()
        self._tabs.addTab("RRE Console", self._console_panel)

        self._stream_panel = self._build_stream_scout_panel()
        self._tabs.addTab("Stream Search", self._stream_panel)

        self._tabs.setSelectedIndex(0)
        self._root.add(self._tabs, BorderLayout.CENTER)

        callbacks.addSuiteTab(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.registerHttpListener(self)

        # unload callback
        try:
            callbacks.registerExtensionStateListener(self)
        except:
            pass

        self._log_out(u"[RRE] Loaded combined extension (RRE + Stream Search).")

    # ----- IExtensionStateListener -----
    def extensionUnloaded(self):
        # signal background work to stop ASAP
        self._stop = True
        try:
            self._log_out(u"[RRE] Extension unloading: stopping background work.")
        except:
            pass

    # ----- ITab -----
    def getTabCaption(self):
        return "RRE"

    def getUiComponent(self):
        return self._root

    # ----- IContextMenuFactory -----
    def createMenuItems(self, invocation):
        items = []
        items.append(JMenuItem("RRE: Trace Dependencies", actionPerformed=lambda x: self.trace_api(invocation)))
        items.append(JMenuItem("RRE: Full Chain Discovery", actionPerformed=lambda x: self.full_chain_discovery(invocation)))
        return items

    # ---------------- Console ----------------
    def _build_console_panel(self):
        panel = JPanel(BorderLayout())

        top = Box.createHorizontalBox()
        top.add(JLabel("Output / Errors (also printed to Burp native output panes)"))
        top.add(Box.createHorizontalStrut(12))

        top.add(JButton("Clear Output", actionPerformed=lambda e: self._clear_console(out=True, err=False)))
        top.add(Box.createHorizontalStrut(6))
        top.add(JButton("Clear Errors", actionPerformed=lambda e: self._clear_console(out=False, err=True)))
        top.add(Box.createHorizontalStrut(12))
        top.add(JButton("Copy Output", actionPerformed=lambda e: self._copy_console(out=True, err=False)))
        top.add(Box.createHorizontalStrut(6))
        top.add(JButton("Copy Errors", actionPerformed=lambda e: self._copy_console(out=False, err=True)))

        top.add(Box.createHorizontalStrut(18))
        top.add(JLabel("Max history:"))
        self._maxHistory = JSpinner(SpinnerNumberModel(DEFAULT_MAX_HISTORY_ITEMS, 0, 200000, 1000))
        top.add(self._maxHistory)
        top.add(Box.createHorizontalStrut(10))
        top.add(JLabel("Max depth:"))
        self._maxDepth = JSpinner(SpinnerNumberModel(DEFAULT_MAX_DEPTH, 1, 200, 1))
        top.add(self._maxDepth)
        top.add(Box.createHorizontalStrut(10))
        top.add(JLabel("Time budget (s):"))
        self._timeBudget = JSpinner(SpinnerNumberModel(DEFAULT_TIME_BUDGET_SEC, 1, 600, 1))
        top.add(self._timeBudget)

        self._out_area = JTextArea()
        self._out_area.setEditable(False)
        self._err_area = JTextArea()
        self._err_area.setEditable(False)

        split = JSplitPane(JSplitPane.VERTICAL_SPLIT, JScrollPane(self._out_area), JScrollPane(self._err_area))
        split.setResizeWeight(0.75)

        panel.add(top, BorderLayout.NORTH)
        panel.add(split, BorderLayout.CENTER)
        return panel

    def _ensure_unicode(self, s):
        try:
            if isinstance(s, unicode):
                return s
            if isinstance(s, str):
                try:
                    return s.decode("utf-8")
                except:
                    try:
                        return s.decode("latin-1")
                    except:
                        return unicode(s)
            return unicode(s)
        except:
            try:
                return unicode(str(s))
            except:
                return u"[unprintable]"

    def _truncate(self, s, limit=200):
        try:
            u = self._ensure_unicode(s)
            if len(u) <= limit:
                return u
            return u[:limit] + u"...(truncated)"
        except:
            return u"[unprintable]"

    def _log_out(self, msg):
        umsg = self._ensure_unicode(msg)
        with self._log_lock:
            self._console_out.append(umsg)
        try:
            self._callbacks.printOutput(umsg)
        except:
            pass
        SwingUtilities.invokeLater(lambda: self._out_area.append(umsg + u"\n"))

    def _log_err(self, msg):
        umsg = self._ensure_unicode(msg)
        with self._log_lock:
            self._console_err.append(umsg)
        try:
            self._callbacks.printError(umsg)
        except:
            pass
        SwingUtilities.invokeLater(lambda: self._err_area.append(umsg + u"\n"))

    def _clear_console(self, out=False, err=False):
        if out:
            with self._log_lock:
                self._console_out = []
            self._out_area.setText("")
        if err:
            with self._log_lock:
                self._console_err = []
            self._err_area.setText("")

    def _copy_console(self, out=False, err=False):
        text = ""
        with self._log_lock:
            if out:
                text = "\n".join([self._ensure_unicode(x) for x in self._console_out])
            if err:
                text = "\n".join([self._ensure_unicode(x) for x in self._console_err])
        try:
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(StringSelection(text), None)
        except:
            pass

    # ---------------- RRE Actions (background threaded) ----------------
    def trace_api(self, invocation):
        selected_messages = None
        try:
            selected_messages = invocation.getSelectedMessages()
        except:
            selected_messages = None

        if not selected_messages:
            self._log_err(u"[RRE] No message selected. Select a request/response first.")
            return

        highlighted_value = self.extract_highlighted_value(invocation, selected_messages[0])
        if not highlighted_value:
            self._log_err(u"[RRE] No selection detected. Highlight a parameter/value in the request or response, then retry.")
            return

        self._log_out(u"[RRE] Starting trace from: {0}".format(self._truncate(highlighted_value)))

        t = threading.Thread(target=self._run_trace_thread, args=("trace", highlighted_value))
        t.setDaemon(True)
        self._track_thread(t)
        t.start()

    def full_chain_discovery(self, invocation):
        selected_messages = None
        try:
            selected_messages = invocation.getSelectedMessages()
        except:
            selected_messages = None

        if not selected_messages:
            self._log_err(u"[RRE] No message selected. Select a request/response first.")
            return

        highlighted_value = self.extract_highlighted_value(invocation, selected_messages[0])
        if not highlighted_value:
            self._log_err(u"[RRE] No selection detected. Highlight a parameter/value in the request or response, then retry.")
            return

        self._log_out(u"[RRE] Full Chain Discovery starting from: {0}".format(self._truncate(highlighted_value)))

        t = threading.Thread(target=self._run_trace_thread, args=("full", highlighted_value))
        t.setDaemon(True)
        self._track_thread(t)
        t.start()

    def _track_thread(self, t):
        try:
            with self._threads_lock:
                self._threads.append(t)
        except:
            pass

    def _run_trace_thread(self, mode, value):
        # NOTE: Burp does not reliably surface exceptions from background threads.
        # Always catch and print stack traces.
        try:
            if self._stop:
                return
            if mode == "trace":
                self.walkback_to_first_reference(value)
            else:
                self.full_walkback_chain(value)
        except Exception:
            self._log_err(u"[RRE] Background thread error:\n{0}".format(self._ensure_unicode(traceback.format_exc())))

    def extract_highlighted_value(self, invocation, selected_message):
        try:
            bounds = invocation.getSelectionBounds()
            if not bounds or bounds[0] == bounds[1]:
                return None

            request = selected_message.getRequest()
            response = selected_message.getResponse()

            req_str = self._helpers.bytesToString(request) if request else ""
            resp_str = self._helpers.bytesToString(response) if response else ""

            if request and bounds[1] <= len(req_str):
                highlighted = req_str[bounds[0]:bounds[1]].strip()
                return highlighted if highlighted else None

            if response and bounds[1] <= len(resp_str):
                highlighted = resp_str[bounds[0]:bounds[1]].strip()
                return highlighted if highlighted else None

            return None
        except:
            return None

    # ---------------- Walkback logic ----------------
    def _get_history_window(self):
        history = self._callbacks.getProxyHistory() or []
        try:
            n = int(self._maxHistory.getValue())
        except:
            n = DEFAULT_MAX_HISTORY_ITEMS
        if n and n > 0 and len(history) > n:
            return history[-n:]
        return history

    def _limits(self):
        try:
            max_depth = int(self._maxDepth.getValue())
        except:
            max_depth = DEFAULT_MAX_DEPTH
        try:
            budget = int(self._timeBudget.getValue())
        except:
            budget = DEFAULT_TIME_BUDGET_SEC
        return max_depth, budget

    def walkback_to_first_reference(self, value):
        history = self._get_history_window()
        visited = set()
        max_depth, budget = self._limits()
        start = time.time()

        arrow_found = u"\u2192"  # →
        arrow_dep   = u"\u2193"  # ↓
        arrow_loop  = u"\u21ba"  # ↺

        def recursive_walk(current_value, depth=0):
            if self._stop:
                self._log_out(u"[RRE] Stopped (extension unloading).")
                return
            if (time.time() - start) > budget:
                self._log_out(u"[RRE] Stopped (time budget exceeded: {0}s).".format(budget))
                return
            if depth > max_depth:
                self._log_out(u"{0}× Max depth reached ({1}).".format(u"    " * depth, max_depth))
                return

            if current_value in visited:
                self._log_out(u"{0}{1} Already visited: {2}".format(u"    " * depth, arrow_loop, self._truncate(current_value)))
                return
            visited.add(current_value)

            for item in history:
                if self._stop:
                    return
                req_b = item.getRequest()
                resp_b = item.getResponse()
                if not req_b or not resp_b:
                    continue

                request = self._helpers.bytesToString(req_b)
                response = self._helpers.bytesToString(resp_b)

                if current_value in response:
                    top_line = request.splitlines()[0] if request else "[No Request]"
                    tag, reason = self._auth_tag_for_request(req_b)

                    self._log_out(u"{0}{1} [{2}] Found in: {3}".format(u"    " * depth, arrow_found, self._ensure_unicode(tag), self._ensure_unicode(top_line)))
                    if reason:
                        self._log_out(u"{0}    (auth hint: {1})".format(u"    " * depth, self._ensure_unicode(reason)))

                    dependency = self.extract_dependency(response, current_value)
                    if dependency and isinstance(dependency, (str, unicode)):
                        self._log_out(u"{0}    {1} Dependency: {2}".format(u"    " * depth, arrow_dep, self._truncate(dependency)))
                        recursive_walk(dependency, depth + 1)
                    return

            self._log_out(u"{0}× No reference found for: {1}".format(u"    " * depth, self._truncate(current_value)))

        recursive_walk(value, 0)

    def full_walkback_chain(self, value):
        history = self._get_history_window()
        visited = set()
        max_depth, budget = self._limits()
        start = time.time()

        arrow_found = u"\u2192"  # →
        arrow_up    = u"\u2191"  # ↑
        arrow_dep   = u"\u2193"  # ↓
        arrow_loop  = u"\u21ba"  # ↺
        x_mark      = u"\u00d7"  # ×

        def calculate_shannon_entropy(s):
            try:
                if not s:
                    return 0.0
                if isinstance(s, unicode):
                    s2 = s.encode("utf-8")
                else:
                    s2 = s
                prob = [float(s2.count(c)) / len(s2) for c in set(s2)]
                return -sum([p * math.log(p, 2) for p in prob])
            except:
                return 0.0

        def recursive_chain(current_value, depth=0):
            if self._stop:
                self._log_out(u"[RRE] Stopped (extension unloading).")
                return
            if (time.time() - start) > budget:
                self._log_out(u"[RRE] Stopped (time budget exceeded: {0}s).".format(budget))
                return
            if depth > max_depth:
                self._log_out((u"    " * depth) + u"× Max depth reached ({0}).".format(max_depth))
                return

            indent = u"    " * depth

            if current_value in visited:
                self._log_out(indent + arrow_loop + u" Already visited: {0}".format(self._truncate(current_value)))
                return
            visited.add(current_value)

            for item in history:
                if self._stop:
                    return
                req_b = item.getRequest()
                resp_b = item.getResponse()
                if not req_b or not resp_b:
                    continue

                request = self._helpers.bytesToString(req_b)
                response = self._helpers.bytesToString(resp_b)

                if current_value in response:
                    top_line = request.splitlines()[0] if request else "[No Request]"
                    tag, reason = self._auth_tag_for_request(req_b)

                    self._log_out(indent + arrow_found + u" [{0}] Found in: {1}".format(self._ensure_unicode(tag), self._ensure_unicode(top_line)))
                    if reason:
                        self._log_out(indent + u"    (auth hint: {0})".format(self._ensure_unicode(reason)))

                    matches = re.findall(r"/([a-zA-Z0-9]{10,})", top_line)
                    for match in matches:
                        entropy = calculate_shannon_entropy(match)
                        if entropy > 3.0 and match not in visited:
                            self._log_out(indent + u"    " + arrow_up + u" High entropy match: {0} (entropy: {1:.2f})".format(self._truncate(match), entropy))
                            recursive_chain(match, depth + 1)

                    dependency = self.extract_dependency(response, current_value)
                    if dependency and isinstance(dependency, (str, unicode)) and dependency not in visited:
                        self._log_out(indent + u"    " + arrow_dep + u" Dependency: {0}".format(self._truncate(dependency)))
                        recursive_chain(dependency, depth + 1)
                    return

            self._log_out(indent + x_mark + u" No reference found for: {0}".format(self._truncate(current_value)))

        self._log_out(u"\n" + arrow_found + u" Starting Recursive Chain Discovery")
        self._log_out(u"Initial Target: {0}\n".format(self._truncate(value)))
        recursive_chain(value, 0)

    # ---------------- Dependency extraction ----------------
    def extract_dependency(self, response, current_value):
        try:
            json_data = self.parse_json(response)
            if json_data:
                dependency = self.find_in_json(json_data, current_value)
                if dependency:
                    return dependency
            return self.find_in_text(response, current_value)
        except:
            return None

    def parse_json(self, response):
        try:
            parts = response.split("\r\n\r\n", 1)
            if len(parts) != 2:
                return None
            body = parts[1]
            if not body.strip().startswith(("{", "[")):
                return None
            return json.loads(body)
        except:
            return None

    def find_in_json(self, json_data, current_value):
        def recursive_search(data):
            if isinstance(data, dict):
                for key, value in data.items():
                    if current_value in str(value):
                        return key if isinstance(value, str) else value
                    if isinstance(value, (dict, list)):
                        result = recursive_search(value)
                        if result:
                            return result
            elif isinstance(data, list):
                for item in data:
                    result = recursive_search(item)
                    if result:
                        return result
            return None
        return recursive_search(json_data)

    def find_in_text(self, response, current_value):
        try:
            for line in response.splitlines():
                if current_value in line:
                    for part in line.split():
                        if part.startswith("key=") or part.startswith("id="):
                            return part.split("=")[-1].strip('"')
            return None
        except:
            return None

    # ---------------- Auth heuristic tagging ----------------
    def _auth_tag_for_request(self, request_bytes):
        try:
            if not request_bytes:
                return ("NOAUTH", "no-request")

            req_info = self._helpers.analyzeRequest(request_bytes)
            headers = req_info.getHeaders()

            lower_headers = []
            for h in headers:
                try:
                    lower_headers.append(str(h).lower())
                except:
                    pass

            for h in lower_headers:
                if h.startswith("authorization:"):
                    return ("AUTH", "Authorization")
                if h.startswith("proxy-authorization:"):
                    return ("AUTH", "Proxy-Authorization")
                if h.startswith("x-api-key:") or h.startswith("x-api_key:"):
                    return ("AUTH", "X-Api-Key")
                if h.startswith("x-auth-token:") or h.startswith("x-auth_token:"):
                    return ("AUTH", "X-Auth-Token")
                if h.startswith("x-access-token:") or h.startswith("x-access_token:"):
                    return ("AUTH", "X-Access-Token")
                if h.startswith("x-session-token:") or h.startswith("x-session_token:"):
                    return ("AUTH", "X-Session-Token")

            cookie_line = None
            for h in lower_headers:
                if h.startswith("cookie:"):
                    cookie_line = h
                    break

            if cookie_line:
                strong_cookie_keys = [
                    "session", "sid", "sess", "jwt", "token", "auth", "bearer",
                    "sso", "saml", "oauth", "id_token", "access_token"
                ]
                for k in strong_cookie_keys:
                    if (k + "=") in cookie_line or (k + ":") in cookie_line:
                        return ("AUTH", "Cookie({0})".format(k))
                if "csrf" in cookie_line or "xsrf" in cookie_line:
                    return ("MAYBE", "Cookie(CSRF/XSRF)")
                return ("MAYBE", "Cookie(present)")

            try:
                req_str = self._helpers.bytesToString(request_bytes)
            except:
                req_str = None

            if req_str:
                low = req_str.lower()
                token_markers = [
                    "access_token=", "id_token=", "token=", "jwt=", "auth=",
                    "session=", "sso=", "sig=", "signature=", "policy=", "key="
                ]
                for m in token_markers:
                    if m in low:
                        return ("MAYBE", "Param({0})".format(m.rstrip("=")))

            return ("NOAUTH", "no-obvious-auth")
        except:
            return ("MAYBE", "auth-check-error")

    # ---------------- Stream Search ----------------
    def _build_stream_scout_panel(self):
        self._enabled = dict(DEFAULT_ENABLED)
        self._seen = BoundedSet(MAX_DEDUP_ENTRIES)

        panel = JPanel(BorderLayout())

        top = Box.createHorizontalBox()
        self._liveChk     = JCheckBox("Live capture", LIVE_ON_BY_DEFAULT)
        self._repeaterChk = JCheckBox("Include Repeater", SCAN_REPEATER_TOO)
        self._typesBtn    = JButton("Types [toggle]", actionPerformed=self._open_types_dialog)
        top.add(self._liveChk)
        top.add(Box.createHorizontalStrut(10))
        top.add(self._repeaterChk)
        top.add(Box.createHorizontalStrut(10))
        top.add(self._typesBtn)
        top.add(Box.createHorizontalStrut(18))
        top.add(JLabel("Max body (KB):"))
        self._maxKb = JSpinner(SpinnerNumberModel(MAX_BODY_KB, 64, 4096, 64))
        top.add(self._maxKb)
        top.add(Box.createHorizontalStrut(18))
        self._status = JLabel("Ready.")
        top.add(self._status)

        self._model = DefaultTableModel(["Type","Description","Link"], 0)
        self._table = JTable(self._model)
        self._table.setAutoCreateRowSorter(True)

        popup = JPopupMenu()
        popup.add(JMenuItem("Copy URL", actionPerformed=self.copy_selected))
        popup.add(JMenuItem("Open in system browser", actionPerformed=self.open_selected))
        popup.add(JMenuItem("Send to Repeater (GET)", actionPerformed=self.send_to_repeater))
        popup.addSeparator()
        popup.add(JMenuItem("Delete selected", actionPerformed=self.delete_selected))
        self._table.setComponentPopupMenu(popup)

        panel.add(top, BorderLayout.NORTH)
        panel.add(JScrollPane(self._table), BorderLayout.CENTER)

        self._update_status()
        return panel

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        try:
            if self._stop:
                return
            if messageIsRequest or not hasattr(self, "_liveChk") or not self._liveChk.isSelected():
                return

            if toolFlag != self._callbacks.TOOL_PROXY:
                if not (self._repeaterChk.isSelected() and toolFlag == self._callbacks.TOOL_REPEATER):
                    return

            url = self._extract_url_from_request(messageInfo)
            ct  = self._content_type_of(messageInfo)

            t, d = classify_url(url or "", ct)
            self._maybe_add(t, d, url)

            if not should_scan_body(ct, url):
                return

            body = self._safe_body_slice(messageInfo, int(self._maxKb.getValue()) * 1024)
            if not body:
                return
            text = self._decode_to_text(body)
            if not text:
                return

            for (tb, ub) in find_absolute_stream_links(text):
                tb2, db2 = classify_url(ub, None)
                self._maybe_add(tb2, db2, ub)

            if t == "mpd" and url:
                for (tm, um) in find_relative_mp4s_in_mpd(text, url):
                    tm2, dm2 = classify_url(um, None)
                    self._maybe_add(tm2, dm2, um)

        except:
            pass

    def _update_status(self):
        on = "on" if self._liveChk.isSelected() else "off"
        rep = "on" if self._repeaterChk.isSelected() else "off"
        rows = self._model.getRowCount()
        self._status.setText("Live:{0}  Repeater:{1}  Rows:{2}".format(on, rep, rows))

    def _safe_body_slice(self, msg, limit_bytes):
        try:
            resp = msg.getResponse()
            if not resp:
                return None
            an = self._helpers.analyzeResponse(resp)
            body = resp[an.getBodyOffset():]
            return body[:limit_bytes] if len(body) > limit_bytes else body
        except:
            return None

    def _decode_to_text(self, body_bytes):
        try:
            return self._helpers.bytesToString(body_bytes)
        except:
            try:
                return str(body_bytes.tostring(), "latin-1")
            except:
                return None

    def _content_type_of(self, msg):
        try:
            an = self._helpers.analyzeResponse(msg.getResponse())
            for h in an.getHeaders():
                if str(h).lower().startswith("content-type:"):
                    return str(h).split(":",1)[1].strip()
        except:
            pass
        return None

    def _extract_url_from_request(self, msg):
        try:
            reqInfo = self._helpers.analyzeRequest(msg)
            return str(reqInfo.getUrl())
        except:
            return None

    def _maybe_add(self, t, d, link):
        if not t or not link:
            return
        if not self._enabled.get(t, False):
            return
        key = (t, link)
        if not self._seen.add(key):
            return
        SwingUtilities.invokeLater(lambda: (self._model.addRow([t, d, link]), self._update_status()))

    # Types dialog (parented)
    def _open_types_dialog(self, evt=None):
        try:
            dlg = JDialog(self._suite_frame) if self._suite_frame is not None else JDialog()
        except:
            dlg = JDialog()
        dlg.setTitle("RRE – Stream Search Capture Types")
        dlg.setModal(True)

        root = JPanel()
        root.setLayout(BoxLayout(root, BoxLayout.Y_AXIS))
        self._typeCheckboxes = {}

        for group in ["Manifests & Playlists", "Schemes", "Segments / Progressive"]:
            root.add(JLabel(" " + group))
            sub = JPanel()
            sub.setLayout(BoxLayout(sub, BoxLayout.Y_AXIS))
            for t in TYPE_GROUPS[group]:
                cb = JCheckBox("{0}  ({1})".format(t, TYPE_DESCRIPTIONS.get(t, t)), self._enabled.get(t, False))
                self._typeCheckboxes[t] = cb
                sub.add(cb)
            root.add(sub)
            root.add(JLabel(" "))

        row = JPanel()
        row.setLayout(BoxLayout(row, BoxLayout.X_AXIS))
        row.add(JButton("Select all", actionPerformed=lambda e:self._types_select_all(True)))
        row.add(Box.createHorizontalStrut(8))
        row.add(JButton("Select none", actionPerformed=lambda e:self._types_select_all(False)))
        row.add(Box.createHorizontalStrut(8))
        row.add(JButton("Manifests only", actionPerformed=lambda e:self._types_set_manifests_only()))
        row.add(Box.createHorizontalStrut(8))
        row.add(JButton("OK", actionPerformed=lambda e:(self._apply_types_from_dialog(), dlg.dispose())))
        row.add(Box.createHorizontalStrut(8))
        row.add(JButton("Cancel", actionPerformed=lambda e:dlg.dispose()))
        root.add(row)

        dlg.getContentPane().add(root)
        dlg.pack()
        try:
            dlg.setLocationRelativeTo(self._suite_frame if self._suite_frame is not None else self._root)
        except:
            dlg.setLocationRelativeTo(self._root)
        dlg.setVisible(True)

    def _types_select_all(self, val):
        for cb in self._typeCheckboxes.values():
            cb.setSelected(val)

    def _types_set_manifests_only(self):
        for t, cb in self._typeCheckboxes.items():
            cb.setSelected(t in TYPE_GROUPS["Manifests & Playlists"])

    def _apply_types_from_dialog(self):
        for t, cb in self._typeCheckboxes.items():
            self._enabled[t] = cb.isSelected()
        self._update_status()

    # Popup actions
    def _get_selected_urls(self):
        rows = self._table.getSelectedRows()
        urls = []
        for r in rows:
            mr = self._table.convertRowIndexToModel(r)
            urls.append(self._model.getValueAt(mr, 2))
        return urls

    def copy_selected(self, evt=None):
        urls = self._get_selected_urls()
        if not urls:
            return
        s = "\n".join(urls)
        try:
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(StringSelection(s), None)
        except:
            pass
        self._update_status()

    def open_selected(self, evt=None):
        # Security: only open safe schemes to avoid unexpected handlers
        cnt = 0
        if Desktop.isDesktopSupported():
            desk = Desktop.getDesktop()
            for u in self._get_selected_urls():
                try:
                    url = URL(u)
                    scheme = url.getProtocol().lower()
                    if scheme not in ["http", "https"]:
                        continue
                    desk.browse(URI(u))
                    cnt += 1
                except:
                    pass
        self._status.setText("Opened {0} URL(s).".format(cnt))

    def send_to_repeater(self, evt=None):
        cnt = 0
        for u in self._get_selected_urls():
            try:
                url = URL(u)
                host = url.getHost()
                port = url.getPort()
                if port == -1:
                    port = 443 if url.getProtocol().lower() == "https" else 80
                use_https = (url.getProtocol().lower() == "https")
                path = url.getFile() or "/"
                req = "GET {0} HTTP/1.1\r\nHost: {1}\r\nUser-Agent: RRE-StreamScout\r\nAccept: */*\r\nConnection: close\r\n\r\n".format(path, host)
                self._callbacks.sendToRepeater(host, port, use_https, self._helpers.stringToBytes(req), "RRE Stream Search")
                cnt += 1
            except:
                pass
        self._status.setText("Sent {0} to Repeater.".format(cnt))

    def delete_selected(self, evt=None):
        rows = self._table.getSelectedRows()
        if not rows:
            return
        model_rows = [self._table.convertRowIndexToModel(r) for r in rows]
        model_rows.sort(reverse=True)
        deleted = 0
        for mr in model_rows:
            try:
                t = self._model.getValueAt(mr, 0)
                link = self._model.getValueAt(mr, 2)
                self._seen.remove((t, link))
                self._model.removeRow(mr)
                deleted += 1
            except:
                pass
        self._status.setText("Deleted {0} entrie(s).".format(deleted))
