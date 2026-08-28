"""WebRecon desktop GUI — a dark-themed Tkinter front-end over the scan engine.

Runs the same Engine used by the CLI, but in a background thread so the window
stays responsive. Progress is streamed to a live log; findings land in a
colour-coded table with a detail pane; reports are written and openable.

Launch:  python -m webrecon.gui      (or the `webrecon-gui` command)
"""
from __future__ import annotations

import os
import queue
import re
import threading
from datetime import datetime, timezone
from pathlib import Path

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from webrecon import __version__
from webrecon.core.config import Config
from webrecon.core.target import parse_target, TargetError
from webrecon.engine import Engine
from webrecon.model.severity import Severity, risk_score, risk_band
from webrecon.report import json_report, html_report


# ---- Dark theme palette (mirrors the HTML report) -----------------------
BG = "#0f1420"
CARD = "#171d2b"
LINE = "#26304a"
TEXT = "#e6e9f0"
MUTED = "#8a93a6"
ACCENT = "#4dd0e1"
FIELD = "#0c1018"

SEV_COLOR = {
    "CRITICAL": "#ff4d5e",
    "HIGH": "#ff8a3d",
    "MEDIUM": "#ffcc45",
    "LOW": "#4dd0e1",
    "INFO": "#7f9cf5",
}
OK = "#38d39f"

_RICH_TAG = re.compile(r"\[/\]|\[/?[a-z_ ]+\]")


def _strip_markup(text: str) -> str:
    return _RICH_TAG.sub("", text)


class QueueConsole:
    """A stand-in for rich.Console: forwards printed lines to a queue."""

    def __init__(self, q: "queue.Queue"):
        self._q = q

    def print(self, *args, **kwargs) -> None:
        msg = " ".join(str(a) for a in args) if args else ""
        self._q.put(("log", _strip_markup(msg)))


class WebReconGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.queue: "queue.Queue" = queue.Queue()
        self.scan_thread: threading.Thread | None = None
        self.result = None
        self.report_paths: dict[str, Path] = {}

        root.title(f"WebRecon {__version__} — Web Security Scanner")
        root.geometry("1080x760")
        root.minsize(920, 620)
        root.configure(bg=BG)

        self._build_style()
        self._build_header()
        self._build_input()
        self._build_body()
        self._build_footer()

        self.root.after(100, self._poll_queue)

    # ---- styling --------------------------------------------------------
    def _build_style(self) -> None:
        style = ttk.Style()
        style.theme_use("clam")

        style.configure(".", background=BG, foreground=TEXT,
                        fieldbackground=FIELD, bordercolor=LINE,
                        font=("Segoe UI", 10))
        style.configure("TFrame", background=BG)
        style.configure("Card.TFrame", background=CARD)
        style.configure("TLabel", background=BG, foreground=TEXT)
        style.configure("Muted.TLabel", background=BG, foreground=MUTED)
        style.configure("Card.TLabel", background=CARD, foreground=TEXT)
        style.configure("Title.TLabel", background=BG, foreground=TEXT,
                        font=("Segoe UI Semibold", 20))
        style.configure("Sub.TLabel", background=BG, foreground=MUTED,
                        font=("Segoe UI", 10))

        style.configure("TCheckbutton", background=BG, foreground=TEXT)
        style.map("TCheckbutton", background=[("active", BG)])

        style.configure("TEntry", fieldbackground=FIELD, foreground=TEXT,
                        insertcolor=TEXT, bordercolor=LINE, padding=6)
        style.configure("TSpinbox", fieldbackground=FIELD, foreground=TEXT,
                        insertcolor=TEXT, arrowcolor=ACCENT, padding=4)

        style.configure("Accent.TButton", background=ACCENT, foreground="#06222a",
                        font=("Segoe UI Semibold", 11), padding=(18, 8),
                        borderwidth=0)
        style.map("Accent.TButton",
                  background=[("active", "#79e0ee"), ("disabled", "#2a3350")],
                  foreground=[("disabled", MUTED)])
        style.configure("Ghost.TButton", background=CARD, foreground=TEXT,
                        padding=(12, 6), borderwidth=1)
        style.map("Ghost.TButton", background=[("active", LINE)])

        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=BG, foreground=MUTED,
                        padding=(16, 8), borderwidth=0)
        style.map("TNotebook.Tab",
                  background=[("selected", CARD)],
                  foreground=[("selected", TEXT)])

        style.configure("Treeview", background=CARD, fieldbackground=CARD,
                        foreground=TEXT, rowheight=28, borderwidth=0)
        style.configure("Treeview.Heading", background=BG, foreground=MUTED,
                        font=("Segoe UI Semibold", 10), borderwidth=0)
        style.map("Treeview.Heading", background=[("active", LINE)])
        style.map("Treeview", background=[("selected", LINE)],
                  foreground=[("selected", TEXT)])

        style.configure("Horizontal.TProgressbar", background=ACCENT,
                        troughcolor=FIELD, borderwidth=0)

    # ---- header ---------------------------------------------------------
    def _build_header(self) -> None:
        head = ttk.Frame(self.root, padding=(22, 18, 22, 6))
        head.pack(fill="x")
        ttk.Label(head, text="WebRecon", style="Title.TLabel").pack(anchor="w")
        ttk.Label(head, text="Authorized web vulnerability scanner — "
                  "scan only systems you own or are permitted to test.",
                  style="Sub.TLabel").pack(anchor="w")

    # ---- input bar ------------------------------------------------------
    def _build_input(self) -> None:
        wrap = ttk.Frame(self.root, style="Card.TFrame", padding=16)
        wrap.pack(fill="x", padx=22, pady=(8, 6))

        row1 = ttk.Frame(wrap, style="Card.TFrame")
        row1.pack(fill="x")
        ttk.Label(row1, text="Target URL / IP", style="Card.TLabel").pack(anchor="w")

        row2 = ttk.Frame(wrap, style="Card.TFrame")
        row2.pack(fill="x", pady=(4, 10))
        self.target_var = tk.StringVar(value="http://")
        self.entry = ttk.Entry(row2, textvariable=self.target_var,
                               font=("Consolas", 12))
        self.entry.pack(side="left", fill="x", expand=True, ipady=3)
        self.entry.bind("<Return>", lambda e: self.start_scan())
        self.scan_btn = ttk.Button(row2, text="▶  Scan", style="Accent.TButton",
                                   command=self.start_scan)
        self.scan_btn.pack(side="left", padx=(10, 0))

        opts = ttk.Frame(wrap, style="Card.TFrame")
        opts.pack(fill="x")

        ttk.Label(opts, text="Depth", style="Card.TLabel").pack(side="left")
        self.depth_var = tk.IntVar(value=2)
        ttk.Spinbox(opts, from_=1, to=5, width=4, textvariable=self.depth_var
                    ).pack(side="left", padx=(6, 16))

        ttk.Label(opts, text="Max URLs", style="Card.TLabel").pack(side="left")
        self.maxurls_var = tk.IntVar(value=60)
        ttk.Spinbox(opts, from_=10, to=1000, increment=10, width=6,
                    textvariable=self.maxurls_var).pack(side="left", padx=(6, 16))

        ttk.Label(opts, text="Threads", style="Card.TLabel").pack(side="left")
        self.threads_var = tk.IntVar(value=10)
        ttk.Spinbox(opts, from_=1, to=40, width=4, textvariable=self.threads_var
                    ).pack(side="left", padx=(6, 16))

        self.aggressive_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(opts, text="Aggressive", variable=self.aggressive_var
                        ).pack(side="left", padx=(0, 14))
        self.verbose_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(opts, text="Verbose log", variable=self.verbose_var
                        ).pack(side="left", padx=(0, 14))
        self.authorized_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(opts, text="I am authorized to scan this target",
                        variable=self.authorized_var).pack(side="left")

        # Row 3: profile + authenticated-scan cookie/header
        adv = ttk.Frame(wrap, style="Card.TFrame")
        adv.pack(fill="x", pady=(10, 0))
        ttk.Label(adv, text="Profile", style="Card.TLabel").pack(side="left")
        self.profile_var = tk.StringVar(value="standard")
        ttk.Combobox(adv, textvariable=self.profile_var, width=10, state="readonly",
                     values=["quick", "standard", "deep"]).pack(
            side="left", padx=(6, 16))
        ttk.Label(adv, text="Cookie / Auth header (optional)",
                  style="Card.TLabel").pack(side="left")
        self.cookie_var = tk.StringVar(value="")
        ttk.Entry(adv, textvariable=self.cookie_var, font=("Consolas", 10)
                  ).pack(side="left", fill="x", expand=True, padx=(6, 0), ipady=2)

    # ---- body: summary + notebook --------------------------------------
    def _build_body(self) -> None:
        # Summary strip
        strip = ttk.Frame(self.root, style="Card.TFrame", padding=(16, 10))
        strip.pack(fill="x", padx=22, pady=(6, 6))
        self.score_lbl = tk.Label(strip, text="—", bg=CARD, fg=MUTED,
                                  font=("Segoe UI Semibold", 22))
        self.score_lbl.pack(side="left")
        ttk.Label(strip, text="risk", style="Card.TLabel").pack(
            side="left", padx=(6, 20))
        self.sev_labels: dict[str, tk.Label] = {}
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            lbl = tk.Label(strip, text=f"{sev} 0", bg=CARD, fg=SEV_COLOR[sev],
                           font=("Segoe UI Semibold", 10))
            lbl.pack(side="left", padx=6)
            self.sev_labels[sev] = lbl
        self.progress = ttk.Progressbar(strip, mode="indeterminate", length=160,
                                        style="Horizontal.TProgressbar")
        self.progress.pack(side="right")

        nb = ttk.Notebook(self.root)
        nb.pack(fill="both", expand=True, padx=22, pady=(2, 6))

        # -- Findings tab
        find_tab = ttk.Frame(nb)
        nb.add(find_tab, text="  Findings  ")
        paned = ttk.PanedWindow(find_tab, orient="vertical")
        paned.pack(fill="both", expand=True)

        tree_wrap = ttk.Frame(paned)
        cols = ("sev", "title", "location", "owasp")
        self.tree = ttk.Treeview(tree_wrap, columns=cols, show="headings",
                                 selectmode="browse")
        for cid, txt, w in (("sev", "Severity", 100), ("title", "Finding", 340),
                            ("location", "Location", 340), ("owasp", "OWASP", 120)):
            self.tree.heading(cid, text=txt)
            self.tree.column(cid, width=w, anchor="w")
        for sev, color in SEV_COLOR.items():
            self.tree.tag_configure(sev, foreground=color)
        vs = ttk.Scrollbar(tree_wrap, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vs.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vs.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        paned.add(tree_wrap, weight=3)

        self.detail = tk.Text(paned, height=9, bg=FIELD, fg=TEXT, bd=0,
                              insertbackground=TEXT, wrap="word",
                              font=("Consolas", 10), padx=12, pady=10)
        self.detail.insert("1.0", "Select a finding to see full details "
                           "(description, impact, remediation, evidence).")
        self.detail.configure(state="disabled")
        self._detail_tags()
        paned.add(self.detail, weight=2)

        # -- Live log tab
        log_tab = ttk.Frame(nb)
        nb.add(log_tab, text="  Live Log  ")
        self.log = tk.Text(log_tab, bg=FIELD, fg=TEXT, bd=0, wrap="word",
                           insertbackground=TEXT, font=("Consolas", 10),
                           padx=12, pady=10)
        lvs = ttk.Scrollbar(log_tab, orient="vertical", command=self.log.yview)
        self.log.configure(yscrollcommand=lvs.set)
        self.log.pack(side="left", fill="both", expand=True)
        lvs.pack(side="right", fill="y")
        self.log.configure(state="disabled")

        # -- Recon tab
        recon_tab = ttk.Frame(nb)
        nb.add(recon_tab, text="  Recon  ")
        self.recon = tk.Text(recon_tab, bg=FIELD, fg=TEXT, bd=0, wrap="word",
                             insertbackground=TEXT, font=("Consolas", 10),
                             padx=12, pady=10)
        rvs = ttk.Scrollbar(recon_tab, orient="vertical", command=self.recon.yview)
        self.recon.configure(yscrollcommand=rvs.set)
        self.recon.pack(side="left", fill="both", expand=True)
        rvs.pack(side="right", fill="y")
        self.recon.configure(state="disabled")

    def _detail_tags(self) -> None:
        self.detail.tag_configure("h", foreground=ACCENT,
                                  font=("Consolas", 10, "bold"))
        self.detail.tag_configure("k", foreground=MUTED)

    # ---- footer ---------------------------------------------------------
    def _build_footer(self) -> None:
        bar = ttk.Frame(self.root, padding=(22, 4, 22, 12))
        bar.pack(fill="x")
        self.status = ttk.Label(bar, text="Ready.", style="Muted.TLabel")
        self.status.pack(side="left")
        self.open_folder_btn = ttk.Button(bar, text="Open reports folder",
                                          style="Ghost.TButton", state="disabled",
                                          command=self._open_folder)
        self.open_folder_btn.pack(side="right", padx=(8, 0))
        self.open_json_btn = ttk.Button(bar, text="Open JSON", style="Ghost.TButton",
                                        state="disabled",
                                        command=lambda: self._open("json"))
        self.open_json_btn.pack(side="right", padx=(8, 0))
        self.open_html_btn = ttk.Button(bar, text="Open HTML report",
                                        style="Ghost.TButton", state="disabled",
                                        command=lambda: self._open("html"))
        self.open_html_btn.pack(side="right")

    # ---- scan lifecycle -------------------------------------------------
    def start_scan(self) -> None:
        if self.scan_thread and self.scan_thread.is_alive():
            return
        raw = self.target_var.get().strip()
        if not raw or raw == "http://":
            messagebox.showwarning("WebRecon", "Enter a target URL or IP.")
            return
        if not self.authorized_var.get():
            messagebox.showwarning(
                "Authorization required",
                "You must confirm you are authorized to scan this target.\n\n"
                "Tick 'I am authorized to scan this target' before scanning.")
            return
        try:
            target = parse_target(raw)
        except TargetError as exc:
            messagebox.showerror("Invalid target", str(exc))
            return

        cfg = Config()
        cfg.profile = self.profile_var.get()
        cfg.apply_profile()
        cfg.apply_overrides(
            target=target.base_url, depth=self.depth_var.get(),
            max_urls=self.maxurls_var.get(), threads=self.threads_var.get(),
            aggressive=self.aggressive_var.get(), verbose=self.verbose_var.get(),
            authorized=True, formats=["html", "json", "sarif"])
        # Optional authenticated scan: header-style value -> header, else cookie.
        auth = self.cookie_var.get().strip()
        if auth:
            if re.match(r"^[A-Za-z][A-Za-z0-9-]*:\s", auth):
                k, v = auth.split(":", 1)
                cfg.extra_headers = {k.strip(): v.strip()}
            else:
                cfg.cookie = auth

        # Reset UI
        self._clear_results()
        self._set_running(True)
        self.status.configure(text=f"Scanning {target.base_url} …")
        self._append_log(f"Starting scan of {target.base_url}\n")

        self.scan_thread = threading.Thread(
            target=self._run_engine, args=(target, cfg), daemon=True)
        self.scan_thread.start()

    def _run_engine(self, target, cfg) -> None:
        try:
            console = QueueConsole(self.queue)
            engine = Engine(target, cfg, console=console)
            result = engine.run()
            self.queue.put(("done", result))
        except Exception as exc:  # surface any engine error to the UI
            self.queue.put(("error", str(exc)))

    # ---- queue pump -----------------------------------------------------
    def _poll_queue(self) -> None:
        try:
            while True:
                kind, payload = self.queue.get_nowait()
                if kind == "log":
                    self._append_log(payload + "\n")
                elif kind == "done":
                    self._on_done(payload)
                elif kind == "error":
                    self._on_error(payload)
        except queue.Empty:
            pass
        self.root.after(100, self._poll_queue)

    def _on_done(self, result) -> None:
        self.result = result
        self._set_running(False)
        counts = result.counts()
        score = risk_score(result.findings)
        band = risk_band(score)
        self.score_lbl.configure(
            text=f"{score}/100",
            fg=SEV_COLOR["CRITICAL"] if score >= 70 else
               (SEV_COLOR["HIGH"] if score >= 40 else
                (SEV_COLOR["MEDIUM"] if score >= 15 else OK)))
        for sev, lbl in self.sev_labels.items():
            lbl.configure(text=f"{sev} {counts[sev]}")

        self._findings = result.sorted_findings()
        for idx, f in enumerate(self._findings):
            self.tree.insert("", "end", iid=str(idx),
                             values=(f.severity.value, f.title,
                                     f.location or "-",
                                     f.owasp.split(" - ")[0] if f.owasp else "-"),
                             tags=(f.severity.value,))

        self._fill_recon(result.recon)
        self._write_reports(result)

        self.status.configure(
            text=f"Done — {len(result.findings)} finding(s), risk {score}/100 "
                 f"({band}), {result.duration_seconds:.1f}s, "
                 f"{result.stats.get('requests_sent', 0)} requests.")
        self._append_log(f"\nScan complete: {len(result.findings)} findings.\n")

    def _on_error(self, message: str) -> None:
        self._set_running(False)
        self.status.configure(text="Scan failed.")
        self._append_log(f"\n[ERROR] {message}\n")
        messagebox.showerror("Scan failed", message)

    # ---- results helpers ------------------------------------------------
    def _on_select(self, _event) -> None:
        sel = self.tree.selection()
        if not sel or not getattr(self, "_findings", None):
            return
        f = self._findings[int(sel[0])]
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")

        def line(key, value):
            self.detail.insert("end", f"{key}\n", "h")
            self.detail.insert("end", f"{value}\n\n")

        self.detail.insert("end", f"[{f.severity.value}] ", "h")
        self.detail.insert("end", f"{f.title}\n\n")
        self.detail.insert("end", "Location: ", "k")
        self.detail.insert("end", f"{f.location or 'n/a'}\n")
        self.detail.insert("end", "Classification: ", "k")
        self.detail.insert("end",
                           f"{f.owasp}  {f.cwe}  CVSS~{f.cvss}\n")
        self.detail.insert("end", "Confidence: ", "k")
        self.detail.insert("end", f"{f.confidence}\n\n")
        line("Description", f.description)
        line("Impact", f.impact)
        line("Remediation", f.remediation)
        if f.evidence:
            line("Evidence", f.evidence)
        if f.poc:
            line("Proof / PoC", f.poc)
        if f.references:
            line("References", "\n".join(f.references))
        self.detail.configure(state="disabled")

    def _fill_recon(self, recon: dict) -> None:
        import json
        self.recon.configure(state="normal")
        self.recon.delete("1.0", "end")
        self.recon.insert("1.0", json.dumps(recon, indent=2, default=str))
        self.recon.configure(state="disabled")

    def _write_reports(self, result) -> None:
        out_dir = Path("./reports")
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        host = result.target.split("://")[-1].replace(":", "_").replace(".", "-")
        stem = f"webrecon_{host}_{stamp}"
        self.report_paths["json"] = json_report.write(
            result, out_dir / f"{stem}.json")
        self.report_paths["html"] = html_report.write(
            result, out_dir / f"{stem}.html")
        try:
            from webrecon.report import sarif_report
            sarif_report.write(result, out_dir / f"{stem}.sarif")
        except Exception:
            pass
        for btn in (self.open_html_btn, self.open_json_btn, self.open_folder_btn):
            btn.configure(state="normal")

    # ---- misc UI --------------------------------------------------------
    def _append_log(self, text: str) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", text)
        self.log.see("end")
        self.log.configure(state="disabled")

    def _clear_results(self) -> None:
        self.tree.delete(*self.tree.get_children())
        self._findings = []
        self.score_lbl.configure(text="—", fg=MUTED)
        for sev, lbl in self.sev_labels.items():
            lbl.configure(text=f"{sev} 0")
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.configure(state="disabled")
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")
        for btn in (self.open_html_btn, self.open_json_btn, self.open_folder_btn):
            btn.configure(state="disabled")

    def _set_running(self, running: bool) -> None:
        self.scan_btn.configure(state="disabled" if running else "normal",
                                text="Scanning…" if running else "▶  Scan")
        self.entry.configure(state="disabled" if running else "normal")
        if running:
            self.progress.start(12)
        else:
            self.progress.stop()

    def _open(self, kind: str) -> None:
        path = self.report_paths.get(kind)
        if path and path.exists():
            self._os_open(path)

    def _open_folder(self) -> None:
        folder = Path("./reports").resolve()
        if folder.exists():
            self._os_open(folder)

    @staticmethod
    def _os_open(path: Path) -> None:
        try:
            if os.name == "nt":
                os.startfile(str(path))  # type: ignore[attr-defined]
            elif hasattr(os, "uname") and os.uname().sysname == "Darwin":
                import subprocess
                subprocess.Popen(["open", str(path)])
            else:
                import subprocess
                subprocess.Popen(["xdg-open", str(path)])
        except Exception as exc:
            messagebox.showinfo("WebRecon", f"Could not open:\n{path}\n\n{exc}")


def main() -> int:
    root = tk.Tk()
    WebReconGUI(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
