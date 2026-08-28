"""Alert notification channels for continuous monitoring.

Supports (all optional, pure-stdlib): console, a JSONL log file, generic /
Slack / Discord / Teams webhooks, and SMTP email. A single Notifier fans an
alert out to every configured channel; a broken channel never breaks the run.
"""
from __future__ import annotations

import json
import smtplib
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.mime.text import MIMEText
from pathlib import Path


@dataclass
class Alert:
    target: str
    new: list[dict]                       # new findings (dicts from the DB)
    fixed: list[dict] = field(default_factory=list)
    scan_id: int | None = None

    def worst_severity(self) -> str:
        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        present = {f.get("severity") for f in self.new}
        for s in order:
            if s in present:
                return s
        return "INFO"

    def to_text(self) -> str:
        lines = [f"WebRecon alert — {self.target}",
                 f"{len(self.new)} new finding(s)"
                 + (f", {len(self.fixed)} fixed" if self.fixed else "")]
        for f in self.new[:15]:
            lines.append(f"  [{f.get('severity')}] {f.get('title')} "
                         f"@ {f.get('location') or '-'}")
        if len(self.new) > 15:
            lines.append(f"  … and {len(self.new) - 15} more")
        return "\n".join(lines)


class Notifier:
    def __init__(self, *, webhook: str = "", log_file: str = "",
                 email_to: str = "", smtp_host: str = "", smtp_port: int = 587,
                 smtp_user: str = "", smtp_pass: str = "",
                 console=None, min_severity: str = "info"):
        self.webhook = webhook
        self.log_file = log_file
        self.email_to = email_to
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.smtp_user = smtp_user
        self.smtp_pass = smtp_pass
        self.console = console
        rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
        self.min_rank = rank.get(min_severity.lower(), 1)

    def _passes(self, alert: Alert) -> list[dict]:
        rank = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
        return [f for f in alert.new
                if rank.get(f.get("severity"), 1) >= self.min_rank]

    def send(self, alert: Alert) -> list[str]:
        """Dispatch to all channels; return the list of channels that fired."""
        worthy = self._passes(alert)
        if not worthy:
            return []
        alert = Alert(alert.target, worthy, alert.fixed, alert.scan_id)
        fired: list[str] = []
        for name, fn in (("console", self._console), ("log", self._log),
                         ("webhook", self._webhook), ("email", self._email)):
            try:
                if fn(alert):
                    fired.append(name)
            except Exception as exc:
                if self.console:
                    self.console.print(f"[red]alert channel '{name}' failed:[/] {exc}")
        return fired

    # -- channels
    def _console(self, alert: Alert) -> bool:
        if not self.console:
            return False
        sev = alert.worst_severity()
        color = {"CRITICAL": "bright_red", "HIGH": "red", "MEDIUM": "yellow"}.get(
            sev, "cyan")
        self.console.print(f"[{color}]🔔 ALERT[/] {alert.target}: "
                           f"{len(alert.new)} new (worst: {sev})")
        for f in alert.new[:10]:
            self.console.print(f"   [{color}]{f.get('severity')}[/] "
                               f"{f.get('title')}")
        return True

    def _log(self, alert: Alert) -> bool:
        if not self.log_file:
            return False
        entry = {"time": datetime.now(timezone.utc).isoformat(),
                 "target": alert.target, "scan_id": alert.scan_id,
                 "new": alert.new, "fixed": [f.get("title") for f in alert.fixed]}
        with open(self.log_file, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, default=str) + "\n")
        return True

    def _webhook(self, alert: Alert) -> bool:
        if not self.webhook:
            return False
        text = alert.to_text()
        url = self.webhook
        if "discord.com/api/webhooks" in url:
            payload = {"content": text[:1900]}
        elif "hooks.slack.com" in url or "office.com" in url or "teams" in url:
            payload = {"text": text}
        else:  # generic: rich JSON
            payload = {"text": text, "target": alert.target,
                       "new_count": len(alert.new), "findings": alert.new}
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}, method="POST")
        urllib.request.urlopen(req, timeout=10).read()
        return True

    def _email(self, alert: Alert) -> bool:
        if not (self.email_to and self.smtp_host):
            return False
        msg = MIMEText(alert.to_text())
        msg["Subject"] = (f"[WebRecon] {len(alert.new)} new finding(s) on "
                          f"{alert.target}")
        msg["From"] = self.smtp_user or "webrecon@localhost"
        msg["To"] = self.email_to
        with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=20) as s:
            try:
                s.starttls()
            except Exception:
                pass
            if self.smtp_user:
                s.login(self.smtp_user, self.smtp_pass)
            s.send_message(msg)
        return True
