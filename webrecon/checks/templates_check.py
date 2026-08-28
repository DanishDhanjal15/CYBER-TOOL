"""Check that runs the YAML template engine (bundled + user templates)."""
from __future__ import annotations

from webrecon.checks.base import Check
from webrecon.core.config import Config
from webrecon.core.crawler import CrawlData
from webrecon.core.http_client import HttpClient
from webrecon.core.target import Target
from webrecon.model.finding import Finding
from webrecon.templates_engine.engine import load_templates, run_templates


class TemplateCheck(Check):
    name = "templates"
    description = "YAML template engine (CVE/misconfig/exposure signatures)."

    def run(self, target: Target, http: HttpClient, crawl: CrawlData,
            config: Config) -> list[Finding]:
        templates = load_templates(getattr(config, "templates_dir", "") or None)
        return run_templates(target, http, templates)
