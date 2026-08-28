"""Base class for all vulnerability checks (plugin interface)."""
from __future__ import annotations

from webrecon.core.config import Config
from webrecon.core.crawler import CrawlData
from webrecon.core.http_client import HttpClient
from webrecon.core.target import Target
from webrecon.model.finding import Finding


class Check:
    #: unique lowercase slug used on the CLI (--checks) and in the registry
    name: str = "base"
    #: short human description shown in --list-checks
    description: str = ""

    def run(self, target: Target, http: HttpClient, crawl: CrawlData,
            config: Config) -> list[Finding]:
        """Execute the check and return a list of Findings (possibly empty)."""
        raise NotImplementedError
