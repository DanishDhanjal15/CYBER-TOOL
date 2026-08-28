"""GraphQL endpoint discovery + introspection / misconfiguration checks."""
from __future__ import annotations

from webrecon.checks.base import Check
from webrecon.core.config import Config
from webrecon.core.crawler import CrawlData
from webrecon.core.http_client import HttpClient
from webrecon.core.target import Target
from webrecon.model.finding import Finding
from webrecon.model.severity import Severity


# offensive-osint §16.2 GraphQL discovery paths.
_PATHS = ["/graphql", "/api/graphql", "/graphiql", "/v1/graphql", "/v2/graphql",
          "/query", "/api/query", "/gql", "/graphql/console", "/api/v1/graphql"]
_INTROSPECTION = {"query": "query{__schema{queryType{name} types{name}}}"}
_UI_MARKERS = ("graphiql", "playground", "apollo", "altair")


class GraphqlCheck(Check):
    name = "graphql"
    description = "GraphQL introspection / GraphiQL exposure / batching."

    def run(self, target: Target, http: HttpClient, crawl: CrawlData,
            config: Config) -> list[Finding]:
        findings: list[Finding] = []
        for idx, path in enumerate(_PATHS, start=1):
            url = target.url(path)
            # Introspection via POST JSON.
            resp = http.post(url, json=_INTROSPECTION,
                             headers={"Content-Type": "application/json"})
            if resp is None:
                continue
            body = (resp.text or "")
            low = body.lower()

            if '"__schema"' in body or '"queryType"' in body:
                findings.append(Finding(
                    id=f"GQL-{idx:03d}",
                    title=f"GraphQL introspection enabled: {path}",
                    severity=Severity.HIGH,
                    owasp="A05:2021 - Security Misconfiguration", cwe="CWE-200",
                    cvss=6.5, location=url, confidence="CONFIRMED",
                    description="The GraphQL endpoint answers introspection, "
                                "exposing the full schema (types, queries, "
                                "mutations).",
                    evidence="__schema returned in response",
                    impact="Attackers map every query/mutation to find sensitive "
                           "operations and business-logic flaws.",
                    remediation="Disable introspection in production; require auth "
                                "on the GraphQL endpoint.",
                    poc=f"curl -X POST '{url}' -H 'Content-Type: application/json' "
                        f"-d '{{\"query\":\"{{__schema{{types{{name}}}}}}\"}}'",
                    references=["https://cwe.mitre.org/data/definitions/200.html"]))
            elif any(mk in low for mk in _UI_MARKERS):
                findings.append(Finding(
                    id=f"GQL-UI-{idx:03d}",
                    title=f"GraphQL IDE exposed: {path}",
                    severity=Severity.MEDIUM,
                    owasp="A05:2021 - Security Misconfiguration", cwe="CWE-200",
                    cvss=5.3, location=url, confidence="CONFIRMED",
                    description="A GraphQL IDE (GraphiQL/Playground/Apollo/Altair) "
                                "is reachable on production.",
                    evidence="GraphQL IDE markers in response",
                    impact="Interactive schema exploration and query execution.",
                    remediation="Remove the GraphQL IDE from production.",
                    references=["https://cwe.mitre.org/data/definitions/200.html"]))
        return findings
