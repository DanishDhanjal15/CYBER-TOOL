"""Vulnerability check plugins.

Each module defines one or more Check subclasses. `all_checks()` returns an
instance of every registered check so the engine can iterate over them.
"""
from __future__ import annotations

from .base import Check
from .security_headers import SecurityHeadersCheck
from .cookies import CookieFlagsCheck
from .cors import CorsCheck
from .http_methods import HttpMethodsCheck
from .dir_listing import DirectoryListingCheck
from .info_disclosure import InfoDisclosureCheck
from .sqli import SqlInjectionCheck
from .xss import ReflectedXssCheck
from .command_injection import CommandInjectionCheck
from .lfi_traversal import PathTraversalCheck
from .open_redirect import OpenRedirectCheck
from .csrf import CsrfCheck
from .jwt_check import JwtCheck
from .ssti import SstiCheck
from .ssrf import SsrfCheck
from .idor import IdorCheck
from .secrets import SecretsCheck
from .nosqli import NoSqlInjectionCheck
from .host_header import HostHeaderCheck
from .crlf import CrlfInjectionCheck
from .xxe import XxeCheck
from .graphql import GraphqlCheck
from .templates_check import TemplateCheck
from webrecon.browser.domxss import BrowserDomXssCheck

# Registry: order roughly reflects cost (cheap/passive first).
_REGISTRY: list[type[Check]] = [
    SecurityHeadersCheck,
    CookieFlagsCheck,
    CorsCheck,
    HttpMethodsCheck,
    DirectoryListingCheck,
    InfoDisclosureCheck,
    JwtCheck,
    CsrfCheck,
    OpenRedirectCheck,
    ReflectedXssCheck,
    SqlInjectionCheck,
    CommandInjectionCheck,
    PathTraversalCheck,
    SstiCheck,
    SsrfCheck,
    IdorCheck,
    SecretsCheck,
    NoSqlInjectionCheck,
    HostHeaderCheck,
    CrlfInjectionCheck,
    XxeCheck,
    GraphqlCheck,
    TemplateCheck,
    BrowserDomXssCheck,
]


def all_checks() -> list[Check]:
    return [cls() for cls in _REGISTRY]


def checks_by_names(names: list[str]) -> list[Check]:
    wanted = {n.strip().lower() for n in names if n.strip()}
    return [cls() for cls in _REGISTRY if cls.name in wanted]


def available_names() -> list[str]:
    return [cls.name for cls in _REGISTRY]
