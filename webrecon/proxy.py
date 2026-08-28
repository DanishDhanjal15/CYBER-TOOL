"""An intercepting HTTP(S) proxy that logs all traffic (ZAP-style).

Point your browser at it (default 127.0.0.1:8081) and every request/response
is captured and written to a HAR file you can open in Chrome DevTools or Burp.

  * HTTP        — fully logged (method, URL, headers, body, response).
  * HTTPS       — tunnelled by default (host/SNI logged, content encrypted).
  * HTTPS + --mitm — decrypted and fully logged, by generating a local CA and
                     per-host certificates (needs the `cryptography` package;
                     import the CA into your browser to avoid TLS warnings).

Authorized use only — proxy traffic you own or are permitted to intercept.
"""
from __future__ import annotations

import select
import socket
import ssl
import threading
import time
from urllib.parse import urlparse

import requests

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import datetime as _dt
    import ipaddress
    _HAS_CRYPTO = True
except Exception:  # pragma: no cover
    _HAS_CRYPTO = False


class _CertAuthority:
    """Generates a CA + on-the-fly leaf certs for MITM."""
    def __init__(self, workdir):
        from pathlib import Path
        self.dir = Path(workdir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self._cache: dict[str, tuple] = {}
        self._lock = threading.Lock()
        self.ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "WebRecon Proxy CA")])
        now = _dt.datetime.utcnow()
        self.ca_cert = (x509.CertificateBuilder().subject_name(name)
                        .issuer_name(name).public_key(self.ca_key.public_key())
                        .serial_number(x509.random_serial_number())
                        .not_valid_before(now - _dt.timedelta(days=1))
                        .not_valid_after(now + _dt.timedelta(days=3650))
                        .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                                       critical=True)
                        .sign(self.ca_key, hashes.SHA256()))
        self.ca_path = self.dir / "webrecon-ca.crt"
        self.ca_path.write_bytes(self.ca_cert.public_bytes(serialization.Encoding.PEM))

    def context_for(self, host: str) -> ssl.SSLContext:
        with self._lock:
            if host not in self._cache:
                self._cache[host] = self._make(host)
            cert_pem, key_pem = self._cache[host]
        import tempfile
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # write to temp files (SSLContext needs paths)
        cf = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
        cf.write(key_pem + cert_pem); cf.close()
        ctx.load_cert_chain(cf.name)
        return ctx

    def _make(self, host: str):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
        now = _dt.datetime.utcnow()
        try:
            san = x509.IPAddress(ipaddress.ip_address(host))
        except ValueError:
            san = x509.DNSName(host)
        cert = (x509.CertificateBuilder().subject_name(subject)
                .issuer_name(self.ca_cert.subject).public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - _dt.timedelta(days=1))
                .not_valid_after(now + _dt.timedelta(days=825))
                .add_extension(x509.SubjectAlternativeName([san]), critical=False)
                .sign(self.ca_key, hashes.SHA256()))
        return (cert.public_bytes(serialization.Encoding.PEM),
                key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.TraditionalOpenSSL,
                                  serialization.NoEncryption()))


class _Proxy:
    def __init__(self, mitm=False, ca=None, log=None):
        self.mitm = mitm and _HAS_CRYPTO
        self.ca = ca
        self.transactions: list[dict] = log if log is not None else []
        self._lock = threading.Lock()

    def _log(self, txn):
        with self._lock:
            self.transactions.append(txn)

    def _forward_http(self, method, url, headers, body):
        headers.pop("Proxy-Connection", None)
        t0 = time.monotonic()
        try:
            r = requests.request(method, url, headers=headers, data=body or None,
                                 allow_redirects=False, timeout=25, verify=False)
        except Exception as exc:
            return None, str(exc)
        self._log({
            "method": method, "url": url, "req_headers": headers,
            "req_body": (body or b"").decode("latin-1", "replace")[:12000],
            "status": r.status_code, "resp_headers": dict(r.headers),
            "resp_body": (r.text or "")[:12000],
            "time_ms": round((time.monotonic() - t0) * 1000, 1)})
        return r, None


def _read_request(rfile):
    line = rfile.readline()
    if not line:
        return None
    parts = line.decode("latin-1").split()
    if len(parts) < 2:
        return None
    method, target = parts[0], parts[1]
    headers = {}
    while True:
        h = rfile.readline()
        if h in (b"\r\n", b"\n", b""):
            break
        try:
            k, v = h.decode("latin-1").split(":", 1)
            headers[k.strip()] = v.strip()
        except ValueError:
            continue
    body = b""
    clen = int(headers.get("Content-Length", 0) or 0)
    if clen:
        body = rfile.read(clen)
    return method, target, headers, body


def _handle(conn, proxy: _Proxy, console):
    try:
        rfile = conn.makefile("rb")
        parsed = _read_request(rfile)
        if not parsed:
            return
        method, target, headers, body = parsed

        if method == "CONNECT":                          # HTTPS
            host, _, port = target.partition(":")
            port = int(port or 443)
            if proxy.mitm:
                _mitm_https(conn, rfile, host, port, proxy, console)
            else:
                _tunnel(conn, host, port, proxy, console)
            return

        # Plain HTTP (absolute-form URL)
        url = target if target.startswith("http") else f"http://{headers.get('Host','')}{target}"
        r, err = proxy._forward_http(method, url, headers, body)
        if console:
            code = r.status_code if r else "ERR"
            console.print(f"[dim]{method}[/] {url}  [cyan]{code}[/]")
        if r is None:
            conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n" + (err or "").encode())
            return
        out = f"HTTP/1.1 {r.status_code}\r\n".encode()
        for k, v in r.headers.items():
            if k.lower() in ("transfer-encoding", "content-encoding", "connection"):
                continue
            out += f"{k}: {v}\r\n".encode()
        body_b = r.content
        out += f"Content-Length: {len(body_b)}\r\nConnection: close\r\n\r\n".encode()
        conn.sendall(out + body_b)
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _tunnel(conn, host, port, proxy, console):
    try:
        upstream = socket.create_connection((host, port), timeout=15)
    except Exception:
        conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        return
    conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
    proxy._log({"method": "CONNECT", "url": f"https://{host}:{port}",
                "req_headers": {}, "req_body": "", "status": 200,
                "resp_headers": {}, "resp_body": "[encrypted tunnel — use --mitm to decrypt]",
                "time_ms": 0})
    if console:
        console.print(f"[dim]CONNECT[/] {host}:{port} [yellow](tunnelled)[/]")
    socks = [conn, upstream]
    try:
        while True:
            r, _, _ = select.select(socks, [], [], 30)
            if not r:
                break
            for s in r:
                data = s.recv(8192)
                if not data:
                    return
                (upstream if s is conn else conn).sendall(data)
    except Exception:
        pass
    finally:
        upstream.close()


def _mitm_https(conn, rfile, host, port, proxy, console):
    conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
    try:
        ctx = proxy.ca.context_for(host)
        tls_conn = ctx.wrap_socket(conn, server_side=True)
    except Exception:
        return
    try:
        creq = _read_request(tls_conn.makefile("rb"))
        if not creq:
            return
        method, target, headers, body = creq
        url = f"https://{host}:{port}{target}" if not target.startswith("http") \
            else target
        r, err = proxy._forward_http(method, url, headers, body)
        if console:
            code = r.status_code if r else "ERR"
            console.print(f"[dim]{method}[/] {url}  [green]{code}[/] [dim](mitm)[/]")
        if r is None:
            tls_conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            return
        out = f"HTTP/1.1 {r.status_code}\r\n".encode()
        for k, v in r.headers.items():
            if k.lower() in ("transfer-encoding", "content-encoding", "connection"):
                continue
            out += f"{k}: {v}\r\n".encode()
        out += f"Content-Length: {len(r.content)}\r\nConnection: close\r\n\r\n".encode()
        tls_conn.sendall(out + r.content)
    except Exception:
        pass
    finally:
        try:
            tls_conn.close()
        except Exception:
            pass


def run_proxy(host="127.0.0.1", port=8081, out="proxy-traffic.har",
              mitm=False, console=None) -> int:
    import urllib3
    urllib3.disable_warnings()
    ca = None
    if mitm:
        if not _HAS_CRYPTO:
            if console:
                console.print("[red]--mitm needs the 'cryptography' package "
                              "(pip install cryptography). Falling back to "
                              "tunnel mode.[/]")
            mitm = False
        else:
            ca = _CertAuthority(".webrecon-proxy")
    proxy = _Proxy(mitm=mitm, ca=ca)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((host, port))
    except OSError as exc:
        if console:
            console.print(f"[red]Cannot bind {host}:{port}: {exc}[/]")
        return 2
    srv.listen(50)

    if console:
        console.print(f"[bold cyan]Proxy listening on {host}:{port}[/]")
        console.print(f"Set your browser's HTTP/HTTPS proxy to [bold]{host}:{port}[/]")
        if mitm:
            console.print(f"[yellow]MITM on[/] — trust the CA at "
                          f".webrecon-proxy/webrecon-ca.crt in your browser.")
        else:
            console.print("[dim]HTTPS is tunnelled (metadata only). Use --mitm to "
                          "decrypt.[/]")
        console.print(f"[dim]Traffic → {out}. Press Ctrl+C to stop & save.[/]\n")

    try:
        while True:
            conn, _ = srv.accept()
            threading.Thread(target=_handle, args=(conn, proxy, console),
                             daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        srv.close()
        _save_har(proxy.transactions, out, console)
    return 0


def _save_har(transactions, out, console):
    class _R:
        pass
    r = _R()
    r.transactions = transactions
    from webrecon.report import har_report
    from pathlib import Path
    har_report.write(r, Path(out))
    if console:
        console.print(f"\n[green]Saved {len(transactions)} transaction(s) → "
                      f"{out}[/]")
