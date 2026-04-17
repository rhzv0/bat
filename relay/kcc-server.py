#!/usr/bin/env python3
"""
KCC -- Kernel Compilation Center
Compila bat-stealth.ko para o kernel exato do target.

Portas:
  :8444 TCP   -- bat-server diagnostic via SSH tunnel (localhost only)
  :9444 HTTPS -- agente direto; HMAC-SHA256 auth via X-KCC-Token header
"""

import asyncio, json, hashlib, hmac as py_hmac, os, base64, logging, ssl, subprocess, tempfile
from pathlib import Path

CACHE_DIR    = Path("/root/kcc/cache")
SRC_DIR      = Path("/root/kcc/kperf-qos-src")
BUILD_SCRIPT = Path("/root/kcc/kcc-build.sh")
ENV_FILE     = Path("/root/kcc/.env")
LOG          = logging.getLogger("kcc")

# Shared secret for KCC HTTPS auth -- loaded from /root/kcc/.env at startup
KCC_SECRET = ""


async def _do_compile(kernel_version: str, arch: str, config_hash: str) -> dict:
    """Shared compile logic for both TCP and HTTPS handlers."""
    if not kernel_version or not arch:
        return {"status": "error", "msg": "missing kernel_version or arch"}

    cache_key = hashlib.sha256(
        f"{kernel_version}:{arch}:{config_hash}".encode()
    ).hexdigest()[:16]
    cached_ko = CACHE_DIR / f"{cache_key}.ko"

    if cached_ko.exists():
        LOG.info(f"Cache hit: {cache_key} ({kernel_version}/{arch})")
        ko_bytes = cached_ko.read_bytes()
        cached = True
    else:
        LOG.info(f"Cache miss: compiling for {kernel_version}/{arch}")
        proc = await asyncio.create_subprocess_exec(
            str(BUILD_SCRIPT), kernel_version, arch, str(cached_ko),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=600)
        except asyncio.TimeoutError:
            proc.kill()
            return {"status": "error", "msg": "build timeout (600s)"}
        if proc.returncode != 0:
            err_msg = stderr.decode()[-500:]
            LOG.error(f"Build failed for {kernel_version}/{arch}: {err_msg[-120:]}")
            return {"status": "error", "msg": err_msg}
        ko_bytes = cached_ko.read_bytes()
        cached = False

    ko_sha256 = hashlib.sha256(ko_bytes).hexdigest()
    LOG.info(f"Delivered {len(ko_bytes)} bytes ({cache_key}, cached={cached})")
    return {
        "status":    "ok",
        "ko_b64":    base64.b64encode(ko_bytes).decode(),
        "ko_sha256": ko_sha256,
        "cached":    cached,
        "msg":       "",
    }


async def handle_request(reader, writer):
    """TCP handler for localhost:8444 -- bat-server diagnostic via SSH tunnel.
    Protocol: raw JSON + EOF (CloseWrite) -> JSON response.
    """
    try:
        data = await reader.read(-1)
        if not data:
            writer.close()
            return
        req = json.loads(data)
    except Exception as e:
        LOG.warning(f"TCP bad request: {e}")
        writer.close()
        return

    resp = await _do_compile(
        req.get("kernel_version", ""),
        req.get("arch", ""),
        req.get("config_hash", "nohash"),
    )
    writer.write(json.dumps(resp).encode())
    await writer.drain()
    writer.close()


async def handle_https_agent(reader, writer):
    """HTTPS handler for 0.0.0.0:9444 -- agent direct access.
    Protocol: HTTP/1.1 POST /compile with X-KCC-Token HMAC auth.
    Auth: X-KCC-Token = HMAC-SHA256(secret, hex(body_bytes))
    """
    try:
        # Parse request line
        request_line = (await reader.readline()).decode(errors="replace").strip()
        if not request_line:
            writer.close()
            return
        parts = request_line.split()
        if len(parts) < 2 or parts[0] != "POST" or parts[1] != "/compile":
            writer.write(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
            writer.close()
            return

        # Parse headers
        headers = {}
        while True:
            line = (await reader.readline()).decode(errors="replace").strip()
            if not line:
                break
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()

        content_length = int(headers.get("content-length", 0))
        body = await reader.readexactly(content_length)

        # Verify HMAC-SHA256(secret, hex(body)) if secret is configured
        if KCC_SECRET:
            expected = py_hmac.new(
                KCC_SECRET.encode(), body.hex().encode(), hashlib.sha256
            ).hexdigest()
            token = headers.get("x-kcc-token", "")
            if not py_hmac.compare_digest(expected, token):
                writer.write(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n")
                await writer.drain()
                writer.close()
                LOG.warning("HTTPS: auth failed (bad X-KCC-Token)")
                return

        try:
            req = json.loads(body)
        except Exception:
            resp_body = json.dumps({"status": "error", "msg": "invalid JSON"}).encode()
            _write_http_response(writer, 400, resp_body)
            await writer.drain()
            writer.close()
            return

        resp = await _do_compile(
            req.get("kernel_version", ""),
            req.get("arch", ""),
            req.get("config_hash", "nohash"),
        )
        resp_body = json.dumps(resp).encode()
        _write_http_response(writer, 200, resp_body)
        await writer.drain()
        writer.close()

    except Exception as e:
        LOG.warning(f"HTTPS handler error: {e}")
        try:
            writer.close()
        except Exception:
            pass


def _write_http_response(writer, status: int, body: bytes):
    status_text = {200: "OK", 400: "Bad Request", 401: "Unauthorized", 404: "Not Found"}.get(status, "Error")
    header = (
        f"HTTP/1.1 {status} {status_text}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"\r\n"
    ).encode()
    writer.write(header + body)


def _gen_tls_context() -> ssl.SSLContext:
    """Generate a self-signed TLS context for the HTTPS server."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # Generate self-signed cert in temporary files, load, then delete
    cert_f = tempfile.NamedTemporaryFile(suffix=".pem", delete=False)
    key_f  = tempfile.NamedTemporaryFile(suffix=".pem", delete=False)
    cert_f.close()
    key_f.close()
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", key_f.name, "-out", cert_f.name,
            "-days", "365", "-subj", "/CN=kcc",
        ],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    ctx.load_cert_chain(cert_f.name, key_f.name)
    os.unlink(cert_f.name)
    os.unlink(key_f.name)
    return ctx


async def main():
    global KCC_SECRET

    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    if not BUILD_SCRIPT.exists():
        LOG.error(f"Build script not found: {BUILD_SCRIPT}")
        raise SystemExit(1)
    if not SRC_DIR.exists():
        LOG.error(f"Source dir not found: {SRC_DIR}")
        raise SystemExit(1)

    # Load HMAC secret from /root/kcc/.env (KCC_SECRET=<hex>)
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text().splitlines():
            if line.startswith("KCC_SECRET="):
                KCC_SECRET = line.split("=", 1)[1].strip()
    if not KCC_SECRET:
        KCC_SECRET = os.environ.get("KCC_SECRET", "")
    if KCC_SECRET:
        LOG.info("HMAC auth enabled for HTTPS endpoint")
    else:
        LOG.warning("KCC_SECRET not set -- HTTPS endpoint has NO auth")

    # TCP server for bat-server diagnostic (localhost:8444 via SSH tunnel)
    tcp_server = await asyncio.start_server(handle_request, "127.0.0.1", 8444)
    LOG.info(f"KCC TCP listening on localhost:8444 (cache={CACHE_DIR})")

    # HTTPS server for agent direct access (0.0.0.0:9444)
    ssl_ctx = _gen_tls_context()
    https_server = await asyncio.start_server(
        handle_https_agent, "0.0.0.0", 9444, ssl=ssl_ctx)
    LOG.info("KCC HTTPS listening on 0.0.0.0:9444")

    async with tcp_server, https_server:
        await asyncio.gather(
            tcp_server.serve_forever(),
            https_server.serve_forever(),
        )


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [KCC] %(levelname)s %(message)s",
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler("/var/log/kcc.log"),
        ],
    )
    asyncio.run(main())
