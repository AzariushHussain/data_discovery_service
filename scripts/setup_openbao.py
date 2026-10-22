"""Interactive local setup; no automatic unsealing or background token rotation."""
import getpass
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import warnings
from urllib.error import HTTPError, URLError
from urllib.request import Request, build_opener, ProxyHandler, HTTPRedirectHandler

ROOT = Path(__file__).resolve().parent.parent
SECRETS = ROOT / ".secrets"
TOKEN_FILE = SECRETS / "openbao-token.txt"
INIT_FILE = SECRETS / "openbao-init.json"


class SetupError(Exception):
    pass


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # Never forward administrative credentials to another address.


def compose(*args, capture=False):
    result = subprocess.run(
        ["docker", "compose", *args], cwd=ROOT, check=True, text=True,
        stdout=subprocess.PIPE if capture else None,
    )
    return result.stdout.strip() if capture else None


def request(address, method, path, token=None, payload=None, timeout=10):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Vault-Token"] = token
    data = json.dumps(payload).encode() if payload is not None else None
    # Local loopback traffic must not send credentials through environment proxies.
    opener = build_opener(ProxyHandler({}), NoRedirects())
    try:
        with opener.open(Request(f"{address}/v1/{path}", data=data, headers=headers, method=method), timeout=timeout) as response:
            body = response.read()
            return json.loads(body) if body else {}
    except HTTPError as exc:
        raise SetupError(f"OpenBao {path} returned HTTP {exc.code}.") from None
    except (URLError, TimeoutError, OSError):
        raise SetupError("OpenBao could not be reached; check its container logs.") from None


def write_token(token):
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", dir=SECRETS, delete=False) as stream:
            temporary = Path(stream.name)
            os.chmod(temporary, 0o600)
            stream.write(token)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(TOKEN_FILE)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def prompt_secret(message):
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        try:
            return getpass.getpass(message).strip()
        except getpass.GetPassWarning:
            raise SetupError("Use an interactive terminal for hidden credential prompts.") from None


def setup():
    compose("version", capture=True)
    SECRETS.mkdir(mode=0o700, exist_ok=True)
    SECRETS.chmod(0o700)
    # Compose requires this file even before the application container is started.
    descriptor = os.open(TOKEN_FILE, os.O_WRONLY | os.O_CREAT, 0o600)
    os.close(descriptor)
    TOKEN_FILE.chmod(0o600)
    compose("config", "--quiet")
    compose("run", "--rm", "--no-deps", "--user", "root", "--entrypoint", "sh", "openbao",
            "-c", "chown -R openbao:openbao /bao/data && chmod 700 /bao/data")
    compose("up", "-d", "openbao")
    binding = compose("port", "openbao", "8200", capture=True).splitlines()[0]
    _, _, port = binding.rpartition(":")
    if not port.isdigit():
        raise SetupError("Could not determine OpenBao's published local port.")
    address = f"http://127.0.0.1:{port}"
    for attempt in range(60):
        try:
            initialized = request(address, "GET", "sys/init")["initialized"]
            break
        except SetupError:
            if attempt == 59:
                raise SetupError("OpenBao did not start within one minute.") from None
            time.sleep(1)

    admin_token = None
    initial_key = None
    if not initialized:
        # Reserve a private file before initialization; never overwrite saved recovery data.
        try:
            descriptor = os.open(INIT_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            raise SetupError("Recovery file already exists for an uninitialized vault. Check matching data/credentials; nothing was reset.") from None
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            credentials = request(address, "POST", "sys/init",
                                  payload={"secret_shares": 1, "secret_threshold": 1}, timeout=120)
            json.dump(credentials, stream)
            stream.flush()
            os.fsync(stream.fileno())
        print(f"New vault initialized. Recovery credentials saved to {INIT_FILE}.")
        print("Back up that file in your password manager, then remove the local recovery copy.")
        admin_token = credentials["root_token"]
        initial_key = (credentials.get("keys_base64") or credentials["keys"])[0]

    status = request(address, "GET", "sys/seal-status")
    while status["sealed"]:
        key = initial_key or prompt_secret("Saved unseal key (hidden): ")
        initial_key = None
        if not key:
            raise SetupError("An unseal key is required; existing data was preserved.")
        status = request(address, "POST", "sys/unseal", payload={"key": key})
    # Raft may be unsealed before its active node is ready for writes.
    for attempt in range(60):
        try:
            request(address, "GET", "sys/health")
            break
        except SetupError:
            if attempt == 59:
                raise SetupError("OpenBao did not become active within one minute.") from None
            time.sleep(1)

    admin_token = admin_token or prompt_secret("Administrator token (hidden): ")
    if not admin_token:
        raise SetupError("An administrator token is required.")
    mounts = request(address, "GET", "sys/mounts", admin_token)
    mounts = mounts.get("data", mounts)
    mount = mounts.get("discovery/")
    if mount is None:
        request(address, "POST", "sys/mounts/discovery", admin_token,
                {"type": "kv", "options": {"version": "2"}})
    elif mount["type"] != "kv" or str(mount.get("options", {}).get("version")) != "2":
        raise SetupError("Existing discovery mount is not KV v2. It was not replaced.")
    policy = (ROOT / "openbao" / "discovery-policy.hcl").read_text(encoding="utf-8")
    request(address, "PUT", "sys/policies/acl/discovery-service", admin_token, {"policy": policy})
    result = request(address, "POST", "auth/token/create", admin_token, {
        "display_name": "discovery-api", "policies": ["discovery-service"],
        "no_default_policy": True, "ttl": "24h", "explicit_max_ttl": "24h",
        "renewable": False,
    })
    auth = result["auth"]
    if set(auth["policies"]) != {"discovery-service"} or not auth["client_token"]:
        raise SetupError("Unexpected application token permissions; token file was not replaced.")
    write_token(auth["client_token"])
    print("Restricted application token written. Starting the app with its updated file mount.")
    compose("up", "-d", "--build", "--force-recreate", "app")
    print("Setup complete. API: http://localhost:8000/docs")
    print("Rerun this command after OpenBao restarts or before the 24-hour app token expires.")


if __name__ == "__main__":
    os.umask(0o077)
    try:
        setup()
    except SetupError as exc:
        print(f"Setup stopped: {exc}", file=sys.stderr)
        sys.exit(1)
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError):
        print("Setup stopped. Check Docker, file permissions, and the README. Credential values were not logged.", file=sys.stderr)
        sys.exit(1)
    except (KeyboardInterrupt, EOFError):
        print("\nSetup cancelled. Existing vault data was preserved.", file=sys.stderr)
        sys.exit(1)
