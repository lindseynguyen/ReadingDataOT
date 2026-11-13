"""AI connection profiles (internal / self-hosted models only by default).

A profile describes how OTInspect reaches an OpenAI-compatible endpoint: a LiteLLM
AI gateway, vLLM, Ollama, LM Studio, LocalAI or Azure OpenAI. Profiles are stored in
``~/.otinspect/ai_profiles.json`` (override with ``OTINSPECT_AI_CONFIG``).

Security rules enforced here:

* API keys are never written to the profile file. They come from the OS keyring
  (optional ``keyring`` package), an environment variable, or memory for the session.
* HTTPS is required, except for loopback addresses or when plain HTTP is explicitly
  allowed for a lab endpoint.
* ``internal_only`` (default on) refuses endpoints that resolve to a public IP address,
  unless the host is listed in ``allowed_hosts``.
* System proxy variables are ignored unless a proxy is set in the profile, so traffic
  cannot silently leave through a corporate or malicious proxy.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import stat
from dataclasses import asdict, dataclass, field, fields
from typing import Any
from urllib.parse import urlsplit

PROVIDERS = {
    "litellm": "LiteLLM AI gateway (OpenAI-compatible)",
    "openai_compatible": "OpenAI-compatible server (vLLM, Ollama, LM Studio, LocalAI, TGI)",
    "azure_openai": "Azure OpenAI (private endpoint)",
}
SECRET_STORES = ("keyring", "env", "session")
KEYRING_SERVICE = "otinspect-ai"
DEFAULT_PATH = os.path.join(os.path.expanduser("~"), ".otinspect", "ai_profiles.json")
_HEADER_NAME = re.compile(r"^[A-Za-z0-9-]{1,64}$")
_FORBIDDEN_HEADERS = {"authorization", "api-key", "x-api-key", "cookie", "proxy-authorization",
                      "host", "content-length", "transfer-encoding"}
_SESSION_KEYS: dict[str, str] = {}


class AIConfigError(ValueError):
    """Invalid or unsafe AI profile."""


@dataclass
class AIProfile:
    name: str = "default"
    provider: str = "litellm"
    base_url: str = ""                       # e.g. https://llm-gateway.internal.example/v1
    model: str = ""                          # LiteLLM model alias / deployment name
    azure_api_version: str = "2024-10-21"    # Azure OpenAI only
    # --- credentials (never stored in this file)
    secret_store: str = "env"                # keyring | env | session
    api_key_env: str = "OTINSPECT_AI_API_KEY"
    # --- request
    timeout_s: float = 60.0
    max_tokens: int = 1500
    temperature: float = 0.2
    user_tag: str = ""                       # LiteLLM "user" field for spend / audit tracking
    extra_headers: dict[str, str] = field(default_factory=dict)   # non-secret, e.g. x-litellm-tags
    # --- transport security
    verify_tls: bool = True
    ca_bundle: str = ""                      # internal CA (PEM)
    client_cert: str = ""                    # mTLS certificate (PEM)
    client_key: str = ""                     # mTLS private key (PEM, unencrypted or via OS store)
    proxy: str = ""                          # empty = direct connection, system proxy ignored
    allow_http: bool = False                 # plain HTTP only for a lab endpoint you accept the risk for
    internal_only: bool = True               # refuse endpoints resolving to public IPs
    allowed_hosts: list[str] = field(default_factory=list)
    # --- data minimisation
    mask_ips: bool = True
    mask_macs: bool = True
    mask_names: bool = True                  # asset names, hostnames, IED / PLC names
    mask_paths: bool = True                  # file paths -> file type only
    mask_secrets: bool = True                # always recommended
    max_findings: int = 150
    max_assets: int = 150
    max_prompt_chars: int = 60000
    confirm_before_send: bool = True         # GUI shows the exact payload first
    # --- audit
    audit_log: bool = True                   # metadata only (hashes, sizes, status), never content
    audit_log_path: str = ""                 # default ~/.otinspect/ai_audit.jsonl

    # ------------------------------------------------------------------ helpers
    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> AIProfile:
        known = {f.name for f in fields(cls)}
        clean = {k: v for k, v in d.items() if k in known}
        for bad in ("api_key", "key", "password", "token", "secret"):
            if bad in d:
                raise AIConfigError(f"Profile contains '{bad}': store API keys in the OS keyring "
                                    f"or an environment variable, never in the profile file")
        p = cls(**clean)
        p.validate(resolve=False)
        return p

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def host(self) -> str:
        return (urlsplit(self.base_url).hostname or "").lower()

    def audit_path(self) -> str:
        return self.audit_log_path or os.path.join(os.path.dirname(config_path()), "ai_audit.jsonl")

    def validate(self, resolve: bool = True) -> None:
        if not re.fullmatch(r"[\w .-]{1,64}", self.name or ""):
            raise AIConfigError("Profile name: 1-64 letters, digits, space, dot, dash or underscore")
        if self.provider not in PROVIDERS:
            raise AIConfigError(f"Unknown provider {self.provider!r}")
        if self.secret_store not in SECRET_STORES:
            raise AIConfigError(f"secret_store must be one of {', '.join(SECRET_STORES)}")
        if self.secret_store == "env" and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", self.api_key_env or ""):
            raise AIConfigError("api_key_env must be an environment variable name")
        if not self.base_url:
            return                       # incomplete profile may be saved, not used
        u = urlsplit(self.base_url)
        if u.scheme not in ("https", "http") or not u.hostname:
            raise AIConfigError("Base URL must look like https://host[:port]/path")
        if u.username or u.password:
            raise AIConfigError("Do not put credentials in the base URL")
        if u.query or u.fragment:
            raise AIConfigError("Base URL must not contain a query string or fragment")
        if u.scheme == "http" and not (self.allow_http or _is_loopback_name(u.hostname)):
            raise AIConfigError("Plain HTTP would expose prompts and the API key on the network; "
                                "use HTTPS or explicitly allow HTTP for a lab endpoint")
        if not (1 <= float(self.timeout_s) <= 600):
            raise AIConfigError("Timeout must be between 1 and 600 seconds")
        if not (16 <= int(self.max_tokens) <= 32000):
            raise AIConfigError("Max tokens must be between 16 and 32000")
        if not (0 <= float(self.temperature) <= 2):
            raise AIConfigError("Temperature must be between 0 and 2")
        if self.provider == "azure_openai" and not self.model:
            raise AIConfigError("Azure OpenAI needs the deployment name in 'model'")
        for k, v in (self.extra_headers or {}).items():
            if not _HEADER_NAME.match(k) or k.lower() in _FORBIDDEN_HEADERS:
                raise AIConfigError(f"Header {k!r} is not allowed here (use the secret store for keys)")
            if any(c in str(v) for c in "\r\n") or len(str(v)) > 1024:
                raise AIConfigError(f"Invalid value for header {k!r}")
        if self.proxy:
            pu = urlsplit(self.proxy)
            if pu.scheme not in ("http", "https") or not pu.hostname:
                raise AIConfigError("Proxy must be http(s)://host:port")
            if pu.username or pu.password:
                raise AIConfigError("Do not put proxy credentials in the profile")
        for p in (self.ca_bundle, self.client_cert, self.client_key):
            if p and not os.path.isfile(p):
                raise AIConfigError(f"File not found: {p}")
        if bool(self.client_cert) != bool(self.client_key) and self.client_key:
            raise AIConfigError("A client key needs a client certificate")
        if resolve:
            check_endpoint(self)


# ---------------------------------------------------------------------- endpoint policy
def _is_loopback_name(host: str) -> bool:
    if host in ("localhost", "localhost.localdomain"):
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


_INTERNAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",      # RFC 1918
    "100.64.0.0/10",                                       # CGNAT / overlay VPNs
    "127.0.0.0/8", "169.254.0.0/16",                       # loopback, link-local
    "::1/128", "fc00::/7", "fe80::/10")]                   # IPv6 loopback, ULA, link-local


def _is_internal(ip: str) -> bool:
    a = ipaddress.ip_address(ip.split("%", 1)[0])
    if getattr(a, "ipv4_mapped", None):
        a = a.ipv4_mapped
    return any(a in n for n in _INTERNAL_NETS if n.version == a.version)


def _host_allowed(host: str, allowed: list[str]) -> bool:
    for a in allowed or []:
        a = a.strip().lower()
        if a and (host == a or (a.startswith("*.") and host.endswith(a[1:]))):
            return True
    return False


def resolve_host(host: str) -> list[str]:
    try:
        return sorted({ai[4][0] for ai in socket.getaddrinfo(host, None)})
    except OSError as e:
        raise AIConfigError(f"Cannot resolve {host}: {e}") from None


def check_endpoint(p: AIProfile) -> list[str]:
    """Raise AIConfigError if the endpoint breaks the internal-only policy.

    Returns the resolved addresses (shown in the GUI test result)."""
    host = p.host
    if not host:
        raise AIConfigError("No base URL configured")
    ips = resolve_host(host.strip("[]"))
    if p.internal_only and not _host_allowed(host, p.allowed_hosts):
        public = [ip for ip in ips if not _is_internal(ip)]
        if public:
            raise AIConfigError(
                f"{host} resolves to public address(es) {', '.join(public)}. Internal-only mode is on: "
                f"use an internal endpoint, or add the host to 'Allowed hosts' if this is intended")
    return ips


# ---------------------------------------------------------------------- storage
def config_path() -> str:
    return os.environ.get("OTINSPECT_AI_CONFIG") or DEFAULT_PATH


def load_profiles(path: str | None = None) -> dict[str, AIProfile]:
    path = path or config_path()
    if not os.path.isfile(path):
        return {}
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict) or not isinstance(data.get("profiles", []), list):
        raise AIConfigError(f"{path}: expected {{'profiles': [...]}}")
    out = {}
    for d in data.get("profiles", []):
        p = AIProfile.from_dict(d)
        out[p.name] = p
    return out


def default_profile_name(path: str | None = None) -> str:
    path = path or config_path()
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh).get("default", "")
    except (OSError, ValueError, AttributeError):
        return ""


def save_profiles(profiles: dict[str, AIProfile], default: str = "", path: str | None = None) -> str:
    path = path or config_path()
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    for p in profiles.values():
        p.validate(resolve=False)
    data = {"version": 1, "default": default if default in profiles else next(iter(profiles), ""),
            "profiles": [p.to_dict() for p in profiles.values()]}
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
    os.replace(tmp, path)
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    return path


def get_profile(name: str | None = None, path: str | None = None) -> AIProfile:
    profiles = load_profiles(path)
    if not profiles:
        raise AIConfigError(f"No AI profile configured ({path or config_path()}). "
                            f"Create one in the GUI (AI settings) or with 'otinspect ai init'")
    name = name or default_profile_name(path) or next(iter(profiles))
    if name not in profiles:
        raise AIConfigError(f"Unknown AI profile {name!r}; available: {', '.join(profiles)}")
    return profiles[name]


# ---------------------------------------------------------------------- secrets
def _keyring():
    try:
        import keyring  # optional dependency
        return keyring
    except Exception:
        return None


def keyring_available() -> bool:
    return _keyring() is not None


def set_api_key(p: AIProfile, key: str) -> str:
    """Store the key according to the profile; returns where it went (for the UI)."""
    key = (key or "").strip()
    if p.secret_store == "keyring":
        kr = _keyring()
        if not kr:
            raise AIConfigError("The 'keyring' package is not installed; choose environment "
                                "variable or session-only storage, or pip install keyring")
        if key:
            kr.set_password(KEYRING_SERVICE, p.name, key)
        else:
            try:
                kr.delete_password(KEYRING_SERVICE, p.name)
            except Exception:
                pass
        return "OS keyring"
    if p.secret_store == "session":
        if key:
            _SESSION_KEYS[p.name] = key
        else:
            _SESSION_KEYS.pop(p.name, None)
        return "memory (this session only)"
    return f"environment variable {p.api_key_env} (set it outside OTInspect)"


def get_api_key(p: AIProfile) -> str:
    if p.secret_store == "keyring":
        kr = _keyring()
        return (kr.get_password(KEYRING_SERVICE, p.name) or "") if kr else ""
    if p.secret_store == "session":
        return _SESSION_KEYS.get(p.name, "")
    return os.environ.get(p.api_key_env, "")


def template_profile() -> AIProfile:
    return AIProfile(name="internal-gateway", provider="litellm",
                     base_url="https://llm-gateway.internal.example/v1", model="ot-analyst",
                     user_tag="otinspect", extra_headers={"x-litellm-tags": "otinspect"})
