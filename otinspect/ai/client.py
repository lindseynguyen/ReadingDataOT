"""Minimal, hardened client for OpenAI-compatible chat endpoints (standard library only).

* TLS verification on by default, TLS 1.2 minimum, optional internal CA and mTLS.
* System proxy variables ignored; only the proxy set in the profile is used.
* Redirects refused (a redirect could send the prompt and key to another host).
* Endpoint policy (internal-only) re-checked before every request.
* Response size capped; error messages never contain the API key.
"""
from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from .config import AIConfigError, AIProfile, check_endpoint, get_api_key

MAX_RESPONSE_BYTES = 4 * 1024 * 1024
USER_AGENT = "OTInspect-AI/1"


class AIRequestError(RuntimeError):
    pass


@dataclass
class ChatResult:
    text: str
    model: str = ""
    usage: dict = field(default_factory=dict)
    finish_reason: str = ""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise AIRequestError(f"Endpoint answered with a redirect ({code}) to another location; refused. "
                             f"Set the final URL as base URL")


def _ssl_context(p: AIProfile) -> ssl.SSLContext:
    if p.verify_tls:
        ctx = ssl.create_default_context(cafile=p.ca_bundle or None)
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if p.client_cert:
        ctx.load_cert_chain(p.client_cert, p.client_key or None)
    return ctx


def _opener(p: AIProfile):
    proxies = {"http": p.proxy, "https": p.proxy} if p.proxy else {}
    return urllib.request.build_opener(
        urllib.request.ProxyHandler(proxies),          # {} = ignore HTTP(S)_PROXY from the environment
        urllib.request.HTTPSHandler(context=_ssl_context(p)),
        _NoRedirect())


def _scrub(text: str, key: str) -> str:
    if key and key in text:
        text = text.replace(key, "[API key]")
    return text


class ChatClient:
    def __init__(self, profile: AIProfile, api_key: str | None = None):
        profile.validate(resolve=False)
        if not profile.base_url:
            raise AIConfigError("No base URL configured")
        if not profile.model:
            raise AIConfigError("No model configured")
        self.p = profile
        self.key = api_key if api_key is not None else get_api_key(profile)

    # ------------------------------------------------------------------ urls / headers
    def _url(self, what: str) -> str:
        base = self.p.base_url.rstrip("/")
        if self.p.provider == "azure_openai":
            if what == "models":
                return f"{base}/openai/models?api-version={self.p.azure_api_version}"
            return (f"{base}/openai/deployments/{urllib.request.quote(self.p.model, safe='')}"
                    f"/chat/completions?api-version={self.p.azure_api_version}")
        return f"{base}/{what}"

    def _headers(self) -> dict[str, str]:
        h = {"Content-Type": "application/json", "Accept": "application/json", "User-Agent": USER_AGENT}
        h.update(self.p.extra_headers or {})
        if self.key:
            if self.p.provider == "azure_openai":
                h["api-key"] = self.key
            else:
                h["Authorization"] = f"Bearer {self.key}"
        return h

    # ------------------------------------------------------------------ transport
    def _request(self, method: str, url: str, body: dict | None = None) -> dict:
        check_endpoint(self.p)
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(url, data=data, method=method, headers=self._headers())
        try:
            with _opener(self.p).open(req, timeout=float(self.p.timeout_s)) as r:
                raw = r.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as e:
            detail = ""
            try:
                detail = e.read(2000).decode("utf-8", "replace")
                detail = json.loads(detail).get("error", {}).get("message", detail) if detail.startswith("{") else detail
            except Exception:
                pass
            hint = {401: "check the API key", 403: "the key is not allowed to use this model",
                    404: "check the base URL (LiteLLM usually ends with /v1) and the model name",
                    429: "rate limit or budget reached on the gateway"}.get(e.code, "")
            raise AIRequestError(_scrub(f"HTTP {e.code} from {self.p.host}"
                                        f"{': ' + hint if hint else ''}"
                                        f"{' - ' + str(detail)[:300] if detail else ''}", self.key)) from None
        except ssl.SSLError as e:
            raise AIRequestError(f"TLS error with {self.p.host}: {e.reason or e}. "
                                 f"For an internal CA, set the CA bundle in the profile") from None
        except urllib.error.URLError as e:
            reason = getattr(e, "reason", e)
            if isinstance(reason, AIRequestError):
                raise reason from None
            raise AIRequestError(_scrub(f"Cannot reach {self.p.host}: {reason}", self.key)) from None
        except TimeoutError:
            raise AIRequestError(f"Timed out after {self.p.timeout_s:g} s waiting for {self.p.host}") from None
        if len(raw) > MAX_RESPONSE_BYTES:
            raise AIRequestError("Response too large; refused")
        try:
            return json.loads(raw.decode("utf-8"))
        except ValueError:
            raise AIRequestError(f"{self.p.host} did not return JSON (is the base URL the API root?)") from None

    # ------------------------------------------------------------------ API
    def list_models(self) -> list[str]:
        d = self._request("GET", self._url("models"))
        return sorted(str(m.get("id", "")) for m in d.get("data", []) if isinstance(m, dict))

    def chat(self, messages: list[dict]) -> ChatResult:
        body = {"messages": messages, "max_tokens": int(self.p.max_tokens),
                "temperature": float(self.p.temperature), "stream": False}
        if self.p.provider != "azure_openai":
            body["model"] = self.p.model
        if self.p.user_tag:
            body["user"] = self.p.user_tag
        d = self._request("POST", self._url("chat/completions"), body)
        try:
            ch = d["choices"][0]
            text = ch["message"].get("content") or ""
        except (KeyError, IndexError, TypeError, AttributeError):
            raise AIRequestError("Unexpected response format (no choices[0].message)") from None
        if not isinstance(text, str):
            text = json.dumps(text, ensure_ascii=False)
        return ChatResult(text=text, model=str(d.get("model", self.p.model)),
                          usage=d.get("usage") or {}, finish_reason=str(ch.get("finish_reason", "")))
