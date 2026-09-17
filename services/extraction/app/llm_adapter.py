"""Hosted-model adapter — the served-LLM seam behind the schema gate.

Speaks the OpenAI-compatible chat API (the de-facto standard): works
against hosted frontier APIs in the SaaS profile AND local vLLM in the
Compact/air-gap profile — same client, different base URL. The adapter is
deliberately dumb: it carries a prompt pair in, raw text out. EVERYTHING
that matters for safety happens after it returns (JSON parse, schema
gate, corroboration) and before it is called (prompt treats the document
as delimited untrusted data).

Env:
    TRUVO_LLM_BASE_URL  e.g. https://api.openai.com/v1  (required)
    TRUVO_LLM_API_KEY   bearer token                    (optional for local vLLM)
    TRUVO_LLM_MODEL     model name                      (required)
    TRUVO_LLM_TIMEOUT   seconds, default 120
    TRUVO_LLM_MAX_TOKENS      request cap, default 4096 (C2)
    TRUVO_LLM_MAX_RESP_BYTES  hard parse cap, default 524288 (C2)
    TRUVO_LLM_BUDGET_TOKENS   cumulative budget; 0 = unlimited (C2)
    TRUVO_LLM_JSON_MODE "1" to request JSON response format where supported
    TRUVO_LLM_THINKING  "disabled" to turn off reasoning modes (GLM-4.5+):
                        extraction is bounded JSON work — thinking adds
                        tens of seconds per doc for zero gate-relevant gain

temperature=0 everywhere: the extractor must be as deterministic as a
served model allows, so re-extraction of the same artifact is stable.
"""

import json
import os
import time
from typing import Optional

import requests

__all__ = ["OpenAICompatibleInvoke", "adapter_from_env",
           "ResponseTooLarge", "BudgetExceeded"]

_RETRYABLE = {429, 500, 502, 503, 504}


class ResponseTooLarge(RuntimeError):
    """A provider returned more bytes than the configured cap — treated as
    hostile/misbehaving, never parsed (security review C2)."""


class BudgetExceeded(RuntimeError):
    """Cumulative token spend crossed the configured budget — the caller
    (pipeline cycle) treats this as an abort + alert, not a silent skip."""


class OpenAICompatibleInvoke:
    """invoke(system, user) -> str — the contract LLMExtractor expects."""

    def __init__(self, base_url: str, api_key: Optional[str] = None,
                 model: str = "", timeout: float = 120.0,
                 json_mode: bool = False, thinking: Optional[str] = None,
                 max_tokens: int = 4096, max_response_bytes: int = 512 * 1024,
                 budget_tokens: int = 0, session=None):
        self._base = base_url.rstrip("/")
        self._api_key = api_key
        self._model = model
        self._timeout = timeout
        self._json_mode = json_mode
        self._thinking = thinking
        self._max_tokens = max_tokens
        self._max_response_bytes = max_response_bytes
        self._budget_tokens = budget_tokens
        self._budget_spent = 0
        self._session = session or requests.Session()

    @property
    def budget_spent(self) -> int:
        """Tokens consumed so far — the cycle reports this for alerting."""
        return self._budget_spent

    def __call__(self, system: str, user: str) -> str:
        return self.invoke(system, user)

    def invoke(self, system: str, user: str) -> str:
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = "Bearer %s" % self._api_key
        body = {
            "model": self._model,
            "temperature": 0,
            "max_tokens": self._max_tokens,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        if self._json_mode:
            body["response_format"] = {"type": "json_object"}
        if self._thinking:
            body["thinking"] = {"type": self._thinking}

        url = "%s/chat/completions" % self._base
        last_error = None
        for attempt in (1, 2):  # one retry on transient server trouble
            try:
                resp = self._session.post(url, headers=headers,
                                          data=json.dumps(body),
                                          timeout=self._timeout)
            except requests.RequestException as exc:
                last_error = exc
                if attempt == 1:
                    time.sleep(1.5)
                    continue
                raise
            if resp.status_code == 200:
                # hostile-provider guard (security review C2): never parse
                # more than MAX_RESPONSE_BYTES regardless of what arrives
                if len(resp.content) > self._max_response_bytes:
                    raise ResponseTooLarge(
                        "LLM response %d bytes > cap %d — refusing to parse"
                        % (len(resp.content), self._max_response_bytes))
                payload = resp.json()
                usage = payload.get("usage", {}).get("total_tokens") or 0
                self._budget_spent += usage
                if self._budget_tokens and self._budget_spent > self._budget_tokens:
                    raise BudgetExceeded(
                        "LLM token budget exceeded: %d > %d"
                        % (self._budget_spent, self._budget_tokens))
                return payload["choices"][0]["message"]["content"]
            if resp.status_code in _RETRYABLE and attempt == 1:
                time.sleep(1.5)
                continue
            raise RuntimeError("LLM API %s -> %s: %s"
                               % (resp.status_code, url, resp.text[:300]))
        raise RuntimeError("LLM API failed: %s" % last_error)


def adapter_from_env() -> OpenAICompatibleInvoke:
    base = os.environ.get("TRUVO_LLM_BASE_URL")
    model = os.environ.get("TRUVO_LLM_MODEL")
    if not base or not model:
        raise SystemExit(
            "llm extractor requires TRUVO_LLM_BASE_URL and TRUVO_LLM_MODEL "
            "(hosted frontier API for SaaS; local vLLM for Compact)")
    return OpenAICompatibleInvoke(
        base_url=base,
        api_key=os.environ.get("TRUVO_LLM_API_KEY"),
        model=model,
        timeout=float(os.environ.get("TRUVO_LLM_TIMEOUT", "120")),
        json_mode=os.environ.get("TRUVO_LLM_JSON_MODE", "") == "1",
        thinking=os.environ.get("TRUVO_LLM_THINKING") or None,
        max_tokens=int(os.environ.get("TRUVO_LLM_MAX_TOKENS", "4096")),
        max_response_bytes=int(os.environ.get("TRUVO_LLM_MAX_RESP_BYTES",
                                              str(512 * 1024))),
        budget_tokens=int(os.environ.get("TRUVO_LLM_BUDGET_TOKENS", "0")),
    )
