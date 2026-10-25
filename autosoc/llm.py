"""One provider-agnostic LLM client: Amazon Bedrock (Claude), with OpenRouter as an optional fallback.

- JSON-only responses (agents validate them against a schema)
- response cache in SQLite (identical prompts never cost a second call)
- exponential backoff on 429/5xx, then fall back to the next provider that has a key
- `offline` provider: a deterministic stand-in so tests run without network or quota
"""
import hashlib
import json
import os
import re
import time

from urllib.parse import quote

import httpx

from . import config, db


class LLMUnavailable(Exception):
    pass


class ContentFiltered(Exception):
    """The model's own safety filter blocked the prompt (e.g. Amazon Nova on security content)."""
    pass


# provider -> time until which it is out of quota (a daily cap: no point retrying for hours).
# Kept in SQLite so the CLI, the UI and the scheduler all see it.
def _exhausted_get(provider):
    row = db.one("SELECT v FROM kv WHERE k=?", (f"llm_exhausted:{provider}",))
    return float(row["v"]) if row else 0.0


def _exhausted_set(provider, until):
    db.execute("INSERT OR REPLACE INTO kv (k, v) VALUES (?, ?)", (f"llm_exhausted:{provider}", str(until)))


def _retry_after(body):
    """Seconds the provider asks us to wait, if it says so (e.g. 'try again in 12s' / retryDelay)."""
    m = re.search(r"(?:retry|try again) in ((?:\d+h)?(?:\d+m)?[\d.]+s)", body)
    if m:
        parts = {unit: float(n) for n, unit in re.findall(r"([\d.]+)([hms])", m.group(1))}
        return float(parts.get("h", 0)) * 3600 + float(parts.get("m", 0)) * 60 + float(parts.get("s", 0))
    m = re.search(r'"retryDelay":\s*"([\d.]+)s"', body)
    return float(m.group(1)) if m else None


def status():
    """Which providers are configured and which are out of quota right now."""
    out = {}
    for p, _ in _providers():
        until = _exhausted_get(p)
        out[p] = ("out of quota until " + time.strftime("%b %d %H:%M", time.localtime(until))
                  if until > time.time() else "ok")
    return out


PROVIDERS = ("bedrock", "openrouter")
KEY_ENV = {"bedrock": "AWS_BEARER_TOKEN_BEDROCK"}


def _providers():
    order = [config.LLM_PROVIDER] + [p for p in PROVIDERS if p != config.LLM_PROVIDER]
    out = []
    for p in order:
        if p == "offline":
            break
        key = os.getenv(KEY_ENV.get(p, f"{p.upper()}_API_KEY"), "").strip()
        if key:
            out.append((p, key))
    return out


def _bedrock(key, system, user):
    """Bedrock Converse API with a Bedrock API key (bearer token)."""
    region = os.getenv("AWS_REGION", "ap-southeast-2")
    model = os.getenv("BEDROCK_MODEL") or "au.anthropic.claude-haiku-4-5-20251001-v1:0"
    r = httpx.post(
        f"https://bedrock-runtime.{region}.amazonaws.com/model/{quote(model, safe='')}/converse",
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
        json={
            "system": [{"text": system}],
            "messages": [{"role": "user", "content": [{"text": user}]}],
            "inferenceConfig": {"maxTokens": 4096},
        },
        timeout=120,
    )
    if r.status_code != 200:
        raise _HTTPError(r.status_code, r.text[:2000])
    body = r.json()
    # Amazon Nova applies a model-level content filter that blocks some security/attack prompts
    # (stopReason "content_filtered"). Treat it as a hard failure so we fall back at once instead of
    # retrying a prompt the model will keep refusing. Claude models on Bedrock do not do this.
    if body.get("stopReason") == "content_filtered":
        raise ContentFiltered(f"{model} refused the prompt (content_filtered)")
    blocks = body["output"]["message"]["content"]
    return "".join(b.get("text", "") for b in blocks)



def _openai_compat(base, key, model, system, user):
    r = httpx.post(
        f"{base}/chat/completions",
        headers={"Authorization": f"Bearer {key}"},
        json={
            "model": model,
            "temperature": 0.1,
            "response_format": {"type": "json_object"},
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        },
        timeout=90,
    )
    if r.status_code != 200:
        raise _HTTPError(r.status_code, r.text[:500])
    return r.json()["choices"][0]["message"]["content"]


class _HTTPError(Exception):
    def __init__(self, status, body):
        super().__init__(f"HTTP {status}: {body}")
        self.status = status
        self.body = body


def _call(provider, key, system, user):
    if provider == "bedrock":
        return _bedrock(key, system, user)
    if provider == "openrouter":
        return _openai_compat("https://openrouter.ai/api/v1", key,
                              os.getenv("OPENROUTER_MODEL", "meta-llama/llama-3.3-70b-instruct:free"),
                              system, user)
    raise ValueError(provider)


def parse_json(text):
    text = text.strip()
    m = re.search(r"```(?:json)?\s*(.*?)```", text, re.S)
    if m:
        text = m.group(1)
    start = min([i for i in (text.find("{"), text.find("[")) if i >= 0], default=0)
    return json.loads(text[start:])


def complete_json(system: str, user: str, *, agent: str, case_id=None, offline=None, use_cache=True):
    """Return (parsed_json, meta). `offline` is a zero-arg callable used in offline mode
    or when every provider is unavailable."""
    key = hashlib.sha256(f"{system}\n---\n{user}".encode()).hexdigest()
    db.audit(case_id, agent, "prompt", {"system": system, "user": user[:6000]})

    if config.LLM_PROVIDER != "offline" and use_cache:
        hit = db.one("SELECT response FROM llm_cache WHERE key=?", (key,))
        if hit:
            try:
                out = parse_json(hit["response"])
                db.audit(case_id, agent, "llm_response", {"provider": "cache", "response": out})
                return out, {"provider": "cache"}
            except ValueError:
                pass

    errors = []
    for provider, api_key in ([] if config.LLM_PROVIDER == "offline" else _providers()):
        if _exhausted_get(provider) > time.time():
            errors.append(f"{provider}: out of quota (skipped)")
            continue
        for attempt in range(6):
            try:
                text = _call(provider, api_key, system, user)
                out = parse_json(text)
                db.insert("llm_cache", {"key": key, "response": text, "ts": time.time()})
                db.audit(case_id, agent, "llm_response", {"provider": provider, "response": out})
                return out, {"provider": provider}
            except _HTTPError as e:
                errors.append(f"{provider}: {str(e)[:300]}")
                wait = _retry_after(e.body)
                if e.status == 429 and wait and wait > 60:
                    _exhausted_set(provider, time.time() + wait)  # daily cap: fall through to the next provider
                    break
                if e.status in (429, 500, 502, 503, 504):
                    # per-minute caps (tokens or requests per minute): wait as long as the provider asks
                    time.sleep(min((wait or 2 ** (attempt + 1)) + 0.5, 60))
                    continue
                break  # auth / bad request: try the next provider
            except ContentFiltered as e:
                errors.append(f"{provider}: {e}")
                break  # the model refuses this prompt; retrying will not help
            except (httpx.HTTPError, ValueError, KeyError, IndexError) as e:
                errors.append(f"{provider}: {type(e).__name__}: {e}")
                time.sleep(1)
                continue

    if offline is None:
        raise LLMUnavailable("; ".join(errors) or "no provider configured")
    out = offline()
    db.audit(case_id, agent, "llm_response",
             {"provider": "offline", "response": out, "errors": errors[-3:]})
    return out, {"provider": "offline", "errors": errors}
