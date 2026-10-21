"""
Contexta Backend - Gemini client

Thin async wrapper over the google-genai SDK:
  * JSON mode with tolerant parsing
  * bounded concurrency, timeout, retry on transient errors only
  * injectable singleton (tests supply a fake with the same interface)
"""

import asyncio
import json
import re
from typing import Any, Dict, Optional

import structlog
from tenacity import (
    AsyncRetrying, retry_if_exception, stop_after_attempt, wait_exponential,
)

from app.config import settings

logger = structlog.get_logger()


class AIUnavailable(Exception):
    """AI is not configured or the provider failed."""

    def __init__(self, message: str, code: str = "ai_unavailable"):
        super().__init__(message)
        self.code = code


def _is_transient(exc: BaseException) -> bool:
    if isinstance(exc, (asyncio.TimeoutError, TimeoutError, ConnectionError)):
        return True
    code = getattr(exc, "code", None)
    return code in (408, 429, 500, 502, 503, 504)


def parse_json(text: str) -> Dict[str, Any]:
    """Parse model output as JSON, tolerating code fences and surrounding prose."""
    cleaned = (text or "").strip()
    cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", cleaned, flags=re.IGNORECASE)
    try:
        value = json.loads(cleaned)
    except json.JSONDecodeError:
        start, end = cleaned.find("{"), cleaned.rfind("}")
        if start == -1 or end <= start:
            raise AIUnavailable("Model returned invalid JSON", "ai_bad_response")
        try:
            value = json.loads(cleaned[start:end + 1])
        except json.JSONDecodeError:
            raise AIUnavailable("Model returned invalid JSON", "ai_bad_response")
    if not isinstance(value, dict):
        raise AIUnavailable("Model returned JSON that is not an object", "ai_bad_response")
    return value


class GeminiClient:
    def __init__(self, api_key: str, model: str, timeout: int, concurrency: int):
        self.model = model
        self.timeout = timeout
        self._api_key = api_key
        self._client = None
        self._sem = asyncio.Semaphore(max(1, concurrency))

    @property
    def configured(self) -> bool:
        return bool(self._api_key)

    @property
    def label(self) -> str:
        return f"gemini:{self.model}"

    def _get_client(self):
        if self._client is None:
            from google import genai

            self._client = genai.Client(api_key=self._api_key)
        return self._client

    async def _call(self, prompt: str, system: Optional[str], temperature: float,
                    max_tokens: int, json_mode: bool) -> str:
        from google.genai import types

        kwargs: Dict[str, Any] = {
            "temperature": temperature,
            "max_output_tokens": max_tokens,
            "system_instruction": system,
        }
        if json_mode:
            kwargs["response_mime_type"] = "application/json"
        if "2.5" in self.model and "flash" in self.model:
            kwargs["thinking_config"] = types.ThinkingConfig(thinking_budget=0)
        config = types.GenerateContentConfig(**kwargs)

        async with self._sem:
            async for attempt in AsyncRetrying(
                stop=stop_after_attempt(3),
                wait=wait_exponential(multiplier=1, min=1, max=8),
                retry=retry_if_exception(_is_transient),
                reraise=True,
            ):
                with attempt:
                    response = await asyncio.wait_for(
                        self._get_client().aio.models.generate_content(
                            model=self.model, contents=prompt, config=config
                        ),
                        timeout=self.timeout,
                    )
        text = getattr(response, "text", None)
        if not text:
            raise AIUnavailable("Model returned an empty response", "ai_bad_response")
        return text

    async def _guard(self, coro_factory):
        if not self.configured:
            raise AIUnavailable("GEMINI_API_KEY is not configured", "ai_not_configured")
        try:
            return await coro_factory()
        except AIUnavailable:
            raise
        except Exception as exc:
            code = getattr(exc, "code", None)
            logger.error("Gemini request failed", error=str(exc)[:300], code=code)
            if code in (401, 403):
                raise AIUnavailable("Gemini rejected the API key (invalid or revoked)", "ai_auth")
            if code == 429:
                raise AIUnavailable("Gemini rate limit / quota exceeded", "ai_rate_limited")
            raise AIUnavailable(f"Gemini request failed: {str(exc)[:200]}", "ai_error")

    async def generate_json(self, prompt: str, system: Optional[str] = None, temperature: float = 0.3,
                            max_tokens: int = 2048) -> Dict[str, Any]:
        text = await self._guard(lambda: self._call(prompt, system, temperature, max_tokens, True))
        return parse_json(text)

    async def generate_text(self, prompt: str, system: Optional[str] = None, temperature: float = 0.4,
                            max_tokens: int = 4096) -> str:
        return await self._guard(lambda: self._call(prompt, system, temperature, max_tokens, False))


_client: Optional[Any] = None


def get_ai() -> Any:
    """Return the process-wide AI client (GeminiClient or an injected fake)."""
    global _client
    if _client is None:
        _client = GeminiClient(
            api_key=settings.gemini_api_key if settings.gemini_configured else "",
            model=settings.gemini_model,
            timeout=settings.gemini_timeout_seconds,
            concurrency=settings.gemini_max_concurrency,
        )
    return _client


def set_ai(client: Optional[Any]) -> None:
    """Override the AI client (tests) or reset it with ``None``."""
    global _client
    _client = client
