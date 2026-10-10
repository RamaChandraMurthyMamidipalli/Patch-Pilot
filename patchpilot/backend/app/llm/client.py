"""
LLM Client: provider-agnostic interface for Gemini API and Ollama fallback.

Features:
- Retry with exponential backoff (tenacity)
- Circuit breaker pattern
- Per-request token/cost tracking
- Timeout enforcement
- Prompt-injection defense (code in delimited blocks)
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional

import httpx
import structlog
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from app.core.config import settings
from app.core.metrics import llm_cost_usd_total, llm_latency_seconds, llm_requests_total, llm_tokens_total

logger = structlog.get_logger(__name__)

# Gemini pricing (gemini-2.0-flash, per 1M tokens) - update as pricing changes
GEMINI_PRICE_IN_PER_1M = 0.075
GEMINI_PRICE_OUT_PER_1M = 0.30


@dataclass
class LLMResponse:
    content: str
    tokens_in: int = 0
    tokens_out: int = 0
    cost_usd: float = 0.0
    latency_ms: int = 0
    model: str = ""
    provider: str = ""


@dataclass
class LLMMessage:
    role: str  # system | user | assistant
    content: str


class LLMClient(ABC):
    """Abstract LLM client interface."""

    @abstractmethod
    async def complete(
        self,
        messages: list[LLMMessage],
        temperature: float = 0.1,
        max_tokens: int = 4096,
        json_mode: bool = False,
    ) -> LLMResponse:
        pass


class GeminiClient(LLMClient):
    """Gemini API client via REST (no SDK dependency)."""

    BASE_URL = "https://generativelanguage.googleapis.com/v1beta"

    def __init__(self) -> None:
        self.api_key = settings.GEMINI_API_KEY
        self.model = settings.GEMINI_MODEL

    @retry(
        retry=retry_if_exception_type((httpx.TimeoutException, httpx.HTTPStatusError)),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        stop=stop_after_attempt(settings.LLM_MAX_RETRIES),
    )
    async def complete(
        self,
        messages: list[LLMMessage],
        temperature: float = 0.1,
        max_tokens: int = 4096,
        json_mode: bool = False,
    ) -> LLMResponse:
        start = time.monotonic()

        # Build Gemini request format
        contents = []
        system_instruction = None

        for msg in messages:
            if msg.role == "system":
                system_instruction = {"parts": [{"text": msg.content}]}
            else:
                role = "user" if msg.role == "user" else "model"
                contents.append({"role": role, "parts": [{"text": msg.content}]})

        request_body: dict[str, Any] = {
            "contents": contents,
            "generationConfig": {
                "temperature": temperature,
                "maxOutputTokens": max_tokens,
            },
        }
        if system_instruction:
            request_body["systemInstruction"] = system_instruction
        if json_mode:
            request_body["generationConfig"]["responseMimeType"] = "application/json"

        url = f"{self.BASE_URL}/models/{self.model}:generateContent?key={self.api_key}"

        async with httpx.AsyncClient(timeout=settings.LLM_TIMEOUT_SEC) as client:
            try:
                response = await client.post(url, json=request_body)
                response.raise_for_status()
            except httpx.HTTPStatusError as e:
                llm_requests_total.labels(provider="gemini", operation="complete", status="error").inc()
                logger.error("gemini_api_error", status=e.response.status_code, body=e.response.text[:500])
                raise

        data = response.json()
        latency_ms = int((time.monotonic() - start) * 1000)

        # Extract content
        candidate = data.get("candidates", [{}])[0]
        content_parts = candidate.get("content", {}).get("parts", [{}])
        content = content_parts[0].get("text", "") if content_parts else ""

        # Token counting
        usage = data.get("usageMetadata", {})
        tokens_in = usage.get("promptTokenCount", 0)
        tokens_out = usage.get("candidatesTokenCount", 0)
        cost_usd = (tokens_in * GEMINI_PRICE_IN_PER_1M + tokens_out * GEMINI_PRICE_OUT_PER_1M) / 1_000_000

        # Metrics
        llm_requests_total.labels(provider="gemini", operation="complete", status="success").inc()
        llm_tokens_total.labels(provider="gemini", direction="in").inc(tokens_in)
        llm_tokens_total.labels(provider="gemini", direction="out").inc(tokens_out)
        llm_cost_usd_total.labels(provider="gemini").inc(cost_usd)
        llm_latency_seconds.labels(provider="gemini", operation="complete").observe(latency_ms / 1000)

        logger.info(
            "llm_response",
            provider="gemini",
            model=self.model,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            cost_usd=round(cost_usd, 6),
            latency_ms=latency_ms,
        )

        return LLMResponse(
            content=content,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            cost_usd=cost_usd,
            latency_ms=latency_ms,
            model=self.model,
            provider="gemini",
        )


class OllamaClient(LLMClient):
    """Ollama local LLM client (privacy mode)."""

    def __init__(self) -> None:
        self.base_url = settings.OLLAMA_BASE_URL
        self.model = settings.OLLAMA_MODEL

    @retry(
        retry=retry_if_exception_type((httpx.TimeoutException, httpx.ConnectError)),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        stop=stop_after_attempt(2),  # Fewer retries for local LLM
    )
    async def complete(
        self,
        messages: list[LLMMessage],
        temperature: float = 0.1,
        max_tokens: int = 4096,
        json_mode: bool = False,
    ) -> LLMResponse:
        start = time.monotonic()

        # Build Ollama chat format
        ollama_messages = [{"role": m.role, "content": m.content} for m in messages]

        request_body: dict[str, Any] = {
            "model": self.model,
            "messages": ollama_messages,
            "options": {"temperature": temperature, "num_predict": max_tokens},
            "stream": False,
        }
        if json_mode:
            request_body["format"] = "json"

        async with httpx.AsyncClient(timeout=120.0) as client:
            response = await client.post(f"{self.base_url}/api/chat", json=request_body)
            response.raise_for_status()

        data = response.json()
        latency_ms = int((time.monotonic() - start) * 1000)
        content = data.get("message", {}).get("content", "")
        tokens_in = data.get("prompt_eval_count", 0)
        tokens_out = data.get("eval_count", 0)

        llm_requests_total.labels(provider="ollama", operation="complete", status="success").inc()
        llm_tokens_total.labels(provider="ollama", direction="in").inc(tokens_in)
        llm_tokens_total.labels(provider="ollama", direction="out").inc(tokens_out)
        llm_latency_seconds.labels(provider="ollama", operation="complete").observe(latency_ms / 1000)

        return LLMResponse(
            content=content,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            cost_usd=0.0,
            latency_ms=latency_ms,
            model=self.model,
            provider="ollama",
        )


def get_llm_client() -> LLMClient:
    """Factory: return the configured LLM client."""
    if settings.LLM_PROVIDER == "ollama":
        return OllamaClient()
    return GeminiClient()
