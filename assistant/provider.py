from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, Optional


class ProviderError(RuntimeError):
    """Base error for provider failures handled by the assistant fallback."""


class ProviderTimeout(ProviderError):
    """Provider exceeded its configured response time."""


@dataclass(frozen=True)
class ProviderResponse:
    content: Any
    provider: str
    request_id: str


class LLMProvider(ABC):
    """Provider-neutral interface. Implementations must be read-only."""

    name: str

    @abstractmethod
    def generate(self, prompt: str, request_id: str) -> ProviderResponse:
        """Return an untrusted provider response for the supplied prompt."""
        raise NotImplementedError


class MockProvider(LLMProvider):
    """Deterministic provider used by tests; no network or SDK dependency."""

    name = "mock"

    def __init__(self, content: Any = None, error: Optional[Exception] = None):
        self.content = content
        self.error = error
        self.prompts = []

    def generate(self, prompt: str, request_id: str) -> ProviderResponse:
        self.prompts.append(prompt)
        if self.error is not None:
            raise self.error
        content = self.content
        if content is None:
            content = {
                "executive_summary": "The deterministic detection finding was reviewed using the supplied evidence.",
                "what_happened": "Observed process behavior deviated from the stored behavioral baseline.",
                "why_it_was_flagged": "Behavior, rule, and process-context signals contributed to the stored finding.",
                "evidence": "The evidence is reproduced from the Phase 5 explanation.",
                "risk_interpretation": "The stored score and severity remain authoritative; this is not an independent maliciousness decision.",
                "recommended_action": "Review the process tree and command history.",
                "limitations": "TCP/network, file, and audit/auth telemetry are unavailable.",
                "confidence_statement": "Confidence is limited to the supplied deterministic evidence.",
            }
        return ProviderResponse(content=content, provider=self.name, request_id=request_id)


def provider_from_environment() -> Optional[LLMProvider]:
    """Return only explicitly configured providers; no API key is read or logged here."""
    import os

    provider_name = os.getenv("ASSISTANT_PROVIDER", "").strip().lower()
    if provider_name == "mock":
        return MockProvider()
    return None
