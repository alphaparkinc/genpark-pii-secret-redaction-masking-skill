"""
PII and Secret Redaction Engine with Reversible Token Vault.
Zero external dependencies, standard library only.
"""

import re
from typing import Dict, List, Any, Tuple

REDACTION_RULES = [
    ("EMAIL", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b"),
    ("PHONE", r"\b(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    ("SSN", r"\b\d{3}-\d{2}-\d{4}\b"),
    ("API_KEY", r"\b(ghp|sk|ak|key)_[a-zA-Z0-9_-]{16,64}\b"),
    ("IP_ADDR", r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
]

class PIISecretRedactorClient:
    """
    Sanitizes prompts before LLM dispatch and restores original tokens upon response:
    - Replaces sensitive entities with synthetic placeholders: [EMAIL_1], [API_KEY_1]
    - Maintains an in-memory session vault for reversible de-anonymization
    """

    def __init__(self):
        self.vault: Dict[str, str] = {} # token -> real_value
        self.reverse_vault: Dict[str, str] = {} # real_value -> token

    def redact(self, text: str) -> Tuple[str, Dict[str, str]]:
        """Masks sensitive data in text and populates vault."""
        redacted_text = text
        session_tokens = {}

        for tag, pattern in REDACTION_RULES:
            matches = list(re.finditer(pattern, redacted_text))
            # Process in reverse order to preserve match offsets
            for m in reversed(matches):
                val = m.group(0)
                if val in self.reverse_vault:
                    token = self.reverse_vault[val]
                else:
                    idx = len([k for k in self.vault if k.startswith(f"[{tag}_")]) + 1
                    token = f"[{tag}_{idx}]"
                    self.vault[token] = val
                    self.reverse_vault[val] = token

                session_tokens[token] = val
                start, end = m.span()
                redacted_text = redacted_text[:start] + token + redacted_text[end:]

        return redacted_text, session_tokens

    def restore(self, redacted_text: str) -> str:
        """Reverses tokenization, inserting original values."""
        restored = redacted_text
        for token, original in self.vault.items():
            restored = restored.replace(token, original)
        return restored
