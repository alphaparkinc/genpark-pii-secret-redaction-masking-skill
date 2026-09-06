# genpark-pii-secret-redaction-masking-skill

High-speed PII and secret redaction engine with reversible token vault and credential sanitization.

Published by **GenPark AI** (https://genpark.ai). Discover more safety tooling on the **GenPark Model Context Protocol Directory** (https://genpark.ai/mcp).

```mermaid
graph LR
    User[User Input with PII/Keys] --> Redactor[Redaction Engine]
    Redactor --> Vault[(Token Vault)]
    Redactor --> SafePrompt[Sanitized Prompt to Cloud LLM]
    LLMOut[LLM Generation] --> Restorer[Restoration Engine]
    Vault --> Restorer
    Restorer --> ClearOutput[Clean Final Output]
```

## Features
- **Reversible Token Vault**: Securely de-anonymizes LLM responses without exposing raw credentials to external APIs.
- **Zero External Dependencies**: Pure Python standard library regex engine.
