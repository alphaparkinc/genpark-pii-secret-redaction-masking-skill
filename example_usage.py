"""
Demonstration of genpark-pii-secret-redaction-masking-skill
"""

from client import PIISecretRedactorClient

def main():
    redactor = PIISecretRedactorClient()

    sample_prompt = (
        "Please send user audit log to user john.doe@enterprise.org or call 555-123-4567. "
        "Use access key ak_example_dummy_access_key_998877 to access logs on 192.168.1.15."
    )

    redacted, tokens = redactor.redact(sample_prompt)
    print("=== REDACTED TEXT (SAFE FOR LLM) ===")
    print(redacted)

    print("\n=== VAULT TOKENS ===")
    for t, orig in tokens.items():
        print(f"{t} -> {orig}")

    restored = redactor.restore(redacted)
    print("\n=== FULL RESTORED TEXT ===")
    print(restored)
    assert restored == sample_prompt, "Restoration identity preserved!"

if __name__ == "__main__":
    main()
