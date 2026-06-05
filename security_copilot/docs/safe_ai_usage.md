# Safe AI Usage

Security Copilot Chat is for fake/sample lab documentation only.

## Do Not Enter

- Real company data
- Real client data
- Real tenant data
- Real vendor confidential data
- Secrets
- Passwords
- Tokens
- API keys
- Credentials
- Private documents
- Internal policies
- Production logs

## Local-Only Boundary

Version 1 uses local TF-IDF retrieval over repository files. It does not send prompts, documents, or answers to external services.

## Future LLM Mode

Optional LLM mode is future-ready but disabled by default. Any future implementation should use secure secret management outside the repository, explicit user opt-in, safe redaction, and clear data-handling warnings.
