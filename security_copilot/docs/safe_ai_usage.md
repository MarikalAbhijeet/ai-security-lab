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

The assistant uses local TF-IDF retrieval over repository files. By default, generated answers use a local Ollama instance at the configured local URL. Tests use mock mode and do not call Ollama.

## Local LLM Mode

Ollama mode is intended for local workstation demos only. It should not be treated as a production SOC copilot and should not receive sensitive production content. Keep `.env` files out of Git and use `.env.example` only as a safe reference.
