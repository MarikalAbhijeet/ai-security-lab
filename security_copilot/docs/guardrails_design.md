# Guardrails Design

Security Copilot Chat runs pre-LLM guardrails before retrieval or generation.

## Blocked Input Types

- Secret-like values such as API key assignments, bearer tokens, and private key blocks
- Password, token, and client secret assignments
- Common cloud or database connection strings
- Prompt override attempts such as requests to ignore instructions or reveal system prompts
- Long pasted logs or documents

## Why Guardrails Run First

The assistant should never index, retrieve against, or send sensitive pasted content to an LLM provider. Even though Ollama is local, the lab keeps a strict portfolio-safe boundary and requires fake/sample data only.

## User Guidance

When guardrails block a question, the assistant asks the user to remove sensitive content and ask a short question about the local lab instead.
