# Local LLM Design

Security Copilot Chat uses Ollama as the default local LLM provider with `qwen2.5:3b`.

## Design Goals

- Keep data on the local workstation.
- Avoid paid APIs and API keys.
- Retrieve only safe repository documentation and sample files.
- Cite local sources in every answer.
- Provide deterministic mock mode for tests and CI.
- Clearly warn that this is a synthetic lab model, not production detection or response tooling.

## Provider Flow

1. Load provider settings from environment variables.
2. Run guardrails against the user question.
3. Retrieve relevant local chunks.
4. Check Ollama availability at `OLLAMA_BASE_URL`.
5. Confirm the configured model is present.
6. Send the constrained prompt to local Ollama only when setup is ready.
7. Return setup instructions if Ollama is unavailable or the model is missing.

## Default Model

The default model is `qwen2.5:3b` because it is small enough for local demos while still supporting natural-language summaries.

This repository does not claim that the model is production-grade, complete, or suitable for autonomous security decisions.
