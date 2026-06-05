# RAG Design

Security Copilot Chat uses a local retrieval-augmented generation workflow. Retrieval is local and deterministic. Generation uses local Ollama by default, or mock mode during tests and CI.

## Retrieval Flow

1. Resolve the index root and ensure it stays inside the repository.
2. Discover supported local documents with `.md`, `.txt`, `.kql`, `.ps1`, `.json`, and `.csv` extensions.
3. Skip excluded folders, hidden paths, internal instruction files, dependency manifests, and sensitive filename patterns.
4. Load UTF-8 text documents under a size limit.
5. Build a TF-IDF matrix with scikit-learn.
6. Score the user question against the local corpus with cosine similarity.
7. Use the top retrieved snippets to build a constrained prompt.
8. Generate through local Ollama or deterministic mock mode.
9. Cite the local files used.

## Why Local First

This lab is designed for safe GitHub portfolio review. Local retrieval and local Ollama keep the assistant inexpensive and avoid paid APIs or cloud LLM keys. Mock mode keeps CI deterministic and does not require Ollama.

## Confidence Note

The assistant reports a simple confidence-style note based on the strongest retrieval score:

- Higher confidence for stronger local matches
- Moderate confidence for partial local matches
- Low confidence when local context is weak or absent

This is not a calibrated probability. It is a retrieval-quality hint.

## Limitations

- The assistant answers only from local lab files.
- It does not reason over live security telemetry.
- It does not call a production SIEM, EDR, IAM system, ticketing system, cloud LLM, or paid API.
- Local Ollama output still requires human review.
- Retrieved snippets may omit context if the local docs are incomplete.
- If local retrieval is weak, the assistant should say it does not have enough local context.
- Human review is still required.
