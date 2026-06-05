# RAG Design

Security Copilot Chat uses a local retrieval-augmented generation style workflow without external model calls.

## Retrieval Flow

1. Resolve the index root and ensure it stays inside the repository.
2. Discover supported local documents with `.md`, `.txt`, `.kql`, and `.ps1` extensions.
3. Skip excluded folders, hidden paths, internal instruction files, dependency manifests, and sensitive filename patterns.
4. Load UTF-8 text documents under a size limit.
5. Build a TF-IDF matrix with scikit-learn.
6. Score the user question against the local corpus with cosine similarity.
7. Use the top retrieved snippets to build an answer.
8. Cite the local files used.

## Why Offline First

This lab is designed for safe GitHub portfolio review. Offline retrieval keeps the assistant deterministic, inexpensive, and safe to run without paid APIs or secrets.

## Confidence Note

The assistant reports a simple confidence-style note based on the strongest retrieval score:

- Higher confidence for stronger local matches
- Moderate confidence for partial local matches
- Low confidence when local context is weak or absent

This is not a calibrated probability. It is a retrieval-quality hint.

## Limitations

- The assistant answers only from local lab files.
- It does not reason over live security telemetry.
- It does not call a production SIEM, EDR, IAM system, ticketing system, or LLM.
- Retrieved snippets may omit context if the local docs are incomplete.
- If local retrieval is weak, the assistant should say it does not have enough local context.
- Human review is still required.
