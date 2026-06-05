# Defensive Patterns for Prompt Injection

Use these patterns when designing or reviewing AI-assisted workflows.

## Instruction Hierarchy

Keep system, developer, application, and user instructions separate. User input and retrieved content should never override trusted instructions.

## Input Separation

Label untrusted content clearly. For example, treat uploaded documents, emails, web pages, and tickets as data to analyze, not instructions to follow.

## Output Validation

Validate model output before using it in tickets, detections, automation, or decisions. Prefer structured schemas when possible.

## Least Privilege Tools

Limit what tools an AI workflow can call. Require approval before sending data, changing tickets, disabling accounts, or taking containment action.

## Sensitive Data Handling

Do not place secrets, credentials, tokens, private documents, or real company data in prompts. Use fake sample data for labs and demos.

## Human Review

Use AI as an assistant for triage and summarization. Keep a human analyst responsible for final security decisions.
