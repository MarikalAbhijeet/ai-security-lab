# Security Design Notes

AI Security Lab is designed for safe portfolio demonstration. The tools use local fake/sample data, standard-library Python where possible, explicit validation, and constrained file handling.

## Safe Sample Data

All project inputs are fake JSON or synthetic CSV files created for lab use. They are modeled after common security workflows but do not contain real company data, client data, tenant data, vendor confidential data, internal policies, credentials, API keys, tokens, passwords, private documents, or production logs.

The sample data is intentionally realistic enough to support portfolio discussion while remaining safe to publish.

## Local-Only Execution

The analyzer projects do not connect to:

- Microsoft Defender
- Microsoft Sentinel
- Entra ID
- Exchange Online
- Freshservice
- Vendor portals
- External AI services
- Paid APIs
- Live security systems

The ML anomaly detection module uses only a local synthetic CSV file and local Python libraries.

Security Copilot Chat uses local repository documents only. It excludes hidden files, `.git`, `.env`, virtual environments, cache folders, build folders, internal instruction files, dependency manifests, and sensitive filename patterns. It does not send questions or retrieved context to external services.

The Streamlit dashboard runs the same local analyzer scripts and displays the resulting Markdown.

## Input Validation

Each analyzer validates required JSON fields before generating a report. Missing or malformed inputs fail safely with clear error messages instead of producing misleading output.

Normal usage is based on the fake JSON files in each project's `sample-inputs` directory. Batch mode processes only files in that directory. Single-file mode is intended for sample JSON files and validates the JSON content; Project 4 also enforces that single-file vendor profiles stay inside its `sample-inputs` folder.

## Output Path Safety

Report writing is constrained to each project's `sample-output` folder. Batch output defaults to `sample-output/batch`, and custom batch output directories must remain inside `sample-output`.

This prevents accidental writes outside the intended project folder and keeps generated artifacts organized for GitHub review.

## Dashboard Safety

The dashboard avoids arbitrary path input. Users choose from a fixed list of four projects and a dropdown of known local JSON sample files. The app validates that the selected file remains inside the selected project's `sample-inputs` folder.

Analyzer scripts are launched with argument lists rather than shell strings, reducing command-injection risk. The dashboard also uses a timeout and displays safe error messages for failures.

Security Copilot Chat validates question length and retrieves only from local repository files. Users are warned not to type real secrets, credentials, company data, client data, tenant data, or vendor confidential data.

## Prompt Safety

The prompt injection lab uses defensive sample prompts. The examples describe unsafe request patterns without including real secrets, real private policies, working exploit chains, or operational instructions that would enable abuse.

The expected safe behavior reinforces refusal, least privilege, instruction hierarchy, input separation, and data protection.

## Dependency Approach

Projects 1-4 use the Python standard library only. Project 5 adds pandas and scikit-learn for local synthetic ML anomaly detection. Security Copilot Chat uses scikit-learn for local TF-IDF retrieval. The dashboard adds Streamlit as a presentation dependency in `dashboard/requirements.txt`.

Keeping dependencies minimal makes the repo easier to review and reduces unnecessary supply-chain exposure.

## Portfolio Boundaries

This repository is educational and demonstration-focused. It is not a production SOC platform, phishing gateway, LLM firewall, or vendor risk management system.

Future enterprise integrations should be added only with approved test tenants, approved sample data, and secure secret management outside the repository.
