# Prompt Injection Testing Lab

This project is a beginner-friendly, rule-based prompt injection testing lab using only safe fake/sample prompts.

Version 1 does not use paid APIs, real company data, real secrets, credentials, tokens, private documents, internal policies, or external AI providers. It reads one local sample JSON prompt and generates a Markdown test report.

## What It Generates

For each prompt test, the tool creates:

- Risk rating: Low, Medium, or High
- Detected injection indicators
- Attack type
- OWASP LLM Top 10 mapping
- MITRE ATLAS-style mapping
- Recommended mitigation
- Expected safe response
- Pass/fail result
- Markdown test report

## Project Structure

```text
03-prompt-injection-lab/
|-- README.md
|-- requirements.txt
|-- prompt_injection_lab.py
|-- docs/
|   |-- defensive_patterns.md
|   |-- mitre_atlas_mapping.md
|   `-- owasp_llm_mapping.md
|-- sample-inputs/
|   |-- direct-instruction-override.json
|   |-- system-prompt-extraction.json
|   |-- sensitive-data-request.json
|   |-- role-play-jailbreak.json
|   |-- indirect-fake-document.json
|   |-- output-manipulation.json
|   |-- fake-data-exfiltration.json
|   `-- benign-normal-prompt.json
|-- sample-output/
|   `-- direct-instruction-override-report.md
`-- tests/
    `-- test_prompt_injection_lab.py
```

## Sample Prompt Tests Included

The lab includes eight safe sample tests:

1. Direct instruction override
2. System prompt extraction attempt
3. Sensitive data request
4. Role-play jailbreak style prompt
5. Indirect prompt injection from a fake document
6. Output manipulation attempt
7. Data exfiltration attempt using fake secret names only
8. Benign normal prompt

Each sample includes a test ID, title, prompt text, expected risk level, expected attack type, OWASP LLM mapping, MITRE ATLAS-style mapping, and expected safe behavior.

## Requirements

- Python 3.9 or newer
- No external Python packages are required

## Run Instructions

From this project folder:

```powershell
python .\prompt_injection_lab.py .\sample-inputs\direct-instruction-override.json
```

To save the report to a Markdown file:

```powershell
python .\prompt_injection_lab.py .\sample-inputs\direct-instruction-override.json -o .\sample-output\direct-instruction-override-report.md
```

Run the other sample tests:

```powershell
python .\prompt_injection_lab.py .\sample-inputs\system-prompt-extraction.json
python .\prompt_injection_lab.py .\sample-inputs\sensitive-data-request.json
python .\prompt_injection_lab.py .\sample-inputs\role-play-jailbreak.json
python .\prompt_injection_lab.py .\sample-inputs\indirect-fake-document.json
python .\prompt_injection_lab.py .\sample-inputs\output-manipulation.json
python .\prompt_injection_lab.py .\sample-inputs\fake-data-exfiltration.json
python .\prompt_injection_lab.py .\sample-inputs\benign-normal-prompt.json
```

## Example Output

```text
## Risk Rating

High

## Attack Type

Direct Instruction Override

## Pass/Fail Result

Pass
```

## Security Notes

- All prompts are fake and safe for portfolio use.
- Fake names like `fake_secret`, `sample_token`, and `lab_secret` are placeholders only.
- The tool does not connect to external AI APIs or execute prompt content.
- Saved reports must use the `.md` extension and stay inside the `sample-output` folder.
- Rule-based logic is used first so the reasoning is transparent and easy to improve.

## Limitations

- This is not a live LLM firewall or production security control.
- Phrase matching is intentionally simple and can miss nuanced attacks.
- MITRE ATLAS-style mappings are simplified for lab use and should be reviewed before production documentation.
- Human review is still required for final AI risk decisions.

## Run Tests

The tests use only the Python standard library:

```powershell
python -m unittest discover -s tests
```

## Portfolio Value

This project demonstrates practical skills in:

- OWASP LLM Top 10 awareness
- Prompt injection testing
- MITRE ATLAS-style AI threat mapping
- Secure AI workflow design
- SOC-friendly AI risk reporting
- Safe rule-based AI Security portfolio design
