# Threat Evidence Workbench Report

## File Summary

- File name: `sample_signin_logs.csv`
- Detected evidence type: Entra sign-in style logs
- Total records/lines: 3

## Severity Recommendation

High

## Top Suspicious Indicators

- **Multiple failed logins** (Medium): Repeated failed authentication attempts were observed.
- **Successful login after failures** (High): A successful login occurred after failed attempts.
- **Failed MFA** (Medium): MFA failure or denial was observed.
- **New device indicator** (Medium): The activity references a new or unfamiliar device.
- **Risky country indicator** (High): The activity references a risky or unusual country.
- **Impossible travel indicator** (High): The evidence suggests geographically impossible travel.

## Human Review Warning

This is sample output from fake/synthetic lab data only. A human analyst must validate findings before operational action.
