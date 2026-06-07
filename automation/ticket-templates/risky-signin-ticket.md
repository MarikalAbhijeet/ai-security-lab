# Risky Sign-In Ticket Note

## Summary
Detected a fake/sample risky sign-in pattern for `user@example.com` from `203.0.113.10`.

## Analyst Findings
- Review failed login count, MFA result, device state, geolocation, and application accessed.
- Compare activity to recent successful sign-ins and known user travel.
- Check for new device, risky country, impossible travel, or privileged activity indicators.

## Recommended Next Steps
- Validate with the user through an approved process.
- Review Sentinel/Defender sign-in timeline.
- Escalate if user confirmation fails or privileged access is involved.

## Safety Note
Sample/demo only. Do not include real user data, tenant data, or production logs.
