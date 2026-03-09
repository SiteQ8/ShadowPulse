# Contributing to ShadowPulse

## Adding Detection Signatures

1. Identify the detection category (persistence, malware, network, etc.)
2. Add grep/find patterns to the appropriate module function
3. Use `add_finding` with correct severity and remediation
4. Test on both Debian/Ubuntu and RHEL/CentOS

## Adding Modules

1. Create a new section following the existing pattern
2. Add `--modulename` flag to argument parser
3. Use `save_evidence` for all artifact collection
4. All evidence must be SHA-256 hashed automatically

## Standards

- Pure Bash 4.0+ — no external language dependencies
- ShellCheck clean (no warnings)
- Non-destructive — read-only operations only
- Evidence integrity — SHA-256 hash every artifact
