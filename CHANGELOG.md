# Changelog

## [1.0.0] - 2026-03-09

### Added
- 8 forensic investigation modules (739 lines Bash)
- Module 1: Volatile data (processes, FDs, modules, mounts, env secrets)
- Module 2: Persistence (cron, systemd, init, shell profiles, SSH, LD_PRELOAD)
- Module 3: Malware (webshells 14 sigs, crypto miners, reverse shells, rootkits, SUID, package integrity)
- Module 4: Users (UID 0, passwordless, sudoers, login history, SSH activity)
- Module 5: Network (connections, C2 ports, DNS, ARP, firewall, promiscuous)
- Module 6: Logs (collection, tampering, brute force, privilege escalation)
- Module 7: IOC extraction (IPs, domains, URLs, hashes, suspicious history)
- Module 8: Timeline (file mods, auth events, packages, logins)
- SHA-256 chain of custody for all evidence
- HTML forensic report with severity scoring
- Modular execution (--volatile, --malware, etc.)
- Custom output directory (--output)
- Professional GUI documentation page
