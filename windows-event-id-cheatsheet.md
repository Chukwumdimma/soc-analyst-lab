# Windows Event ID Cheat Sheet

Notes from the SOC Odyssey vault and my own study.

## Windows Security log
| Event ID | Meaning |
|---|---|
| 4624 | Successful logon (Logon Type 10 = remote desktop) |
| 4625 | Failed logon |
| 4663 | File or object access (needs Object Access auditing and a SACL) |
| 4688 | New process created (not audited by default) |

## Windows System log
| Event ID | Meaning |
|---|---|
| 1074 | Planned shutdown or restart |
| 7045 | New service installed |

## Windows Defender Operational log
| Event ID | Meaning |
|---|---|
| 1002 | Scan stopped before completion |
| 1116 | Malware detected |
| 1117 | Action taken on malware |

## Sysmon
| Event ID | Meaning |
|---|---|
| 1 | Process created |
| 11 | File created (name and full path) |
| 15 | File stream created (Zone.Identifier, shows download source) |

## Things I noticed
- Windows doesn't log a dedicated event for a plain .exe being installed, and process creation (4688) isn't audited by default. That gap is why Sysmon is used.
- Many 4625 failures followed by a 4624 success can mean a guessed password.
