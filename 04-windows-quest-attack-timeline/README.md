# Windows Quest: Reconstructing an Attack Timeline

## Scenario
A Windows host showed a remote logon followed by a run of suspicious commands. Using Wazuh, I rebuilt what the attacker did, in order, and measured how long it took from the first remote logon to the last persistence step. This uses the same host and data as my [September 2024 Wazuh investigation](../03-wazuh-sept-2024-investigation), looked at from the incident-timeline side.

## Environment
- Tool: Wazuh dashboard (Threat Hunting, Events)
- Host: Windows (`WIN-HOST`). The attacker's public address is masked as `197.237.16.x`.
- Times are in UTC. The dashboard shows them one hour ahead.

## What I did
1. Searched for remote logons with `data.win.system.eventID:4624 and data.win.eventdata.logonType:10`.
2. Searched Sysmon process creation (`data.win.system.eventID:1`) with the `commandLine` and `parentImage` columns to read the commands.
3. Searched for `schtasks`, `sc.exe create` and the registry Run key to find the persistence steps.
4. Decoded a Base64 command from a registry value with `base64 -d`.
5. Used the event's own timestamps to work out the elapsed time.

## What I found


## Problems and how I fixed them


## What I learned
