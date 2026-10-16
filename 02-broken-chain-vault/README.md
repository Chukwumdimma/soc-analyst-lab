
# Broken Chain: Unencrypted Traffic

## Scenario
A user logged in to a website over plain HTTP, so their credentials crossed the network readable. I was given a packet capture and had to find the server, the login page, the credentials and the secure protocols the user's machine was also running.

## Environment
- Tool: Wireshark on Kali Linux (VirtualBox)
- Evidence: `BrokenChain.pcap`, 498 packets over about 30 seconds
- SHA256: c8d7910d8c84e891aa5f20c209192670679eb856901f7bb1b92364eacd421c81

## What I did
1. Downloaded the capture, extracted it with `unzip`, and opened it in Wireshark.
2. Checked the packet count and file hash under Statistics, then Capture File Properties.
3. Filtered for the login with `http.request.method == "POST"`, which returned one packet.
4. Read the submitted form fields in the packet details, then used Follow TCP Stream to see the full request and response.
5. Filtered `udp`, then removed the known noise with `udp && !(dns || mdns || llmnr || ssdp)` to find the secure UDP protocol.
6. Filtered `wg` to read the WireGuard port, and `tls` to find the secure TCP protocol.

## What I found


## Problems and how I fixed them


## What I learned
