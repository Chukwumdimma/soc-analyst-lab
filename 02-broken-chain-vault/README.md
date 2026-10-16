
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
### 1. The capture
![Capture file properties](bc01-capture-properties.png)
498 packets over about 30 seconds. I recorded the SHA256 hash so anyone can check they have the same file.

### 2. The login
![Login POST packet, password hidden](bc02-login-post-redacted.png)
A user at 192.168.100.6 sent `POST /doLogin` to 65.61.137.117 (testfire.net) over HTTP on port 80. The form fields were `uid` and `passw`, and both were readable in the packet.

### 3. The full conversation
![TCP stream, password and cookies hidden](bc03-tcp-stream-redacted.png)
The Referer header showed the form was submitted from `http://testfire.net/login.jsp`. The server answered `302 Found` with `Location: login.jsp`, sending the browser back to the login page. That suggests the login was not accepted. The page body wasn't in the capture, so I can't prove it. Either way, the username and password were exposed. testfire.net is a public demo banking site made for security testing, so these were practice credentials.

```mermaid
sequenceDiagram
    participant U as User (192.168.100.6)
    participant S as testfire.net (65.61.137.117)
    U->>S: POST /doLogin on port 80 (uid and passw sent as plain text)
    Note over U,S: HTTP is unencrypted, so anyone capturing this traffic can read the credentials
    S-->>U: 302 Found, Location login.jsp
    U->>S: GET /login.jsp
    S-->>U: 200 OK
```

### 4. Secure protocols on the same machine
![WireGuard packets with UDP ports](bc04-wireguard.png)
Wireshark showed WireGuard (a VPN) over UDP. The client's first packet went to destination port 51820, which is the port the server listens on. TLS (TLSv1.2) was also in use over TCP.


## Problems and how I fixed them


## What I learned
