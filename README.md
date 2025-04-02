# HAWK - HTTP/S Analysis Web Kit 🦅

## Overview
HAWK (HTTP/S Analysis Web Kit) is a powerful network analysis tool designed for security researchers, penetration testers, and developers who need deep insights into network traffic. It provides functionalities similar to Wireshark while offering additional proxy capabilities for traffic manipulation similar to Burp Suite or Fiddler 4.

## Features
- **Packet Viewer**: Analyze network packets in real-time, similar to Wireshark.

- **Universal Proxy**: Proxy any port and manipulate traffic by editing, forwarding, or blocking requests.

- **Advanced HTTPS Proxying**: Intercept, view, and modify non encrypted HTTPS traffic.

<video controls width="600">
  <source src="https://github.com/user-attachments/assets/1c921954-2396-40e2-bc13-41b90fddf1a4" type="video/mp4">
  Your browser does not support the video tag.
</video>

- **TLS Client & Server**: Simple TLSv1.2 Client And Server Implementation.

## Installation
```sh
git clone [https://github.com/guykey/HAWK-HTTP-S-Analysis-Web-Kit.git]
cd HAWK-HTTP-S-Analysis-Web-Kit/
```


### Building the Project
HAWK is a C++ GUI application built using Visual Studio. To compile and run it:
1. Open `HAWK.sln` in Visual Studio.
2. Select the `Release` build configuration.
3. Build the project using `Build -> Build Solution` (make sure to build the `HAWK_MAIN` project).
4. Run the application from Visual Studio.

## Documentation
Further documentation, reaserch and information is listed here:
[HAWK Project Documentation](https://drive.google.com/drive/folders/1Q2v-WCJHIUktr5ynlPXBoItn3EPqOW5B)

## Dependencies
All dependencies are located in the repository.
HAWK uses the libraries:
- CryptoPP [https://github.com/weidai11/cryptopp] (for general cryptography tools)
- WinDivert [https://github.com/basil00/WinDivert] (for diverting packets to Proxy Server)
- Npcap [https://github.com/nmap/npcap] (for Wireshark element)
- wxWidgets [https://github.com/wxWidgets/wxWidgets] (GUI library)
- zlib [https://zlib.net/] (for deflating gzip http traffic)

