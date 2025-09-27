# 1. Prerequisites

You need:
- A C compiler for Windows:
    - Either MSVC (Visual Studio / Build Tools)
    - Or MinGW-w64 (gcc for Windows)
- The Npcap SDK (Developer Pack) from:
https://nmap.org/npcap/#download

# 2. Install the Npcap SDK

1. Download the npcap-sdk-x.x.zip file.
2. Extract it somewhere simple, e.g.:
```
C:\npcap-sdk\
```
3. Check that the following exist:
```
C:\npcap-sdk\Include\pcap.h
C:\npcap-sdk\Lib\x64\wpcap.lib (for 64-bit builds)
C:\npcap-sdk\Lib\Win32\wpcap.lib (for 32-bit builds)
```
# 3. Source File
Place the provided sniffer source file in a folder, e.g.:
```
C:\projects\tcp_sniffer\tcp_sniffer.c
```

# 4. Compiling with MinGW-w64 (gcc)
1. Open a terminal where gcc is available (MinGW-w64 shell or Git Bash if configured).
2. Navigate to your project folder:
```
cd C:/projects/tcp_sniffer
```
3. Run the compile command:

**64-bit build:**
```
gcc main.c -o ./bin/main -IC:/npcap-sdk/Include -LC:/npcap-sdk/Lib/x64 -lwpcap -lPacket -lws2_32
```

**32-bit build:**
```
gcc tcp_sniffer.c -o tcp_sniffer.exe -IC:/npcap-sdk/Include -LC:/npcap-sdk/Lib/Win32 -lwpcap -lPacket -lws2_32 -m32
```

# 6. Libraries Explained
When linking, we need three libraries:

- ``wpcap.lib`` → main Npcap/libpcap API (functions your code calls).
- ``Packet.lib`` → low-level helper library that wpcap depends on.
- ``Ws2_32.lib`` → standard Windows sockets library (part of Windows SDK).