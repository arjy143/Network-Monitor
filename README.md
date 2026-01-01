# Network Monitor

A terminal UI application for seeing your network's traffic at a glance. Built using C++20, ncurses, and libpcap.

## Features

- **Real-time packet capture** - Live monitoring of network traffic on any interface
- **Multi-panel UI** with F1-F4 switching:
  - **F1 - Packets**: Scrollable list of captured packets with protocol coloring
  - **F2 - Statistics**: Packet counts, byte totals, throughput, and protocol breakdown
  - **F3 - Graph**: ASCII traffic graph showing packets/sec or bytes/sec over time
  - **F4 - Detail**: Full packet inspection with parsed headers and hex dump
- **Interface sidebar** - Browse and select network interfaces
- **Protocol parsing** - Ethernet, IPv4, IPv6, TCP, UDP, ICMP, ARP
- **Hostname/URL extraction**:
  - **DNS**: Shows queried domain names (e.g., "google.com Query A")
  - **HTTP**: Extracts Host header and request path from unencrypted traffic
  - **TLS/HTTPS**: Extracts Server Name Indication (SNI) from Client Hello
- **Color-coded protocols** - Easy visual identification of traffic types

## Building

```bash
mkdir build && cd build
cmake ..
make
```

### Dependencies

- CMake 3.16+
- C++20 compiler (GCC 10+ or Clang 10+)
- ncurses
- libpcap

On Debian/Ubuntu:
```bash
sudo apt install build-essential cmake libncurses-dev libpcap-dev
```

## Running

Packet capture requires root privileges or appropriate capabilities:

```bash
# Option 1: Run as root
sudo ./build/network-monitor

# Option 2: Set capabilities (preferred)
sudo setcap cap_net_raw,cap_net_admin=eip ./build/network-monitor
./build/network-monitor
```

## Keyboard Controls

| Key | Action |
|-----|--------|
| F1 | Switch to Packet List panel |
| F2 | Switch to Statistics panel |
| F3 | Switch to Graph panel |
| F4 | Switch to Packet Detail panel |
| Tab | Toggle focus between sidebar and main panel |
| Up/Down | Navigate lists or scroll content |
| Enter | Select interface (starts capture) / Select packet for detail view |
| s | Stop capture |
| q | Quit |

### Panel-specific keys

**Packet List (F1)**:
- `a` - Toggle auto-scroll
- `g/G` - Jump to first/last packet
- `PgUp/PgDn` - Page through packets

**Graph (F3)**:
- `b` - Toggle between packets/sec and bytes/sec view

**Detail (F4)**:
- `p` - Parsed view (default)
- `h` - Hex dump view
- `a` - ASCII view

## Architecture

```
src/
  main.cpp          # Entry point
  app.cpp/hpp       # Application controller and event loop
  ui.cpp/hpp        # ncurses wrapper with color support
  capture.cpp/hpp   # libpcap wrapper with background capture thread
  packet.cpp/hpp    # Packet parsing (Ethernet, IP, TCP, UDP, etc.)
  packet_store.cpp/hpp  # Thread-safe packet storage with statistics
  sidebar.cpp/hpp   # Interface selection widget
  panel.cpp/hpp     # Base panel class
  panels/
    packet_list.cpp/hpp  # Live packet list view
    stats.cpp/hpp        # Statistics view
    graph.cpp/hpp        # Traffic graph view
    detail.cpp/hpp       # Packet detail/hex dump view
```
