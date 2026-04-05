# ADJ-Shark

**Author:** Javier Ribal del Río

Wireshark dissector for the HyperLoop telemetry protocol. Reads packet and measurement definitions directly from the [`adj/`](https://github.com/Hyperloop-UPV/adj) JSON files at runtime, so it stays in sync with the protocol automatically.

## Requirements

- Wireshark 3.x or later
- The `adj/` repository cloned locally

## Installation

**1. Download `adj_dissector.lua`** from the [latest release](../../releases/latest).

**2. Copy it to your Wireshark plugins directory:**

| OS | Path |
|---|---|
| Linux | `~/.config/wireshark/plugins/` |
| macOS | `~/Library/Application Support/Wireshark/plugins/` |
| Windows | `%APPDATA%\Wireshark\plugins\` |

```bash
# Linux/macOS
cp adj_dissector.lua ~/.config/wireshark/plugins/
```

**3. Set the `adj/` path in Wireshark:**

Edit → Preferences → Protocols → ADJ → **Path** → `/your/local/path/to/adj`

**4. Reload plugins:** `Ctrl+Shift+L`

> **After pulling updates to `adj/`, press `Ctrl+Shift+L` — no reinstall needed.**

**IT IS ALSO REQUIRED EVEN IF YOU RESTAR WIRESHARK**

---

## Usage

The dissector activates automatically on **UDP port 50400**.

Each packet is decoded into a tree showing the board, packet name, and all variables with their values and units:

```
ADJ Protocol
├── Packet ID: 1703
├── Board: BCU
├── Packet Name: DC Link
└── Variables (3) [12 bytes payload]
    ├── DC Link Average Voltage: 320.5 V
    ├── DC Link A Voltage: 319.8 V
    └── DC Link B Voltage: 321.1 V
```

---

## Filters

### By board

```
adj.board == "BCU"
adj.board == "VCU"
adj.board == "LCU"
adj.board == "PCU"
adj.board == "HVSCU"
adj.board == "BMSL"
adj.board == "HVSCU-Cabinet"
```

### By packet ID

```
adj.packet_id == 1703
adj.packet_id == 777
```

### By packet name

```
adj.packet_name == "DC Link"
adj.packet_name == "Battery Data"
```

### Combine filters

```wireshark
# All BCU packets except Motor Currents
adj.board == "BCU" && adj.packet_id != 1704

# VCU or LCU traffic
adj.board == "VCU" || adj.board == "LCU"
```

### Erroneous packets

```wireshark
# Any packet with a problem
_ws.expert && adj

# Unknown packet ID (not defined in adj/)
adj.unknown_id

# Truncated payload (too short for its variable list)
adj.truncated

# Both
adj.unknown_id || adj.truncated
```

---

## Columns

To add a **Board** column to the packet list:

Edit → Preferences → Columns → **+** → Title: `Board`, Type: `Custom`, Fields: `adj.board`

