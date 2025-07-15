# 🎮 Trackmania Nations Forever – LAN Server Discovery & TCP Communication (Reverse Engineering)

This document describes how **Trackmania Nations Forever (TMNF)** discovers LAN servers and communicates with them using a combination of **UDP broadcasts** and **TCP packets**.

---

## 1. 🔍 UDP Discovery Phase

### Protocol Overview
- **Protocol:** UDP
- **Destination IP:** `255.255.255.255` (or network-specific broadcast like `192.168.178.255`)
- **Destination Ports:** `2350`, `2351`
- **Source Port:** Must be `60051` (servers will not respond otherwise)

### Discovery Payload (Hex)

```
82007f0c5b0909000000546d466f726576657203000000313030fd2c0000
```


### Meaning
| Bytes                        | Description                  |
|-----------------------------|------------------------------|
| `546d466f7265766572`         | ASCII `"TmForever"`          |
| `03 00 00 00`                | Discovery type `3`           |
| `31 30 30`                   | ASCII `"100"` – protocol version |
| `...fd2c0000`                | Likely session ID or seed (not yet reversed) |

### Server Response (UDP)
UDP packet sent back to source port `60051`, e.g.:

```
82019a6c5cc0fd2c00000700000047616d654e657409000000546d466f7265766572030000003130300700000064676e2d64656219641dac2e0919641dac2e09
```


Decoded:
- Signature: `"TmForever100"`
- Hostname: `"dgn-deb"` or `"PC-ce9b0c"`
- Prefix: `"GameNet"`

---

## 2. 📡 TCP Server Info Phase

### TCP Setup
- **Protocol:** TCP
- **Target:** Responding Server
- **Port:** `2350`
- **Client Source Port:** `55417`

### TCP Packet 1 (Hex)

```
0e000000820399f895580700000008000000
```


### TCP Packet 2 (Hex)

```
1200000082033bd464400700000007000000d53d4100
```


These are sent **in sequence**, with a short delay (~200ms) between them.

### TCP Server Response (Example Hexdump)
A successful response looks like this (example truncated for brevity):

```
5e0100008303b66349fab2010000001a0700000006000000d53d4100a20100002d19641dac2e090700000064676e2d6465620500000023535256230060000001200020010b00000052554b696464696e674d656c05045374616469756d64046c00000d0120bf02000f0f000000090000004331352d5370656564a0d20000da0700086c020a30312d52616365...
```


Decoded strings (UTF-8 interpretation where applicable):
- `SRV#<name>` = Server name
- `Stadium`, `Endurance` = Game mode
- `C04-Race`, `01-Race` = Map names
- Hostname repeated (e.g. `dgn-deb`)

---

## 3. 🧠 TCP Payload Analysis (Detailed Reverse Engineering)

### 3.1 Active Player Count

The current number of connected players is **not directly encoded as a number**. Instead, the payload contains a separate block for each connected player, starting with the **byte marker `48 07`**.

#### Player Block Structure:
- **Marker:** `48 07`
- **2 Bytes:** Optional (type or length)
- **Player Name:** UTF-8 encoded (variable length)
- **Terminator:** `FF FF FF FF`

**Example** (for player 'lanparty'):
```
48 07 ?? ?? 6C 61 6E 70 61 72 74 79 FF FF FF FF
```

#### Python Code for Extracting Player Names:

```python
def extract_player_names(payload: bytes) -> list[str]:
    names = []
    i = 0
    while i < len(payload) - 8:
        if payload[i] == 0x48 and payload[i+1] == 0x07:
            try:
                name_start = i + 4
                name_end = payload.index(b'\xff\xff\xff\xff', name_start)
                name_bytes = payload[name_start:name_end]
                name = name_bytes.decode('utf-8', errors='ignore')
                names.append(name)
                i = name_end + 4
            except ValueError:
                break
        else:
            i += 1
    return names
```

### 3.2 Maximum Player Count (Server Slots)

The maximum number of players is located at a **fixed position** relative to the string marker **`#SRV#`** (Hex: `23 53 52 56 23`).

- **Offset +10** after `#SRV#`: 1 Byte → maximum number of players

**Examples:**
```
23 53 52 56 23 00 60 00 00 01 20  → 32 players (0x20 = 32)
23 53 52 56 23 00 60 00 00 01 05  → 5 players  (0x05 = 5)
```

#### Python Code for Extracting Maximum Player Count:

```python
def extract_max_players(payload: bytes) -> int:
    srv_marker = b'#SRV#'
    idx = payload.find(srv_marker)
    if idx != -1 and len(payload) > idx + 10:
        return payload[idx + 10]
    return -1  # not found
```

### 3.3 Server Name

The **server name** is located as UTF-8 encoded text after the player limit structure in the payload. It has **no effect** on the structure or position of the player limit.

**Example** (server name 'Bana'):
```
... 23 53 52 56 23 00 60 00 00 01 05 ... 42 61 6E 61
```
- `01 05` → 5 player slots
- `42 61 6E 61` → 'Bana' (server name)

---

## 4. 🧪 Sequence Summary

1. **Client sends UDP broadcast** to `255.255.255.255:2350` from port `60051`
2. **Server replies with UDP** containing identity and hostname
3. **Client connects via TCP to port 2350**, using source port `55417`
4. **Client sends 2 TCP packets**
5. **Server replies with full server metadata (TCP)**
6. **Parse TCP payload** to extract player names, player count, and max slots

---

## 5. ⚙️ Notes

- UDP **source port must match expected** (`60051`)
- TCP **source port must be fixed** to `55417` for compatibility
- TCP payloads must be sent in proper order
- Server response format may resemble **GBX** (Trackmania binary encoding)
- Strings are often **null-terminated ASCII**
- **Player blocks** always start with `48 07` and end with `FF FF FF FF`
- **Maximum player count** is always located 10 bytes after the `#SRV#` marker

---

## 6. 🔮 Potential Extensions

- Write a parser for server TCP response (GBX-style)
- Build a LAN server browser UI
- Add filter logic for servername, mode, map, player count
- Generalize to other Trackmania variants (TMU, TM²)
- **Implement complete payload parser** using the discovered player and slot extraction methods

---

## 7. ✅ Validated Behavior

This sequence has been tested using packet captures and direct analysis against Trackmania Nations Forever LAN servers. The payload analysis methods for extracting player names and server slots have been verified through binary protocol reverse engineering. It is suitable for automating LAN discovery and comprehensive data extraction from dedicated servers.
