# TrackMania Forever (TMNF/TMUF) – Server Query Network Protocol

> **Purpose of this document:** A complete, verified reference on how to query a TrackMania Forever server
> (Nations/United Forever, "TmForever") using the game's own protocol and how to decode the response.
> Written so that a developer or an LLM can rebuild the protocol 1:1 without access to the binary.
>
> - **Source:** Reverse engineering of `TrackmaniaServer.exe` (build 2011-02-21, x86, image base `0x00400000`) with Ghidra.
>   All statements are derived from the decompiled code, not from existing implementations.
> - **Verified:** against a real game client ↔ server capture, and live against a Windows and a
>   Linux dedicated server (see [Section 13](#13-verification-status)).
> - **As of:** 2026-10-04.
> - **Supersedes:** `TMNF/TMNF_Doku.md` (2025). That document is **substantively wrong** (it describes a
>   UDP announcement to the master server, incorrect `#SRV#` meanings, and invented fixed fields) and should
>   no longer be used.

---

## Contents

0. [Summary](#0-summary)
1. [Context and ports](#1-context-and-ports)
2. [Data types and encodings](#2-data-types-and-encodings)
3. [TCP framing and message header](#3-tcp-framing-and-message-header)
4. [Checksum (HMAC-MD5)](#4-checksum-hmac-md5)
5. [Compression (LZO1X)](#5-compression-lzo1x)
6. [Message types](#6-message-types)
7. [CNetFormConnectionAdmin and the query flow](#7-cnetformconnectionadmin-and-the-query-flow)
8. [The server info (response payload)](#8-the-server-info-response-payload)
9. [Annotated example (real capture)](#9-annotated-example-real-capture)
10. [Robust detection of a TrackMania server](#10-robust-detection-of-a-trackmania-server)
11. [Reference implementation (Python, standard library only)](#11-reference-implementation-python-standard-library-only)
12. [UDP LAN discovery (partially analyzed)](#12-udp-lan-discovery-partially-analyzed)
13. [Verification status](#13-verification-status)
14. [Common misconceptions](#14-common-misconceptions)
15. [Ghidra index (addresses, class IDs)](#15-ghidra-index-addresses-class-ids)
16. [Existing implementations](#16-existing-implementations)

---

## 0. Summary

```
Open a TCP connection to the game port (default 2350), then send two messages:

  [u32 len=14] 82 03 [u32 checksum] 07000000 08000000              ConnectionAdmin v7, subtype 8 (query mode)
  [u32 len=18] 82 03 [u32 checksum] 07000000 07000000 [u32 id]      ConnectionAdmin v7, subtype 7 (info request)

Read response frames until type 3 / version 7 / subtype 6 / request_id == id:

  [u32 len] flags 03 [u32 checksum] ([u32 size] LZO1X data)  →  07000000 06000000 [u32 id] [u32 n] [n bytes server info]

flags:     0x80 | 0x01 LZO-compressed | 0x02 checksum | 0x04/0x08 sequence number (u16)
checksum:  sum of the four u32 words of HMAC-MD5(KEY, message with zeroed checksum field)
KEY:       struct.pack("<4I", 0x80D79DB8, 0xBA216B72, 0x15439598, 0xE1EC1CFA)

Server info: u8 0x2D | IP (4 bytes, reversed) | u16 port | str host login | str "#SRV#"+{"",p,s,f}
             | str "" | u8 players, max players, spectators, max spectators, ladder mode | wstr server name
             | str pack mask | player list | wstr comment | u8 mode | u32 limit | u8 #maps
             | map window (max. 20) | environment ids
str  = u32 length + bytes,  wstr = u32 length + UTF-8 (with BOM EF BB BF if non-ASCII)
```

All integers are **little-endian**.

---

## 1. Context and ports

| Port | Protocol | Purpose |
|---|---|---|
| **2350/TCP** (`server_port`) | Nadeo network protocol (this document) | Game connection **and** server query. The client uses it to fetch the details for the server browser. |
| 2350/UDP | Nadeo network protocol | In-game UDP as well as LAN discovery via broadcast ([Section 12](#12-udp-lan-discovery-partially-analyzed)). |
| 3450 (`server_p2p_port`) | P2P file transfer | not covered by this document |
| 5000/TCP (`xmlrpc_port`) | GbxRemote (XML-RPC) | Remote administration. Different protocol, requires credentials, and by default is reachable only locally. |

The query described here requires **no credentials** and works against any TmForever server
(dedicated on Windows and Linux, as well as servers hosted in-game). The same binary serves Nations (TMNF)
and United (TMUF); the distinction is made via the pack mask.

---

## 2. Data types and encodings

| Type | Encoding | Archive function (Ghidra) |
|---|---|---|
| `u8` | 1 byte | `0x007cf6c0` |
| `u16` | 2 bytes LE | `0x007cf6d0` |
| `u32` / `i32` | 4 bytes LE | `0x007cf6e0` |
| `str` | `u32` byte length + bytes, no null terminator. Practically ASCII; decode as UTF-8. | `0x007cf760` |
| `wstr` | UTF-16 internally, **UTF-8** on the wire: `u32` byte length + bytes. If the text contains non-ASCII characters, it is preceded by a **UTF-8 BOM `EF BB BF`** (included in the length). Decode with `utf-8-sig`. | write `0x007cf5d0`, read `0x007cf400`, conversion `0x007c6d20`, BOM at `0x0095df30` |
| `addr` | 4 bytes IPv4 in **reversed** order, followed by `u16` port (LE) | `0x004e7b30` |
| `id` | Nadeo "lookback string" (`CMwId`), see below | `0x007e5970` |

**IPv4 example:** The bytes `1d 64 1d ac` yield `172.29.100.29`. The port `2e 09` yields 2350.

**`id` (lookback string), version 3, as the server writes it:**

1. Before the **first** `id` of an archive there is a one-time `u32 version` (the server writes `3`).
2. After that, each `id` is a `u32 value`:
   - `0xFFFFFFFF`: empty.
   - `(value & 0xC0000000)` is `0x40000000` or `0x80000000`:
     - `(value & 0x0FFFFFFF) == 0`: A `str` follows. The string is appended to the table.
     - otherwise: reference to `table[(value & 0x0FFFFFFF) - 1]`.
   - otherwise: numeric collection ID (not observed so far; the server writes strings).
3. With version 2, a `str` **always** follows when the top bits are set.

**TrackMania format codes:** Names and comments often contain formatting. Strip them with this regex:
`\$(\$|[0-9a-fA-F]{1,3}|[lLhHpP]\[[^\]]*\]|.)`. `$$` becomes `$`, everything else becomes an empty string.
Examples: `$fff` (color), `$o`, `$i`, `$l[url]`.

---

## 3. TCP framing and message header

Every message on TCP:

```
u32  length            length of the following message (excluding these 4 bytes)
u8   flags             upper nibble MUST be 0x8
u8   type              message type (index into the type table, Section 6)
[u16 sequence]         only if flags & 0x0C
[u32 checksum]         only if flags & 0x02
payload                if flags & 0x01: u32 uncompressed size + LZO1X stream
                       otherwise: payload uncompressed
```

| Flag bit | Meaning |
|---|---|
| `0x80` | Mandatory marker (`(flags & 0xF0) == 0x80`, otherwise the message is discarded) |
| `0x01` | Payload is LZO1X-compressed |
| `0x02` | Checksum present. For types 0–4 it is **mandatory**: if missing, the message is discarded. |
| `0x04` | Sequence number (reliable delivery). `0x04` without `0x02` is invalid. |
| `0x08` | Sequence number (variant) |

- **Receive logic** (`0x004ff3d0`, `CNetConnection::TcpReceive`): read 4 bytes of length, then exactly that many bytes.
  The server reads with `recv` in blocks of 0x4000 bytes (`0x004e7980`).
- **Decoding** (`0x004f2eb0`): check flags, look up the type in the table, check sequence number and checksum,
  decompress, then instantiate the class or call a type-specific decoder.
- **Recommendation for clients:** Reject lengths outside 2…1 MiB. Read frames in a loop
  and skip unknown types.
- **Messages sent by the client:** always `flags = 0x82` (checksum only, uncompressed, no sequence).
- **Messages received from the server:** either `0x82` or `0x83` (compressed). Both must be supported.

---

## 4. Checksum (HMAC-MD5)

Function `0x007cfeb0` (an HMAC construction, the buffers are mixed with `0x36`/`0x5C`) using MD5
(`0x007d71f0`/`0x007d7200`/`0x007d7220`). The key is passed in by the decoder `0x004f2eb0`.

```python
KEY = struct.pack("<4I", 0x80D79DB8, 0xBA216B72, 0x15439598, 0xE1EC1CFA)   # 16 bytes

def checksum(message: bytes, pos: int) -> int:     # message = starting at the flags byte, without length prefix
    data = bytearray(message)
    data[pos:pos + 4] = b"\0\0\0\0"                  # the checksum field counts as 0
    digest = hmac.new(KEY, bytes(data), hashlib.md5).digest()
    return sum(struct.unpack("<4I", digest)) & 0xFFFFFFFF
```

- `pos` is 2 (without sequence number) or 4 (with sequence number).
- The checksum covers the **entire** message (flags, type, seq if present, payload). For compressed
  messages, this is the compressed content.
- Verified against three real packets: request 1 (`0x5895F899`), request 2 (`0x4064D43B`) and response (`0x00C21A68`).

---

## 5. Compression (LZO1X)

If `flags & 0x01`, a `u32 uncompressed_size` follows, then an **LZO1X-1** stream. The server calls
`lzo1x_decompress_safe` (`0x007d2730`), signature `(src, src_len, dst, &dst_len, wrkmem)`.

- This is why the response does contain readable text fragments (LZO copies literals raw),
  but the structure is **not parseable without decompression**: control bytes sit in the middle of the strings.
- Python has no LZO in the standard library. A complete decompressor in about 50 lines is given in
  [Section 11](#11-reference-implementation-python-standard-library-only). Alternatively, the
  `python-lzo` package works (`lzo.decompress(data, False, size)`).
- LZO1X quick reference (state = number of literals copied last):

| Code `t` | Meaning |
|---|---|
| first byte > 17 | `t-17` literals; then state 4 (if ≥ 4) or 1–3 |
| `t < 16`, state 0 | Literal run: `t+3` bytes. If `t == 0`: extended length, each `00` adds 255, then `15 + byte` |
| `t < 16`, state 4 | 3-byte match, distance `0x801 + (t>>2) + (next<<2)` |
| `t < 16`, state 1–3 | 2-byte match, distance `1 + (t>>2) + (next<<2)` |
| `t ≥ 64` (M2) | Length `(t>>5)+1`, distance `1 + ((t>>2)&7) + (next<<3)` |
| `32 ≤ t < 64` (M3) | Length `(t&31 or extended from 31)+2`, distance `1 + (LE16>>2)` |
| `16 ≤ t < 32` (M4) | Length `(t&7 or extended from 7)+2`, distance `((t&8)<<11) + (LE16>>2) + 0x4000`. Raw distance 0 means end of stream. |
| after every match | `(second-to-last byte read & 3)` literals follow; that is the new state |

---

## 6. Message types

Type table at `0x008e92c8`, entries of 7 DWORDs each:
`[class ID, type byte, checksum mandatory, ?, sequence window, ?, type-specific decoder]`.

| Type | Class | Class ID | Decoder | Meaning |
|---|---|---|---|---|
| 0 | `CNetFormQuerrySessions` | `0x12007000` | `0x004f2580` | LAN discovery: request (UDP) |
| 1 | `CNetFormEnumSessions` | `0x12008000` | `0x004f21b0` | LAN discovery: response (UDP) |
| 2 | (unnamed) | `0x12009000` | `0x004f2010` | Connection level, not analyzed |
| **3** | **`CNetFormConnectionAdmin`** | **`0x12010000`** | **`0x004f1c10`** | **Connection management incl. server query** |
| 4 | (unnamed) | `0x1201b000` | `0x004f0710` | not analyzed |
| 5… | Game forms (`0x0300A000`, …) | – | – | Game traffic, irrelevant for the query |

The type is an **index into this table**, not a class ID.

---

## 7. CNetFormConnectionAdmin and the query flow

### 7.1 Payload

```
u32 version     current version 7 (constructor 0x004f0f00 always sets 7)
u32 subtype     0..14
...             depends on subtype
```

Archive function `0x004f14a0`. When reading, it checks `subtype ≤ 14` and (except for subtype 1) `1 ≤ version ≤ 7`;
for `version < 6` there are legacy special cases.

| Subtype | Direction | Content | Meaning |
|---|---|---|---|
| 0 | C→S | Object (callback) | Connection request (game join) |
| 1 | S→C | Object with message | **Rejection**, e.g. `"Please upgrade your application."` |
| 2 / 3 | both | `u32` | Handshake steps (connection ID) |
| 4 | both | Flag | UDP status |
| 5 | C→S | `u32 request_id` | like 7, but **without a response** |
| **6** | **S→C** | **`u32 request_id`, `u32 size`, `u8[size]`** (`size ≤ 0x10000`) | **Info response** |
| **7** | **C→S** | **`u32 request_id`** | **Info request** |
| **8** | **C→S** | – | **Put the connection into query mode** |
| 9–14 | – | Strings/objects | Game handshake (14 = connection response), irrelevant for the query |

### 7.2 Flow

```
Client                                                Server
  │ TCP connect :2350                                    │  Connection state 4 (presumably right after accept)
  │── ConnectionAdmin v7 subtype 8 ──────────────────────▶│  handled immediately (0x005069a0): state 4/0x10/0x20 → 0x40
  │── ConnectionAdmin v7 subtype 7, request_id ─────────▶│  into game queue (0x00502210)
  │                                                      │  CGameNetServer (0x006aeab0): only if state == 0x40
  │◀── ConnectionAdmin v7 subtype 6, request_id, info ───│  Info = serialization of CTrackManiaNetworkServerInfo
  │ close                                                │
```

- **Subtype 8 is mandatory.** Without it the connection stays in the handshake state and the server does not
  answer subtype 7 (`0x004fe3f0` only returns 1 for state `0x40`).
- **Both messages may be sent in a single TCP write.** Subtype 8 is processed synchronously in the
  receive loop (`0x00503830`), whereas subtypes 5/6/7 are only processed afterwards via the game queue. A
  pause between the messages is not necessary.
- **`request_id`** can be chosen freely (e.g. random, ≠ `0xFFFFFFFF`). The server echoes it in the response,
  which is how you match the response. The original client uses a time or counter value (`0x0057bb20`).
- **The response typically arrives within a few milliseconds.** Other frames may theoretically come in
  between; therefore read in a loop.

### 7.3 Error and special cases

| Situation | Server behavior |
|---|---|
| `version != 7` | Response subtype 1 ("Please upgrade your application."), then disconnect |
| Subtype 8 in state 1 or `0x80` | ignored |
| Subtype 8 in another state (0, 2, 8) | Connection is closed |
| Server has no game info yet (map loading or similar) | Subtype 6 with `request_id = 0xFFFFFFFF` and empty data |
| Request with subtype 5 | Info is generated, but **not** sent |
| missing/wrong checksum for type 3 | Message is discarded (no response) |

---

## 8. The server info (response payload)

### 8.1 Serialization chain

The server serializes a `CTrackManiaNetworkServerInfo` via the virtual method `+0x78` of the class hierarchy.
Beforehand, `0x0057b730` sets the flag `+0x7C = 1` ("full info") and resets it to 0 afterwards. Each class writes
the fields of its base class first:

```
CNetMasterHost              0x004f5d90   game tag, address, host login
└ CGameNetServerInfo        0x00697d30   player login "#SRV#…"
  └ CGameCtnNetServerInfo   0x0069c0c0   counters, name, pack mask, players, comment
    └ CTrackManiaNetworkServerInfo 0x004bfc70   game mode, limit, maps, environments
```

### 8.2 Field table

| # | Type | Field | Condition / remark |
|---|---|---|---|
| 1 | `u8` | **Game tag** | `(tag & 0xE0) == 0x20` → valid (`0x004f5cd0`); `(tag & 0x1F) == 0x0D` → TrackMania (`0x004bf360`). Always `0x2D` for TmForever. |
| 2 | `addr` | Server address and port | the IP under which the server reports itself (also the LAN IP if it is bound to 127.0.0.1) |
| 3 | `str` | **Host login** | `CNetMasterHost+0x28`. In LAN mode the **computer name** (Windows: computer name, Linux: hostname). **Not** the server name! |
| 4 | `str` | **Server's player login** | `"#SRV#"` plus password flag, see 8.3. Only if the tag is valid. |
| | | *From here on only if the login starts with `#SRV#`.* | |
| 5 | `str` | unused | always written empty (`u32 0`) |
| 6 | `u8` | PlayerCount | current players |
| 7 | `u8` | MaxPlayerCount | player slots |
| 8 | `u8` | SpectatorCount | current spectators |
| 9 | `u8` | MaxSpectatorCount | spectator slots |
| 10 | `u8` | LadderMode | 0 = inactive, 1 = forced |
| 11 | `wstr` | **ServerName** | incl. format codes |
| 12 | `str` | PackMask (text) | e.g. `"Stadium"` on Nations servers (config `<packmask>stadium</packmask>`). Generated from the 128-bit mask (`0x005f86a0` → `0x0059e580`). |
| 13 | `u32 n` | Number of players | |
| 14 | `n × wstr` | Player nicknames | incl. format codes |
| 15 | `n × i32` | Ladder ranking per player | `-1` = not ranked, `0` = unknown |
| 16 | `wstr` | Comment | Server comment (`GetServerComment` reads the same field `+0x170`) |
| | | *From here on the TrackMania part* | |
| 17 | `u8` | **GameMode** (internal ID) | see 8.4 |
| 18 | `u32` | **Mode limit** | Meaning depends on the mode, see 8.4. Only with full info (always the case for the query). |
| 19 | `u8` | NbChallenges | Number of maps in the playlist, capped at 255 |
| 20 | `u32 m` | Number of maps in the packet | `min(NbChallenges, 20)` |
| 21 | `m ×` | Map entry | `wstr name`, `u32 GoldTime (ms)`, `u16 CopperPrice`, `u8 EnvironmentIndex` (`0x00698f30`), see 8.5 |
| 22 | `u32 k` | Number of environments | |
| 23 | `k × id` | Environment names | Lookback strings (Section 2), e.g. `"Stadium"`. The index from field 21 points here. |

The payload ends exactly after field 23 (checked byte-for-byte against the real capture).

**Counter correction (code finding only):** When writing, PlayerCount and MaxPlayerCount are decreased by 1
if the flag `+0x14` is set in the substructure (function `0x0069a650`). Presumably a server hosted in-game
would otherwise count itself. Dedicated servers returned the expected values live (e.g. 0/6
with `max_players` 6).

### 8.3 Password flags in the `#SRV#` login

Generated in `0x00697930`, called from `0x00697ed0` with the flags "player password set" (`+0x48`),
"spectator password set" (`+0x50`) and referee password (`+0x58`, not encoded).
The mapping to the XML-RPC methods is verified in the code:
`SetServerPassword` → `+0x48`, `SetServerPasswordForSpectator` → `+0x50`, `SetRefereePassword` → `+0x58`.

| Login | Player password | Spectator password |
|---|---|---|
| `#SRV#` | no | no |
| `#SRV#p` | **yes** | no |
| `#SRV#s` | no | **yes** |
| `#SRV#f` | **yes** | **yes** |

The strings are located in the binary at `0x00933f48` (`#SRV#f`), `0x00933f50` (`#SRV#s`), `0x00933f58` (`#SRV#p`) and `0x00933f60` (`#SRV#`).
All four variants are verified live.

### 8.4 Game modes and limit

The internal mode ID (field 17) differs from the XML-RPC/MatchSettings numbering!
Names come from `0x0048bb80`/`0x004bf470`, limits from `0x004bf280`.

| Internal | Mode | XML-RPC `GameMode` | Field 18 means | Source (server field) |
|---|---|---|---|---|
| 1 | TimeAttack | 1 | Time limit in ms | `+0x22C` = `GetTimeAttackLimit` |
| 3 | Rounds | 0 | Points limit | `+0x20C` |
| 6 | Team | 2 | Points limit | `+0x21C` |
| 7 | Laps | 3 | Number of laps | `+0x234` = `GetNbLaps` |
| 8 | Stunts | 4 | Time limit in ms | `+0x22C` |
| 9 | Cup | 5 | Points limit | `+0x23C` = `GetCupPointsLimit` |
| other | unknown | – | 0 | – |

Verified live: Rounds (30 points), TimeAttack (180000/300000 ms), Laps (5), Team (50), Cup (100).
Stunts is only statically evidenced.

### 8.5 Maps (challenges)

- Written in `0x0069c450`. Starting at the **current** playlist index, `min(count, 20)` entries are
  written, wrapping at the end of the list. **The first entry is the current map**, followed by
  the next ones in rotation order.
- **Playlists with > 20 maps are only visible as a window of 20.** Live: 60 maps on the server, 20 in the packet.
  The complete list is only available via XML-RPC (`GetChallengeList`, with credentials).
- **Names are truncated by the server to 15 characters** (UTF-16 units, before UTF-8 encoding).
- **GoldTime** is the gold medal time, not the author time. Checked against the GBX file: `B02-Race`
  has bronze 40280, silver 32980, gold **29050** and author 27410.
- **CopperPrice** is the Coppers display price (`B02-Race` = 697), capped at `0xFFFF`.
- **EnvironmentIndex** is an index into the environment list (field 23). The list contains each environment
  only once.

---

## 9. Annotated example (real capture)

Capture between a game client and an in-game hosted server "Kawabonga" (172.29.100.29),
TimeAttack, one map. The tables were generated by script from the real bytes.

### Request 1: ConnectionAdmin subtype 8

| Offset | Bytes | Field | Value |
|---:|---|---|---|
| 0x00 | `0e 00 00 00` | TCP frame length | 14 |
| 0x04 | `82` | flags | 0x82 (0x80 + 0x02 checksum) |
| 0x05 | `03` | Message type | 3 = CNetFormConnectionAdmin |
| 0x06 | `99 f8 95 58` | Checksum | 0x5895f899 |
| 0x0a | `07 00 00 00` | version | 7 |
| 0x0e | `08 00 00 00` | subtype | 8 |

### Request 2: ConnectionAdmin subtype 7 (request_id 0x00413DD5)

| Offset | Bytes | Field | Value |
|---:|---|---|---|
| 0x00 | `12 00 00 00` | TCP frame length | 18 |
| 0x04 | `82` | flags | 0x82 (0x80 + 0x02 checksum) |
| 0x05 | `03` | Message type | 3 = CNetFormConnectionAdmin |
| 0x06 | `3b d4 64 40` | Checksum | 0x4064d43b |
| 0x0a | `07 00 00 00` | version | 7 |
| 0x0e | `07 00 00 00` | subtype | 7 |
| 0x12 | `d5 3d 41 00` | request_id | 0x00413dd5 |

### Response: outer frame (as it arrives on the wire)

```
9b0000008303681ac2009b0000000a0700000006000000d53d41008b5c00000b2d1d641dac2e09
0900000050432d636539623063050000002353525623500204000106000600094402074b617761
626f6e6761075001075374616469756d0100002c6c0001ffffffff940602e09304000178030001
080000004230322d526163657a710000b9020079020374040b000040070000005374616469756d
110000
```

| Offset | Bytes | Field | Value |
|---:|---|---|---|
| 0x00 | `9b 00 00 00` | TCP frame length | 155 |
| 0x04 | `83` | flags | 0x83 (0x80 + 0x02 checksum + 0x01 LZO) |
| 0x05 | `03` | Message type | 3 = CNetFormConnectionAdmin |
| 0x06 | `68 1a c2 00` | Checksum | 0x00c21a68 |
| 0x0a | `9b 00 00 00` | Uncompressed size | 155 |
| 0x0e | `0a 07 00 00 00 06 00 00 00 d5 3d 41 00 8b 5c …` | LZO1X stream | 145 bytes |

> Note: The bytes `23 53 52 56 23 50` ("`#SRV#P`") in the raw stream are **not** "`#SRV#p`". The `50` is an
> LZO control byte. Anyone parsing without decompression will wrongly consider this server password-protected.

### Response: unpacked ConnectionAdmin payload (155 bytes)

| Offset | Bytes | Field | Value |
|---:|---|---|---|
| 0x00 | `07 00 00 00` | version | 7 |
| 0x04 | `06 00 00 00` | subtype | 6 = info response |
| 0x08 | `d5 3d 41 00` | request_id (echo) | 0x00413dd5 |
| 0x0c | `8b 00 00 00` | Server info length | 139 |

### Server info (CTrackManiaNetworkServerInfo), 139 bytes

| Offset | Bytes | Field | Value |
|---:|---|---|---|
| 0x00 | `2d` | Game tag | 0x2d → (v & 0xE0)=0x20 valid, (v & 0x1F)=0x0D TrackMania |
| 0x01 | `1d 64 1d ac` | IPv4 (reversed byte order) | 172.29.100.29 |
| 0x05 | `2e 09` | Port | 2350 |
| 0x07 | `09 00 00 00` | Host login (LAN: computer name) (length) | 9 |
| 0x0b | `50 43 2d 63 65 39 62 30 63` | Host login (LAN: computer name) | 'PC-ce9b0c' |
| 0x14 | `05 00 00 00` | Server player login + password flag (length) | 5 |
| 0x18 | `23 53 52 56 23` | Server player login + password flag | '#SRV#' |
| 0x1d | `00 00 00 00` | Unused string (always empty) (length) | 0 |
| 0x21 | `01` | PlayerCount | 1 |
| 0x22 | `06` | MaxPlayerCount | 6 |
| 0x23 | `00` | SpectatorCount | 0 |
| 0x24 | `06` | MaxSpectatorCount | 6 |
| 0x25 | `00` | LadderMode | 0 |
| 0x26 | `09 00 00 00` | ServerName (wstr) (length) | 9 |
| 0x2a | `4b 61 77 61 62 6f 6e 67 61` | ServerName (wstr) | 'Kawabonga' |
| 0x33 | `07 00 00 00` | PackMask (text) (length) | 7 |
| 0x37 | `53 74 61 64 69 75 6d` | PackMask (text) | 'Stadium' |
| 0x3e | `01 00 00 00` | Number of players | 1 |
| 0x42 | `09 00 00 00` | Player[0].Name (wstr) (length) | 9 |
| 0x46 | `4b 61 77 61 62 6f 6e 67 61` | Player[0].Name (wstr) | 'Kawabonga' |
| 0x4f | `ff ff ff ff` | Player[0].LadderRanking | -1 (not ranked) |
| 0x53 | `00 00 00 00` | Comment (wstr) (length) | 0 |
| 0x57 | `01` | GameMode | 1 = TimeAttack |
| 0x58 | `e0 93 04 00` | Mode limit | 300000 ms = 5:00 min |
| 0x5c | `01` | NbChallenges (playlist, max 255) | 1 |
| 0x5d | `01 00 00 00` | Number of challenges in the packet | 1 |
| 0x61 | `08 00 00 00` | Challenge[0].Name (wstr, ≤15 characters) (length) | 8 |
| 0x65 | `42 30 32 2d 52 61 63 65` | Challenge[0].Name (wstr, ≤15 characters) | 'B02-Race' |
| 0x6d | `7a 71 00 00` | Challenge[0].GoldTime (ms) | 29050 |
| 0x71 | `b9 02` | Challenge[0].CopperPrice | 697 |
| 0x73 | `00` | Challenge[0].EnvironmentIndex | 0 |
| 0x74 | `01 00 00 00` | Number of environments | 1 |
| 0x78 | `03 00 00 00` | Id version | 3 (only before the first id in the archive) |
| 0x7c | `00 00 00 40` | Id value | 0x40000000 → new string follows (index 0, bit 30) |
| 0x80 | `07 00 00 00` | Environment[0] (length) | 7 |
| 0x84 | `53 74 61 64 69 75 6d` | Environment[0] | 'Stadium' |

**Example of a comment with umlauts** (live capture from a Windows dedicated server):
`1d000000 efbbbf 4c6976652d54657374204b6f6d6d656e74617220 c3a4c3b6c3bc`. That is
29 bytes including the BOM and yields `"Live-Test Kommentar äöü"`.

---

## 10. Robust detection of a TrackMania server

A host is a TmForever server if and only if **all** of the following hold:

1. A TCP connection to port 2350 (or the configured `server_port`) is possible.
2. After sending subtype 8 and subtype 7, a frame with a valid header arrives (`flags & 0xF0 == 0x80`).
3. **The checksum is correct.** This alone practically rules out third-party services, since without the key
   it cannot be generated.
4. Type 3, version 7, subtype 6, `request_id` matches your own.
5. The game tag is `0x2D` (`(t & 0xE0) == 0x20 && (t & 0x1F) == 0x0D`).
6. The structure can be fully parsed with length checks.

**Practical values:**

- A server responds within a few ms (LAN 1–8 ms). For network scans, timeouts of 1–1.5 s per host suffice,
  with about 64 parallel connections. A /23 network (510 hosts) thus takes about 12 s.
- Multiple servers on one host usually use consecutive ports (2350, 2351, …). A separate query is needed
  for each port.

---

## 11. Reference implementation (Python, standard library only)

Tested: The generated requests are byte-identical to the original client, and the real capture is
fully decoded. Works live against dedicated servers on Windows and Linux.
Usage: `python tmnf_query.py <host> [port]`.

```python
"""TrackMania Forever server query - minimal reference implementation (stdlib only)."""
import hashlib
import hmac
import secrets
import socket
import struct

KEY = struct.pack("<4I", 0x80D79DB8, 0xBA216B72, 0x15439598, 0xE1EC1CFA)
GAME_MODES = {1: "TimeAttack", 3: "Rounds", 6: "Team", 7: "Laps", 8: "Stunts", 9: "Cup"}


def checksum(message: bytes, pos: int) -> int:
    data = bytearray(message)
    data[pos:pos + 4] = bytes(4)                      # checksum field counts as 0
    digest = hmac.new(KEY, bytes(data), hashlib.md5).digest()
    return sum(struct.unpack("<4I", digest)) & 0xFFFFFFFF


def build_message(msg_type: int, payload: bytes) -> bytes:
    msg = bytearray([0x82, msg_type]) + bytes(4) + payload   # flags 0x80 | 0x02 (checksum)
    msg[2:6] = struct.pack("<I", checksum(msg, 2))
    return struct.pack("<I", len(msg)) + bytes(msg)          # TCP frame: u32 length


def connection_admin(subtype: int, *args: int) -> bytes:
    return build_message(3, struct.pack(f"<II{len(args)}I", 7, subtype, *args))


def lzo1x_decompress(src: bytes, size: int) -> bytes:
    out, ip, state = bytearray(), 0, 0

    def run(base):                                   # extended length: each 0 byte adds 255
        nonlocal ip
        n = 0
        while src[ip] == 0:
            n += 255
            ip += 1
        n += base + src[ip]
        ip += 1
        return n

    def literals(n):
        nonlocal ip
        out.extend(src[ip:ip + n])
        ip += n

    def match(pos, n):
        if pos < 0:
            raise ValueError("bad LZO distance")
        for i in range(n):                           # byte by byte: source may overlap
            out.append(out[pos + i])

    if src[0] > 17:                                  # first byte > 17: initial literal run
        n = src[0] - 17
        ip = 1
        literals(n)
        state = n if n < 4 else 4
    while True:
        t = src[ip]
        ip += 1
        if t < 16:
            if state == 0:                           # literal run
                literals((t or run(15)) + 3)
                state = 4
                continue
            d = (t >> 2) + (src[ip] << 2)
            ip += 1
            if state == 4:
                match(len(out) - 0x801 - d, 3)       # M1 directly after a literal run
            else:
                match(len(out) - 1 - d, 2)           # M1 after a match
        elif t >= 64:                                # M2
            d = ((t >> 2) & 7) + (src[ip] << 3)
            ip += 1
            match(len(out) - 1 - d, (t >> 5) + 1)
        elif t >= 32:                                # M3
            n = (t & 31 or run(31)) + 2
            d = (src[ip] | src[ip + 1] << 8) >> 2
            ip += 2
            match(len(out) - 1 - d, n)
        else:                                        # M4 (16..31), distance 0 = end of stream
            n = (t & 7 or run(7)) + 2
            d = ((t & 8) << 11) + ((src[ip] | src[ip + 1] << 8) >> 2)
            ip += 2
            if d == 0:
                break
            match(len(out) - d - 0x4000, n)
        state = src[ip - 2] & 3                      # 0-3 literals follow the match
        if state:
            literals(state)
    if len(out) != size:
        raise ValueError("LZO size mismatch")
    return bytes(out)


def decode_message(msg: bytes):
    flags, msg_type, pos = msg[0], msg[1], 2
    if flags & 0xF0 != 0x80:
        raise ValueError("bad flags")
    if flags & 0x0C:
        pos += 2                                     # u16 sequence number
    if flags & 0x02:
        if struct.unpack_from("<I", msg, pos)[0] != checksum(msg, pos):
            raise ValueError("bad checksum")
        pos += 4
    if flags & 0x01:                                 # u32 uncompressed size + LZO1X stream
        size = struct.unpack_from("<I", msg, pos)[0]
        return msg_type, lzo1x_decompress(msg[pos + 4:], size)
    return msg_type, msg[pos:]


class Reader:
    def __init__(self, data):
        self.d, self.p = data, 0

    def take(self, n):
        if n < 0 or self.p + n > len(self.d):
            raise ValueError("truncated")
        self.p += n
        return self.d[self.p - n:self.p]

    def u8(self):
        return self.take(1)[0]

    def u16(self):
        return struct.unpack("<H", self.take(2))[0]

    def u32(self):
        return struct.unpack("<I", self.take(4))[0]

    def i32(self):
        return struct.unpack("<i", self.take(4))[0]

    def str(self):
        return self.take(self.u32()).decode("utf-8", "replace")

    def wstr(self):                                  # UTF-8, BOM if non-ASCII
        return self.take(self.u32()).decode("utf-8-sig", "replace")


def parse_server_info(data: bytes) -> dict:
    r = Reader(data)
    tag = r.u8()
    if tag & 0xE0 != 0x20 or tag & 0x1F != 0x0D:
        raise ValueError("not a TrackMania server")
    info = {"address": ".".join(map(str, reversed(r.take(4)))), "port": r.u16(),
            "host_login": r.str()}
    login = r.str()                                  # "#SRV#" + "" / "p" / "s" / "f"
    if not login.startswith("#SRV#"):
        return info
    info["player_password"] = login[5:6] in ("p", "f")
    info["spectator_password"] = login[5:6] in ("s", "f")
    r.str()                                          # unused, always empty
    for key in ("players", "max_players", "spectators", "max_spectators", "ladder_mode"):
        info[key] = r.u8()
    info["name"], info["pack_mask"] = r.wstr(), r.str()
    names = [r.wstr() for _ in range(r.u32())]
    info["player_list"] = [(name, r.i32()) for name in names]   # (nickname, ladder ranking)
    info["comment"] = r.wstr()
    if r.p == len(data):
        return info
    mode = r.u8()
    info["game_mode"] = GAME_MODES.get(mode, f"Unknown ({mode})")
    info["mode_limit"] = r.u32()                     # ms (TA/Stunts), laps (Laps), points
    info["nb_challenges"] = r.u8()
    maps = [(r.wstr(), r.u32(), r.u16(), r.u8()) for _ in range(r.u32())]
    envs, table, version = [], [], None
    for _ in range(r.u32()):                         # Nadeo "lookback string" ids
        if version is None:
            version = r.u32()                        # 2 or 3, only before the first id
        v = r.u32()
        if v == 0xFFFFFFFF:
            envs.append("")
        elif v & 0xC0000000 in (0x40000000, 0x80000000):
            if version == 2 or v & 0x0FFFFFFF == 0:
                table.append(r.str())
                envs.append(table[-1])
            else:
                envs.append(table[(v & 0x0FFFFFFF) - 1])
        else:
            envs.append(str(v))                      # numeric collection id
    info["challenges"] = [
        {"name": n, "gold_time": g, "copper_price": c, "environment": envs[e] if e < len(envs) else "?"}
        for n, g, c, e in maps
    ]
    return info


def query(host: str, port: int = 2350, timeout: float = 5.0) -> dict:
    request_id = secrets.randbelow(0x7FFFFFFF) + 1
    with socket.create_connection((host, port), timeout) as s:
        s.sendall(connection_admin(8) + connection_admin(7, request_id))  # query mode + info request
        f = s.makefile("rb")
        while True:
            (length,) = struct.unpack("<I", f.read(4))
            if not 2 <= length <= 0x100000:
                raise ValueError("bad frame length")
            msg_type, payload = decode_message(f.read(length))
            if msg_type != 3:
                continue
            r = Reader(payload)
            version, subtype = r.u32(), r.u32()
            if version != 7 or subtype == 1:
                raise ValueError("query refused")
            if subtype != 6:
                continue
            reply_id, data = r.u32(), r.take(r.u32())
            if reply_id == 0xFFFFFFFF:
                raise ValueError("server has no game info yet")
            if reply_id == request_id:
                return parse_server_info(data)


if __name__ == "__main__":
    import json
    import sys

    port = int(sys.argv[2]) if len(sys.argv) > 2 else 2350
    print(json.dumps(query(sys.argv[1], port), indent=2, ensure_ascii=False))
```

**Self-test:** The following expressions must evaluate to true.

```python
connection_admin(8).hex()             == "0e000000820399f895580700000008000000"
connection_admin(7, 0x00413DD5).hex() == "1200000082033bd464400700000007000000d53d4100"
```

The response from Section 9 must, after `decode_message(...)[1][16:]` and `parse_server_info`, yield the name
`Kawabonga`, the mode TimeAttack with 300000 ms, and the map `B02-Race` (gold 29050, copper 697, Stadium).

---

## 12. UDP LAN discovery (partially analyzed)

> ⚠️ **Statically analyzed, not verified live.** Not needed for the TCP query above. Interesting as an
> alternative to TCP-scanning whole network ranges.

The game client searches for LAN servers via UDP broadcast (`CGameNetwork::FindServers`, `0x0057d6f0`):

- **Target:** Broadcast (`FUN_004e7c60(3, port)`) to the server port and the following ports. The number
  comes from the network config (`+0x36`); the exact values are not confirmed.
- **Timing:** For each port, a request is sent after a fixed wait time (`_DAT_009f2c94`).
- **Request** (`CNetFormQuerrySessions`, message type **0**, checksum mandatory): Built by `0x00502900`/`0x00502350`,
  archived in `0x004f24d0`:
  ```
  str  game_id     length 4..255; the server compares it with its identifier (presumably "TmForever",
                   global string 0x00a2a4a8, set at 0x00552774)
  str  ?           length 1..255; not checked by the server
  u32  nonce       echoed in the response
  ```
- **Server** (`0x00506730`): Only responds if `game_id` matches, namely with `CNetFormEnumSessions`
  (type **1**) to the sender address (`0x005062a0`).
- **Response** (`0x004f2120`, `CNetServerInfo` archive `0x004f73d0`):
  ```
  u32  nonce
  str  (0..255), str (4..255, presumably game_id), str (1..255), str (0..255)
  addr, addr     two IPv4/port pairs (6 bytes, encoding as above)
  ```
  The semantics of the strings are unclear. Player counts and map are **not** included in this response;
  the TCP query is needed afterwards for that.

---

## 13. Verification status

| Aspect | Static (Ghidra) | Real capture | Live Windows dedicated | Live Linux dedicated |
|---|:-:|:-:|:-:|:-:|
| Framing, flags, type 3 | ✅ | ✅ | ✅ | ✅ |
| HMAC-MD5 checksum | ✅ | ✅ (3 packets) | ✅ | ✅ |
| LZO1X | ✅ | ✅ | ✅ | ✅ |
| Flow subtype 8 → 7 → 6, sent in one write | ✅ | ✅ | ✅ | ✅ |
| Game tag `0x2D` | ✅ | ✅ | ✅ | ✅ |
| `#SRV#` / `p` / `s` / `f` | ✅ | `#SRV#` | ✅ all 4 | `#SRV#` |
| Counters (players/spectators) | ✅ | ✅ | ✅ | ✅ |
| Server name/comment with Unicode + BOM | ✅ | – | ✅ | – |
| Game modes Rounds/TA/Laps/Team/Cup + limit | ✅ | TA | ✅ | TA |
| Stunts (8) | ✅ | – | – (no Stunts maps) | – |
| Window of 20 maps / truncation to 15 characters | ✅ | – | ✅ (15 maps) | ✅ (60 → 20) |
| GoldTime/CopperPrice | ✅ | ✅ (checked against GBX) | ✅ | ✅ |
| Host login = computer name | ✅ | ✅ | ✅ | ✅ (hostname) |
| Sequence flags, id version 2, numeric ids | ✅ | – | – | – |
| UDP LAN discovery | partial | – | – | – |
| Counter correction (flag `+0x14`) | ✅ | – | – | – |

---

## 14. Common misconceptions

These points made earlier, heuristic implementations fail:

1. **"The response is plain text with fixed offsets."** Wrong, the payload is usually **LZO-compressed**.
   String searching or fixed offsets in the raw stream only work by coincidence.
2. **"The byte after `#SRV#` is the server type."** Wrong. The suffix is part of the string (length 5 or 6);
   in the raw stream an LZO control byte follows (`0x50` = "P"). The suffix encodes passwords, not
   private/ladder/public.
3. **"The first string is the server name."** Wrong. It is the host login, i.e. the computer name. The server name
   comes later as a `wstr`.
4. **"Game mode 0 = TimeAttack, 6 = Team …"** The internal numbering is 1/3/6/7/8/9 (Section 8.4) and
   differs from XML-RPC.
5. **"After subtype 8 you have to wait 200 ms."** Not necessary, both messages can be sent together.
6. **"It is a UDP announcement to the master server."** Wrong, it is the TCP query directly against the game server.
7. **"The query returns all maps."** Only up to 20, starting with the current one.
8. **"A single `read()` returns the complete response."** TCP does not guarantee that. Read the length prefix
   and then exactly that many bytes, in a loop.

---

## 15. Ghidra index (addresses, class IDs)

Binary: `TrackmaniaServer.exe` 2011-02-21, image base `0x00400000`. In Ghidra, the function
`0x004f1c10` was additionally created as `CNetFormConnectionAdmin_Dispatch`, as well as `0x004f2580`.

### 15.1 Network layer

| Address | Function | Purpose |
|---|---|---|
| `0x004e7980` | CNetTcpConnectedSocket::Receive | `recv()` in blocks of 0x4000 bytes |
| `0x004e70c0` | CNetUDP::ReceiveFrom | `recvfrom()`, max. 0x578 bytes |
| `0x004ff3d0` | CNetConnection::TcpReceive | `u32` length prefix, assemble message |
| `0x004f2eb0` | Decode message | flags, type table, sequence, checksum, LZO, instantiation |
| `0x004f2870` | Encode message | counterpart for sending |
| `0x007cfeb0` | HMAC-MD5 | checksum (key from caller) |
| `0x007d2730` | lzo1x_decompress_safe | decompression |
| `0x008e92c8` | Data | message type table (7 DWORDs per entry) |
| `0x00503830` | CNetServer receive loop | routing: ConnectionAdmin subtypes 5/6/7 to the game queue (`0x00502210`), rest immediately |
| `0x005069a0` | ConnectionAdmin handler | version check (7), subtypes 0/2/4/8/14 |
| `0x004fe3f0` | Connection state | state `0x40` → "ready for queries" |
| `0x00506730` | CNetServer UDP receive | QuerrySessions → EnumSessions |

### 15.2 ConnectionAdmin and query

| Address | Function | Purpose |
|---|---|---|
| `0x008ab25f` | Class registration | `0x12010000` "CNetFormConnectionAdmin", factory `0x004f1200` |
| `0x004f0f00` | Constructor | `version = 7`, `subtype = parameter` |
| `0x004f1c10` → `0x004f14a0` | Decoder/archive | subtype switch (fields per subtype) |
| `0x0057bb20` | Client | sends subtype 7 |
| `0x006aeab0` | CGameNetServer (vtable `0x00937e7c` + `0xB8`) | answers subtype 7 with subtype 6 |
| `0x006ae3c0` → `0x0057b730` | Serialize server info | sets `+0x7C = 1` (full info) |

### 15.3 Server info

| Address | Function | Purpose |
|---|---|---|
| `0x004bfc70` | CTrackManiaNetworkServerInfo (vtable `0x008f848c` + `0x78`) | mode, limit, maps |
| `0x0069c0c0` | CGameCtnNetServerInfo (vtable `0x009344e4` + `0x78`) | counters, name, pack mask, players, comment |
| `0x00697d30` | CGameNetServerInfo (vtable `0x00933ff4` + `0x78`) | `#SRV#` login (`+0x88`) |
| `0x004f5d90` | CNetMasterHost (vtable `0x008fdccc` + `0x78`) | game tag `+0x14`, address `+0x18`, login `+0x28` |
| `0x0069a650` | Substructure `+0xB8` | counters and server name |
| `0x0069b8c0`, `0x0069b970`, `0x0061efd0` | Lists | write/read `u32` count |
| `0x0069c450` | Maps | window of 20, environments |
| `0x00698f30` | Map entry | name, GoldTime, CopperPrice, EnvIndex |
| `0x007e5970` | CMwId | lookback strings |
| `0x004bf6c0` / `0x004bf280` | Mode / limit | `u8` mode, `u32` mode-dependent limit |
| `0x004f5cd0` / `0x004bf360` | Tag check | valid / TrackMania |
| `0x00697930`, `0x00697ed0` | `#SRV#` login | password flags p/s/f |
| `0x00697df0` / `0x00697e60` | vtable `+0xB8` / `+0xBC` | player / spectator password active |
| `0x0048bb80`, `0x004bf470` | Mode names | internal ID → name/filter index |
| `0x005f86a0`, `0x0059e580` | Pack mask | 128-bit mask → text (`+0x1E8`) |
| `0x00699140` / `0x00697b50` / `0x004bfcf0` | GetParam | reflection of CGameCtnNetServerInfo / CGameNetServerInfo / CTrackManiaNetworkServerInfo |

### 15.4 Archive primitives

`u8 0x007cf6c0`, `u16 0x007cf6d0`, `u32 0x007cf6e0`, `str 0x007cf760`, `wstr 0x007cf770`
(write `0x007cf5d0`, read `0x007cf400`), UTF-16→UTF-8 with BOM `0x007c6d20`, address `0x004e7b30`.

### 15.5 XML-RPC handlers that confirm the field semantics

| Method | Handler | Field |
|---|---|---|
| SetServerPassword | `0x005a36d0` → `0x0059e710` | `+0x48` |
| SetServerPasswordForSpectator | `0x005a3770` → `0x0059e760` | `+0x50` |
| SetRefereePassword | `0x005a3810` → `0x0059e790` | `+0x58` |
| GetTimeAttackLimit | `0x0049b890` → `0x00495ed0` | `+0x22C` |
| GetNbLaps | `0x0049bbc0` → `0x00496020` | `+0x234` |
| GetLapsTimeLimit | `0x0049bab0` → `0x00495f80` | `+0x238` |
| GetCupPointsLimit | `0x0049c4f0` → `0x00496430` | `+0x23C` |
| GetServerComment | `0x005a35c0` → `0x0059e660` | `+0x170` |
| GetServerPackMask | `0x005a1530` → `0x0059e550` | `+0x1F0` (mask) |

### 15.6 UDP discovery

`CGameNetwork::FindServers` `0x0057d6f0`; sending QuerrySessions `0x00502900` (constructor `0x00502350`,
archive `0x004f24d0`); building EnumSessions `0x005062a0` (copy `0x00505360`), archive
`0x004f2120`/`0x004f73d0`; identifier "TmForever" at `0x00a2a4a8`.

### 15.7 Class IDs

| Class | ID |
|---|---|
| CNetServerInfo | `0x12002000` |
| CNetFormQuerrySessions | `0x12007000` |
| CNetFormEnumSessions | `0x12008000` |
| CNetFormConnectionAdmin | `0x12010000` |
| CGameNetServerInfo | `0x0302E000` |
| CGameCtnNetServerInfo | `0x030BB000` |
| CGameCtnChallengeInfo | `0x03044000` |
| CTrackManiaNetworkServerInfo | `0x24035000` |

---

## 16. Existing implementations

| Project | File | Status |
|---|---|---|
| opengsq-python | `opengsq/protocols/trackmania_nations.py`, `opengsq/responses/trackmania_nations/server_info.py`, tests `tests/protocols/test_trackmania_nations.py` | Newly implemented based on this document (branch `fix/trackmania-nations-protocol`). Async, with tests against real captures and a fake server. |
| Discord-Gameserver-Notifier | `src/discord_gameserver_notifier/discovery/protocols/trackmania_nations.py` | Network range scan via TCP; uses opengsq; strips format codes for Discord. |

Local paths: `C:\Users\Gamienator\Documents\opengsq\opengsq-python` and
`C:\Users\Gamienator\Documents\dgn\Discord-Gameserver-Notifier`, respectively.
