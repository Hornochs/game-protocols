# Call of Duty 4 Server Query Protocol

This document outlines the protocol for querying Call of Duty 4 servers to retrieve information such as server status, player details, and game settings.

## Overview

Call of Duty 4 uses a UDP-based query protocol that allows external applications to retrieve server information. The protocol supports two main query types: `getinfo` for basic server information and `getstatus` for comprehensive server and player data.

**Default Port:** 28960  
**Protocol:** UDP  
**Source Port Requirement:** Queries must be sent from port 28960  

## Query Methods

### getinfo

The `getinfo` command retrieves basic server information without player data.

**Request Format:**
```
\xFF\xFF\xFF\xFF + "getinfo " + challenge
```

**Example Request:**
```
\xFF\xFF\xFF\xFFgetinfo xxx
```

**Response Format:**
```
\xFF\xFF\xFF\xFF + "infoResponse\n" + key-value pairs
```

**Example Response:**
```
\xFF\xFF\xFF\xFFinfoResponse
\sv_maxPing\350\voice\0\mod\0\hw\1\od\1\hc\1\ki\1\ff\0\pswrd\0\shortversion\x21\build\1154\pure\1\gametype\war\sv_maxclients\30\g_humanplayers\0\clients\0\mapname\mp_backlot\hostname\LinuxGSM\protocol\6\challenge\xxx
```

### getstatus

The `getstatus` command retrieves comprehensive server information including player data.

**Request Format:**
```
\xFF\xFF\xFF\xFF + "getstatus"
```

**Example Request:**
```
\xFF\xFF\xFF\xFFgetstatus
```

**Response Format:**
```
\xFF\xFF\xFF\xFF + "statusResponse\n" + key-value pairs + "\n" + player data
```

**Example Response:**
```
\xFF\xFF\xFF\xFFstatusResponse
\sv_maxclients\32\version\CoD4 X - linux-i386 build 1154 May  1 2022\shortversion\-\build\1154\branch\master\revision\0beb470e43b71d1567d068518a61f8003870176d\protocol\21\sv_privateClients\2\sv_hostname\LinuxGSM\sv_minPing\0\sv_maxPing\350\sv_disableClientConsole\0\sv_voice\0\g_mapStartTime\Thu Oct  9 11:28:31 2025\uptime\12 minutes\g_gametype\war\mapname\mp_bloc\sv_maxRate\100000\sv_floodprotect\4\sv_pure\1\gamename\Call of Duty 4\g_compassShowEnemies\0\_Admin\Admin
```

## Data Format

### Key-Value Pairs

Server information is encoded as key-value pairs separated by backslashes (`\`):
```
\key1\value1\key2\value2\key3\value3
```

### Player Data Format

Player information follows the server data and is formatted as:
```
score ping "playername"
```

Example:
```
15 45 "Player1"
8 67 "Player2"
0 23 "NewPlayer"
```

## Server Information Fields

### Basic Information (getinfo)

| Field | Description | Example |
|-------|-------------|---------|
| `hostname` | Server name | `LinuxGSM` |
| `mapname` | Current map | `mp_backlot` |
| `gametype` | Game mode code | `war` |
| `clients` | Current players | `8` |
| `sv_maxclients` | Maximum players | `30` |
| `protocol` | Protocol version | `6` |
| `build` | Build number | `1154` |
| `pure` | Pure server (1/0) | `1` |
| `pswrd` | Password protected (1/0) | `0` |
| `mod` | Mod running (1/0) | `0` |
| `voice` | Voice chat enabled (1/0) | `0` |
| `ff` | Friendly fire (1/0) | `0` |
| `hc` | Hardcore mode (1/0) | `1` |

### Extended Information (getstatus)

| Field | Description | Example |
|-------|-------------|---------|
| `sv_hostname` | Server name | `LinuxGSM` |
| `version` | Full version string | `CoD4 X - linux-i386 build 1154 May 1 2022` |
| `gamename` | Game name | `Call of Duty 4` |
| `uptime` | Server uptime | `12 minutes` |
| `g_gametype` | Game mode code | `war` |
| `g_mapStartTime` | Map start time | `Thu Oct 9 11:28:31 2025` |
| `sv_maxRate` | Maximum rate | `100000` |
| `sv_floodprotect` | Flood protection | `4` |
| `sv_minPing` | Minimum ping | `0` |
| `sv_maxPing` | Maximum ping | `350` |
| `sv_privateClients` | Private client slots | `2` |
| `branch` | Code branch | `master` |
| `revision` | Git revision | `0beb470e43b71d1567d068518a61f8003870176d` |

## Game Type Codes

The `gametype` field uses specific codes to represent different game modes:

| Code | Game Mode | Description |
|------|-----------|-------------|
| `dm` | Death Match | Free-for-all deathmatch |
| `war` | Team Death Match | Team-based elimination |
| `dom` | Domination | Control point capture |
| `koth` | HQ | Headquarters (King of the Hill) |
| `sab` | Sabotage | Bomb planting/defusing |
| `sd` | Search and Destroy | Round-based elimination |

## Protocol Implementation

### Source Port Requirement

CoD4 servers require queries to originate from port 28960. This is a unique requirement of the CoD4 protocol and must be handled by the client implementation.

### Challenge String

The `getinfo` command accepts an optional challenge string (typically "xxx"). This can be used for server authentication or tracking purposes.

### Response Parsing

1. **Header Validation**: Verify the response starts with `\xFF\xFF\xFF\xFF`
2. **Response Type**: Extract the response type (`infoResponse` or `statusResponse`)
3. **Key-Value Parsing**: Split the remaining data by backslashes and process pairs
4. **Player Data**: For `getstatus`, parse player lines after the server data

### Error Handling

- **Timeout**: No response within the specified timeout period
- **Invalid Header**: Response doesn't start with the expected header
- **Malformed Data**: Key-value pairs are incomplete or corrupted
- **Socket Errors**: Network connectivity issues

## Security Notes

- The protocol transmits data in plain text
- No authentication is required for basic queries
- Server information is publicly accessible
- Consider implementing request validation in production environments
