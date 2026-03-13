# MemZTector
MemZTector is a PoC developed in the paper "From RAM to Topology: Forensic Analysis of ZeroTier One-Systems"

# ZeroTier Memory Artifact Extractor

This proof of concept extracts selected ZeroTier-related artefacts from a raw memory dump. It identifies the network ID, the configured target subnet, the optional network name, IPv4 addresses within the detected subnet, and public endpoint addresses found in ZeroTier-related JSON-like structures.

## Features

- searches process dump files (extracted from memory dumps) for ZeroTier-specific memory artefacts
- extracts:
  - network ID / NWID
  - target subnet
  - optional network name
  - IPv4 addresses belonging to the detected subnet
  - public IPv4 endpoints from `surfaceAddresses` and `listeningOn`
- stores intermediate results in a temporary SQLite database
- outputs unique results in a readable text format

## Requirements

- Python 3.9 or newer
- standard library only:
  - `re`
  - `sys`
  - `ipaddress`
  - `sqlite3`
  - `tempfile`
  - `os`

No external dependencies are required.

## Usage

```bash
python3 zt_extract.py <path_to_dumpfile>
