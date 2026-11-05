# P2PEEONME

Experimental direct TLS file-transfer reference prototype targeting Chromebook Linux and Windows 11.

## Provenance and status

Reconstructed from source visible in the conversation. This commit is not a byte-identical recovery of the lost ZIP. These proposed files have not been executed or tested in this turn. Four tests were reported for an earlier rebuild; that result must not be treated as validation of this commit. Run `python test_transfer.py` to obtain current results.

The UI name is P2PEEONME. The marble-and-bronze redesign is not implemented.

## Run

Requires Python 3.10+, Tk, pip and venv. First launch installs cryptography from the Internet into a local virtual environment.

- Chromebook Linux: install python3-venv and python3-tk if missing, then run `sh Start-Linux.sh`.
- Windows 11: install Python including Tk and the Python launcher, then run `Start-Windows.bat`.
- Test two windows on one computer with loopback defaults before using two computers.
- To use a LAN or existing trusted VPN, enter the sender's reachable address and listen IP; restrict firewall access to the friend on TCP 47831.
- Keep the sender running and send invitations only through an authenticated private channel. Invitations are bearer secrets.

## Implemented reference behavior

TLS 1.3; invitation-pinned certificate checked before sending the secret; regular-file contents; 1 MiB chunks; zlib/raw compression selection; SHA-256 chunk/final verification; parallel workers; partial-byte rehash/resume; no-overwrite hard-link publication.

## Limitations

Experimental trusted-peer LAN/VPN use only. No automatic NAT traversal, relay, persistent pairing, offline delivery, standalone installers, automatic updates, public security audit, or proven speed booster. No independent-link bonding or guaranteed compression ratio. No arbitrary partial-program execution.

This reconstruction uses zlib rather than the earlier Zstandard design and rehashes partial bytes rather than storing SQLite progress. It does not implement a global or transfer-local deduplication inventory.

Destinations must support hard links (for example a validated local ext4/NTFS/APFS filesystem); exFAT/FAT32 and some network/cloud destinations are unsupported. Empty directories and filesystem metadata are not preserved. Symlinks and some nonportable filenames are rejected; full cross-platform behavior is unverified.

The sender keeps manifests in memory. Large file counts and full files over 4 GiB have not been validated. Receiver limits the file count to one million. There is no disk-space reservation or interprocess output lock; do not run jobs into the same destination concurrently.

No automatic retry: rerun to revalidate and reuse partial bytes. Keep sources stable during a share. Invitations do not automatically expire; pin validation does not enforce certificate date expiry. Stop rejects future requests, but an in-flight chunk can finish. Private key/session files are not automatically cleaned up.

Not hardened against malicious peers, connection floods, resource exhaustion, or local filesystem race attacks. Use private local output directories. Do not expose this listener broadly to the public Internet.

## Next milestones

1. Execute tests and verify actual Chromebook Linux to Windows 11 transfers in both directions.
2. Package dependencies and add durable device pairing and automatic connectivity.
3. Implement the agreed marble/bronze interface.
4. Measure actual data/links before claiming optimization benefits.
