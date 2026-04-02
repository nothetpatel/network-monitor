# Network Monitor

A network scanner running on Raspberry Pi 5 that detects all devices on a local network.
Uses ARP packets to scan the network, stores device data in a SQLite database, and tracks when devices were last seen.
Built with Python and Scapy.

## Features
- ARP network scanning
- SQLite storage with duplicate prevention
- Timestamps for device tracking
