# Network Monitor

A network scanner running on Raspberry Pi 5 that continuously monitors all devices on a local network.
Uses ARP packets to scan the network every 60 seconds, stores device data in a SQLite database, and alerts when new devices join.
Built with Python and Scapy, runs as a systemd background service.

## Features
- ARP network scanning every 60 seconds
- New device detection with alerts
- SQLite storage with duplicate prevention
- Timestamps tracking when each device was last seen
- Runs automatically on boot as a systemd service

## Stack
- Python 3
- Scapy
- SQLite3
- systemd
