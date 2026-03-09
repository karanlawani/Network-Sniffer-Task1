# Network-Sniffer-Task1
Basic Network Sniffer - Arch Technologies Internship

# Basic Network Sniffer 🌐

## Project Overview
A basic network sniffer built in Python that captures and analyzes 
network traffic in real-time.

## Built With
- Python 3.12
- Scapy 2.7.0
- Npcap (Windows)

## Features
- Captures live network packets (TCP, UDP, ICMP)
- Displays source and destination IP addresses and ports
- Shows real-time timestamps for each packet
- Saves captured packets to a log file
- Displays capture summary at the end

## Requirements
- Python 3.x
- Scapy library
- Npcap (for Windows users)

## Installation
pip install scapy

## How to Run
Run as Administrator:
python sniffer.py

## Sample Output
[2026-03-09 21:46:38] [TCP] 151.101.134.172:443 -> 192.168.100.181:1500
[2026-03-09 21:46:39] [UDP] 192.168.100.181:63664 -> 157.240.227.60:443

## Capture Summary
- TCP  packets: 42
- UDP  packets: 8
- ICMP packets: 0
- TOTAL: 50

## Internship
Arch Technologies - Cyber Security Internship
Task 1: Basic Network Sniffer
