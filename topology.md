# GNS3 Network Topology

## Overview

This topology creates an isolated environment for safely demonstrating DNS vulnerabilities.

## Components

- **Attacker Machine**: Kali Linux VM (Attacker)
- **DNS Server**: Ubuntu Server with BIND9 configured (Primary Target)
- **Secondary DNS Server**: Ubuntu Server with BIND9 (For cache poisoning demonstration)
- **Client Machine**: Ubuntu Desktop (Victim)
- **Router**: Basic L3 routing between networks

## Network Layout

1. **Attack Network**: 192.168.1.0/24

   - Attacker: 192.168.1.10
   - Router Interface: 192.168.1.1

2. **Target Network**: 192.168.2.0/24

   - Primary DNS Server: 192.168.2.10
   - Secondary DNS Server: 192.168.2.20
   - Client: 192.168.2.30
   - Router Interface: 192.168.2.1

3. **Example Domain Network**: 10.0.0.0/24 (simulated external network)
   - Legitimate Web Server: 10.0.0.10
   - Router Interface: 10.0.0.1

## Connectivity

- All machines can reach each other through the router
- The client is configured to use the Secondary DNS Server for name resolution
- The Secondary DNS Server forwards requests to the Primary DNS Server

## Simulation Details

- Use Docker containers where possible for efficiency
- Attacker: Kali Linux Docker image with necessary tools installed
- DNS Servers: Ubuntu with BIND9 Docker images
- Client: Lightweight Alpine Linux or similar container
- Connect nodes using GNS3 virtual switches and router
