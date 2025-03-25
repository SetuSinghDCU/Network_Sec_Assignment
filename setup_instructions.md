# Detailed Setup Instructions

## 1. GNS3 Installation and Initial Configuration

1. Download and install GNS3 from https://gns3.com/software
2. Install GNS3 VM (if using GNS3 VM for better performance)
3. Configure GNS3 to use local server or GNS3 VM
4. Download required Docker images:
   - `kalilinux/kali-rolling` (for attacker)
   - `ubuntu/bind9` (for DNS servers)
   - `ubuntu` (for client)

## 2. Creating the Network Topology

1. Open GNS3 and create a new project called "DNS_Vulnerabilities_Demo"
2. Add a cloud node to represent internet connectivity (optional)
3. Add an L3 router (use Cisco IOSv or similar)
4. Add the following Docker containers:
   - Kali Linux (Attacker)
   - Ubuntu Server with BIND9 (Primary DNS)
   - Ubuntu Server with BIND9 (Secondary DNS)
   - Ubuntu Desktop (Client)
5. Add switches to create the network segments
6. Connect devices according to the network layout in the topology document

## 3. Configuring the Router

```
# Configure interfaces
interface GigabitEthernet0/0
 ip address 192.168.1.1 255.255.255.0
 no shutdown
!
interface GigabitEthernet0/1
 ip address 192.168.2.1 255.255.255.0
 no shutdown
!
interface GigabitEthernet0/2
 ip address 10.0.0.1 255.255.255.0
 no shutdown
!
# Configure routing
ip route 0.0.0.0 0.0.0.0 GigabitEthernet0/0
```

## 4. Configuring the Attacker Machine (Kali Linux)

1. Start the Kali Linux container
2. Configure IP address:
   ```bash
   ip addr add 192.168.1.10/24 dev eth0
   ip route add default via 192.168.1.1
   ```
3. Install additional tools:
   ```bash
   apt update
   apt install -y dnsutils dnsenum dnsrecon dnsmap scapy python3-pip
   pip3 install scapy dnspython
   ```
4. Download/create DNS cache poisoning script (details in attack script section)

## 5. Configuring the Primary DNS Server

1. Start the Ubuntu BIND9 container
2. Configure IP address:
   ```bash
   ip addr add 192.168.2.10/24 dev eth0
   ip route add default via 192.168.2.1
   ```
3. Configure BIND9 (intentionally misconfigured to allow zone transfers):

   Edit `/etc/bind/named.conf.options`:

   ```
   options {
       directory "/var/cache/bind";
       recursion yes;
       allow-recursion { any; };
       allow-query { any; };
       allow-transfer { any; }; // Intentional misconfiguration
       dnssec-validation auto;
       listen-on { any; };
   };
   ```

   Edit `/etc/bind/named.conf.local`:

   ```
   zone "example.com" {
       type master;
       file "/etc/bind/zones/db.example.com";
       allow-transfer { any; }; // Intentional misconfiguration
   };
   ```

   Create zone file `/etc/bind/zones/db.example.com`:

   ```
   $TTL 86400
   @   IN  SOA ns1.example.com. admin.example.com. (
           2023010101  ; Serial
           3600        ; Refresh
           1800        ; Retry
           604800      ; Expire
           86400 )     ; Minimum TTL

   ; Name servers
   @       IN  NS      ns1.example.com.

   ; A records
   ns1     IN  A       192.168.2.10
   www     IN  A       10.0.0.10
   mail    IN  A       10.0.0.20
   ftp     IN  A       10.0.0.30
   intranet IN A       10.0.0.40
   admin   IN  A       10.0.0.50
   ```

4. Restart BIND:
   ```bash
   service bind9 restart
   ```

## 6. Configuring the Secondary DNS Server

1. Start the Ubuntu BIND9 container
2. Configure IP address:
   ```bash
   ip addr add 192.168.2.20/24 dev eth0
   ip route add default via 192.168.2.1
   ```
3. Configure BIND9 as a forwarding/caching DNS server:

   Edit `/etc/bind/named.conf.options`:

   ```
   options {
       directory "/var/cache/bind";
       recursion yes;
       allow-recursion { any; };
       allow-query { any; };
       dnssec-validation no; // Disabled for demonstration
       dnssec-enable no;    // Disabled for demonstration
       listen-on { any; };

       // Forward all requests to our primary DNS (vulnerable to cache poisoning)
       forwarders {
           192.168.2.10;
       };
   };
   ```

4. Restart BIND:
   ```bash
   service bind9 restart
   ```

## 7. Configuring the Client Machine

1. Start the Ubuntu container
2. Configure IP address:
   ```bash
   ip addr add 192.168.2.30/24 dev eth0
   ip route add default via 192.168.2.1
   ```
3. Configure DNS resolution to use the secondary DNS server:

   Edit `/etc/resolv.conf`:

   ```
   nameserver 192.168.2.20
   search example.com
   ```

4. Install tools for verification:
   ```bash
   apt update
   apt install -y dnsutils curl wget
   ```

## 8. Testing Initial Configuration

1. From the client, verify connectivity:

   ```bash
   ping -c 3 192.168.2.10
   ping -c 3 192.168.2.20
   ping -c 3 192.168.1.10
   ```

2. Test DNS resolution:

   ```bash
   dig www.example.com
   dig ns1.example.com
   ```

3. From the attacker, verify the vulnerability exists:
   ```bash
   dig AXFR example.com @192.168.2.10
   ```

This should show all records in the zone if zone transfer is enabled correctly.
