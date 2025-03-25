# DNS Security Countermeasures

This document outlines the security measures that can be implemented to protect against the DNS vulnerabilities demonstrated in this project: DNS Zone Transfer vulnerabilities and DNS Cache Poisoning.

## 1. Protection Against DNS Zone Transfer Vulnerabilities

### Restrict Zone Transfers

1. **Configure BIND to restrict zone transfers**:

   ```
   // In named.conf.options
   options {
       ...
       allow-transfer { none; };  // Global default: no zone transfers
       ...
   };

   // In named.conf.local, per-zone configuration
   zone "example.com" {
       type master;
       file "/etc/bind/zones/db.example.com";
       allow-transfer { 192.168.2.20; };  // Only allow specific secondary DNS servers
   };
   ```

2. **Implement TSIG (Transaction Signature) for Authenticated Zone Transfers**:

   ```bash
   # Generate a TSIG key
   dnssec-keygen -a HMAC-SHA256 -b 256 -n HOST transfer-key

   # Add the key to named.conf
   key "transfer-key" {
       algorithm hmac-sha256;
       secret "generated-secret-key-from-keygen";
   };

   # Configure zones to use the TSIG key
   zone "example.com" {
       type master;
       file "/etc/bind/zones/db.example.com";
       allow-transfer { key transfer-key; };
   };

   # On secondary DNS server
   key "transfer-key" {
       algorithm hmac-sha256;
       secret "generated-secret-key-from-keygen";
   };

   server 192.168.2.10 {
       keys { transfer-key; };
   };

   zone "example.com" {
       type slave;
       file "/var/cache/bind/db.example.com";
       masters { 192.168.2.10; };
   };
   ```

3. **Use ACLs (Access Control Lists) for IP-based restrictions**:

   ```
   acl trusted-secondaries {
       192.168.2.20;
       192.168.2.21;
   };

   zone "example.com" {
       type master;
       file "/etc/bind/zones/db.example.com";
       allow-transfer { trusted-secondaries; };
   };
   ```

### Monitoring and Detection

1. **Set up DNS query logging**:

   ```
   logging {
       channel query_log {
           file "/var/log/named/query.log" versions 3 size 5m;
           severity info;
           print-time yes;
       };
       category queries { query_log; };
   };
   ```

2. **Monitor for Zone Transfer attempts**:

   - Set up log monitoring for AXFR queries
   - Configure alerts for unauthorized zone transfer attempts
   - Use Intrusion Detection Systems (IDS) to detect reconnaissance activities

3. **Regular security audits**:
   - Perform periodic checks of DNS server configurations
   - Use tools like `dnswalk` or `dnscheck` to verify domain configurations
   - Conduct penetration testing to identify misconfigurations

## 2. Protection Against DNS Cache Poisoning

### DNSSEC Implementation

1. **Enable and configure DNSSEC**:

   ```
   // In named.conf.options
   options {
       ...
       dnssec-enable yes;
       dnssec-validation auto;
       ...
   };
   ```

2. **Generate zone signing keys (ZSK) and key signing keys (KSK)**:

   ```bash
   # Generate a Key Signing Key (KSK)
   dnssec-keygen -a RSASHA256 -b 2048 -f KSK -n ZONE example.com

   # Generate a Zone Signing Key (ZSK)
   dnssec-keygen -a RSASHA256 -b 1024 -n ZONE example.com
   ```

3. **Sign your zone**:

   ```bash
   # Sign the zone with the keys
   dnssec-signzone -A -3 $(head -c 16 /dev/random | od -v -t x | head -1 | cut -f 2- -d ' ' | tr -d ' ') -N INCREMENT -o example.com -t db.example.com
   ```

4. **Update named.conf to use signed zone**:
   ```
   zone "example.com" {
       type master;
       file "/etc/bind/zones/db.example.com.signed";
       allow-transfer { trusted-secondaries; };
   };
   ```

### DNS Configuration Hardening

1. **Increase entropy in transaction IDs and source ports**:

   ```
   // In named.conf.options
   options {
       ...
       random-device "/dev/urandom";  // Use a good entropy source
       ...
   };
   ```

2. **Implement Response Rate Limiting (RRL)**:

   ```
   // In named.conf.options
   options {
       ...
       rate-limit {
           responses-per-second 5;
           window 5;
       };
       ...
   };
   ```

3. **Enable DNS query and response validation**:

   ```
   // In named.conf.options
   options {
       ...
       match-mapped-addresses yes;
       checks-names master warn;
       ...
   };
   ```

4. **Use separate resolvers and authoritative servers**:
   - Configure DNS servers to either be resolvers or authoritative, not both
   - This separation limits the attack surface and prevents cache poisoning affecting authoritative data

### Network-Level Protection

1. **Implement DNS Firewall rules**:

   ```
   # Allow only necessary DNS traffic (UDP/TCP port 53)
   iptables -A INPUT -p udp --dport 53 -s trusted-networks -j ACCEPT
   iptables -A INPUT -p tcp --dport 53 -s trusted-networks -j ACCEPT
   iptables -A INPUT -p udp --dport 53 -j DROP
   iptables -A INPUT -p tcp --dport 53 -j DROP
   ```

2. **Deploy DNS-aware IPS/IDS**:

   - Configure Snort or Suricata with DNS-specific rules
   - Monitor for unusual DNS activity patterns
   - Set alerts for high volumes of DNS traffic from single sources

3. **Consider DNS over TLS (DoT) or DNS over HTTPS (DoH)**:
   - Implement RFC 7858 (DoT) or RFC 8484 (DoH) for encrypted DNS traffic
   - Configure Stubby or Unbound for DoT

## 3. General DNS Security Best Practices

1. **Regular Software Updates**:

   - Keep DNS server software up-to-date with latest security patches
   - Subscribe to security mailing lists for DNS software vendors

2. **Implement Proper Access Controls**:

   - Run DNS services with least privilege
   - Use separate user accounts for DNS services
   - Restrict administrative access to DNS servers

3. **Configuration Hardening**:

   - Disable unnecessary features and services
   - Use split-horizon DNS to separate internal and external DNS
   - Implement DNS views to provide different answers based on query source

4. **Monitoring and Logging**:

   ```
   logging {
       channel security_log {
           file "/var/log/named/security.log" versions 3 size 10m;
           severity warning;
           print-time yes;
           print-severity yes;
           print-category yes;
       };
       category security { security_log; };
   };
   ```

5. **Regular Backup of DNS Configuration and Data**:

   ```bash
   # Create backup script
   cat > /usr/local/bin/backup-dns.sh << 'EOF'
   #!/bin/bash
   BACKUP_DIR="/var/backups/dns"
   DATE=$(date +%Y%m%d)
   mkdir -p ${BACKUP_DIR}/${DATE}
   cp -a /etc/bind/* ${BACKUP_DIR}/${DATE}/
   EOF

   # Make executable
   chmod +x /usr/local/bin/backup-dns.sh

   # Add to crontab
   echo "0 2 * * * root /usr/local/bin/backup-dns.sh" > /etc/cron.d/dns-backup
   ```

## 4. Implementation Guide for Secure DNS Server

### Step 1: Install Required Packages

```bash
apt update
apt install -y bind9 bind9utils bind9-doc
```

### Step 2: Configure Basic Security

Edit `/etc/bind/named.conf.options`:

```
options {
    directory "/var/cache/bind";

    // Listen only on necessary interfaces
    listen-on { 127.0.0.1; 192.168.2.10; };
    listen-on-v6 { ::1; };

    // Restrict recursion
    recursion yes;
    allow-recursion { localhost; trusted-clients; };

    // Restrict queries
    allow-query { localhost; trusted-clients; };

    // Disable zone transfers globally
    allow-transfer { none; };

    // Security enhancements
    version "Not disclosed";

    // Enable DNSSEC
    dnssec-enable yes;
    dnssec-validation auto;

    // Response Rate Limiting
    rate-limit {
        responses-per-second 5;
        window 5;
    };

    // Use a good entropy source
    random-device "/dev/urandom";

    // EDNS buffer size
    max-udp-size 4096;

    // Use separate caches
    auth-nxdomain no;
};

// Define ACLs
acl trusted-clients {
    localhost;
    192.168.2.0/24;
};

acl trusted-secondaries {
    192.168.2.20;
};
```

### Step 3: Set Up TSIG Keys for Zone Transfers

```bash
# Generate TSIG key
dnssec-keygen -a HMAC-SHA256 -b 256 -n HOST transfer-key

# Add key to named.conf
cat >> /etc/bind/named.conf << 'EOF'
key "transfer-key" {
    algorithm hmac-sha256;
    secret "generated-secret-key-from-keygen";
};
EOF
```

### Step 4: Configure Zone with Secure Settings

Edit `/etc/bind/named.conf.local`:

```
zone "example.com" {
    type master;
    file "/etc/bind/zones/db.example.com";
    allow-query { any; };
    allow-transfer { key transfer-key; };
    allow-update { none; };
    notify yes;
    also-notify { 192.168.2.20; };
};
```

### Step 5: Set Up DNSSEC for the Zone

```bash
# Generate KSK and ZSK
cd /etc/bind/zones
dnssec-keygen -a RSASHA256 -b 2048 -f KSK -n ZONE example.com
dnssec-keygen -a RSASHA256 -b 1024 -n ZONE example.com

# Sign the zone
dnssec-signzone -A -3 $(head -c 16 /dev/random | od -v -t x | head -1 | cut -f 2- -d ' ' | tr -d ' ') -N INCREMENT -o example.com -t db.example.com

# Update zone configuration
sed -i 's/db.example.com/db.example.com.signed/g' /etc/bind/named.conf.local
```

### Step 6: Configure Logging

Edit `/etc/bind/named.conf`:

```
logging {
    channel default_log {
        file "/var/log/named/default.log" versions 3 size 5m;
        severity info;
        print-time yes;
        print-severity yes;
        print-category yes;
    };

    channel security_log {
        file "/var/log/named/security.log" versions 3 size 10m;
        severity warning;
        print-time yes;
        print-severity yes;
        print-category yes;
    };

    channel query_log {
        file "/var/log/named/query.log" versions 3 size 5m;
        severity info;
        print-time yes;
    };

    category default { default_log; };
    category security { security_log; };
    category queries { query_log; };
};
```

### Step 7: Verify Configuration and Restart BIND

```bash
# Create log directory
mkdir -p /var/log/named
chown bind:bind /var/log/named

# Check configuration
named-checkconf

# Restart BIND
systemctl restart bind9

# Verify DNSSEC is working
dig +dnssec @127.0.0.1 example.com
```

## 5. Testing the Security Implementation

1. **Test Zone Transfer Restrictions**:

   ```bash
   # This should fail
   dig AXFR example.com @192.168.2.10

   # This should succeed with proper TSIG key
   dig AXFR example.com @192.168.2.10 -k /path/to/transfer-key.key
   ```

2. **Test DNSSEC validation**:

   ```bash
   # Verify DNSSEC records
   dig +dnssec example.com @192.168.2.10

   # Verify DNSKEY
   dig DNSKEY example.com @192.168.2.10

   # Test validation
   dig +cd example.com @192.168.2.10  # Should succeed
   ```

3. **Attempt Cache Poisoning on Secured Server**:
   - Run the cache poisoning script against the secured server
   - Verify that DNSSEC validation prevents poisoning
   - Check logs for evidence of the attack attempt

By implementing these security measures, your DNS infrastructure will be significantly better protected against both zone transfer vulnerabilities and cache poisoning attacks.
