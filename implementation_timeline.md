# DNS Vulnerabilities Implementation Timeline and Checklist (10-Day Plan)

## Days 1-3: Environment Setup & Zone Transfer Attack

### Day 1: GNS3 Setup and Network Topology

- [ ] Install GNS3 on all team members' machines
- [ ] Set up GNS3 VM if using VM backend
- [ ] Download required Docker images (Kali Linux, Ubuntu/BIND9)
- [ ] Create the project in GNS3
- [ ] Add router and configure interfaces
- [ ] Add all required nodes (attacker, DNS servers, client)
- [ ] Connect devices according to the topology
- [ ] Verify basic connectivity between nodes

### Day 2: DNS Server Configuration

- [ ] Configure Primary DNS Server (with zone transfer vulnerability)
  - [ ] Install and configure BIND9
  - [ ] Create example.com zone
  - [ ] Intentionally misconfigure to allow zone transfers
- [ ] Configure Secondary DNS Server (for cache poisoning target)
  - [ ] Install and configure BIND9 as a caching resolver
  - [ ] Disable DNSSEC
  - [ ] Configure to forward to primary DNS
- [ ] Configure client to use secondary DNS
- [ ] Test DNS resolution functionality

### Day 3: Zone Transfer Attack Implementation

- [ ] Install tools on attacker machine (dig, dnsenum, dnsrecon, Wireshark/tcpdump)
- [ ] Test basic DNS queries against the target
- [ ] Document normal DNS behavior for comparison
- [ ] Execute Zone Transfer attack and verify success
- [ ] Capture traffic for analysis
- [ ] Document attack procedure and outcomes
- [ ] Prepare visual aids for Zone Transfer section of video

## Days 4-6: Cache Poisoning Attack

### Day 4: Cache Poisoning Attack Preparation

- [ ] Install Python libraries on attacker (Scapy, DNSPython)
- [ ] Develop/adapt the DNS cache poisoning script
- [ ] Test script functionality
- [ ] Set up packet capture for monitoring

### Day 5: Cache Poisoning Attack Execution

- [ ] Execute DNS Cache Poisoning attack
- [ ] Test with different parameters to ensure reliability
- [ ] Set up fake web server for impact demonstration
- [ ] Document attack procedure and outcomes
- [ ] Prepare visual aids for Cache Poisoning section of video

### Day 6: Attack Analysis & Documentation

- [ ] Analyze captured traffic from both attacks
- [ ] Create comparative analysis of both vulnerabilities
- [ ] Document key findings and observations
- [ ] Create diagrams showing the attack flows
- [ ] Finalize attack documentation

## Days 7-8: Security Countermeasures

### Day 7: Zone Transfer Defenses

- [ ] Create a copy of the vulnerable environment
- [ ] Implement secure BIND configuration
  - [ ] Restrict zone transfers
  - [ ] Configure TSIG authentication
- [ ] Set up logging for transfer attempts
- [ ] Test defenses by attempting attacks
- [ ] Document the differences in configurations

### Day 8: Cache Poisoning Defenses

- [ ] Create a copy of the vulnerable environment
- [ ] Implement DNSSEC
  - [ ] Generate signing keys
  - [ ] Sign zones
  - [ ] Configure DNSSEC validation
- [ ] Implement Response Rate Limiting
- [ ] Test defenses by attempting attacks
- [ ] Finalize security countermeasures documentation

## Days 9-10: Video Production

### Day 9: Script Finalization and Recording

- [ ] Finalize the video script
- [ ] Create slides and visual aids
- [ ] Assign speaking parts to team members
- [ ] Practice explanations
- [ ] Set up screen recording software
- [ ] Record all demonstration segments
  - [ ] Introduction and background
  - [ ] Zone Transfer attack demonstration
  - [ ] Cache Poisoning attack demonstration
  - [ ] Defense implementations
  - [ ] Conclusion

### Day 10: Video Editing and Submission

- [ ] Edit video footage
- [ ] Add annotations and callouts
- [ ] Add transitions and title screens
- [ ] Review for technical accuracy
- [ ] Ensure video is under 15 minutes
- [ ] Render final video in WebM or MP4 format
- [ ] Test playback in VLC
- [ ] Complete Declaration of Academic Integrity forms
- [ ] Create submission package
- [ ] Submit assignment

## Team Parallel Work Recommendations

### Team Member 1 (Focus: Environment & Zone Transfer)

- Lead Days 1-2 for environment setup
- Lead Day 3 for Zone Transfer attack
- Support Day 7 for defense implementation
- Record assigned parts on Day 9

### Team Member 2 (Focus: Cache Poisoning)

- Support Days 1-2 for environment setup
- Lead Days 4-5 for Cache Poisoning attack
- Support Day 8 for defense implementation
- Record assigned parts on Day 9

### Team Member 3 (Focus: Documentation & Video)

- Document configurations during Days 1-3
- Support attack implementations on Days 3-5
- Lead Days 7-8 for defense documentation
- Lead Days 9-10 for video production

## Daily Checkpoint Meetings

- 30-minute morning meeting to assign daily tasks
- 30-minute evening meeting to verify progress and address issues
- Continuous communication via team chat/collaboration tools

## Final Deliverable Checklist

### Video Requirements

- [ ] Introduction and outline
- [ ] Explanation of vulnerability relevance
- [ ] Detailed technical explanation
- [ ] Explanation of exploit functionality
- [ ] Description of security tools
- [ ] Live demonstration of tools and exploits
- [ ] Defense strategies
- [ ] Summary and conclusion
- [ ] Duration under 15 minutes
- [ ] Format: WebM or MP4, playable in VLC

### Documentation

- [ ] Completed Declaration of Academic Integrity for all team members
- [ ] All source code with comments
- [ ] Configuration files
- [ ] Network topology diagrams
- [ ] Comprehensive security countermeasures guide
