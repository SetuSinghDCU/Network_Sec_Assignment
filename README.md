# DNS Vulnerabilities Demonstration Project

## Overview

This repository contains all the necessary materials and documentation for implementing and demonstrating two critical DNS security vulnerabilities:

1. DNS Zone Transfer vulnerability
2. DNS Cache Poisoning using Birthday Attack

This project is intended for educational purposes as part of the CSC1134 Network Security Assignment 2024-2025. The goal is to produce a 15-minute educational video demonstrating these vulnerabilities, their impact, and how to defend against them.

## Project Structure

### Documentation Files

| File                               | Description                                                      |
| ---------------------------------- | ---------------------------------------------------------------- |
| [requirements.md](requirements.md) | Assignment requirements and guidelines from the professor        |
| [proposal.md](proposal.md)         | Our submitted proposal for the DNS vulnerabilities demonstration |
| [README.md](README.md)             | This file - project overview and navigation                      |

### Implementation Files

| File                                                               | Description                                                                            |
| ------------------------------------------------------------------ | -------------------------------------------------------------------------------------- |
| [topology.md](topology.md)                                         | Network topology for the GNS3 environment                                              |
| [setup_instructions.md](setup_instructions.md)                     | Step-by-step setup instructions for all components                                     |
| [dns_zone_transfer_attack.md](dns_zone_transfer_attack.md)         | Detailed procedure for executing and demonstrating the Zone Transfer attack            |
| [dns_cache_poisoning_attack.md](dns_cache_poisoning_attack.md)     | Complete implementation of the DNS Cache Poisoning attack using Birthday Attack method |
| [dns_security_countermeasures.md](dns_security_countermeasures.md) | Comprehensive security countermeasures against both vulnerabilities                    |

### Project Management

| File                                                     | Description                                            |
| -------------------------------------------------------- | ------------------------------------------------------ |
| [implementation_timeline.md](implementation_timeline.md) | 10-day accelerated timeline with tasks and checkpoints |
| [video_script.md](video_script.md)                       | Detailed script for the 15-minute video presentation   |
| [additional_resources.md](additional_resources.md)       | Reference materials and additional resources           |

## Accelerated Implementation Process (10-Day Plan)

### Days 1-3: Environment Setup & Zone Transfer Attack

1. Set up GNS3 environment and network topology
2. Configure DNS servers with intentional vulnerabilities
3. Implement and document Zone Transfer attack

### Days 4-6: Cache Poisoning Attack

1. Develop and test the DNS Cache Poisoning script
2. Execute attack and demonstrate impact
3. Analyze and document attack procedures and outcomes

### Days 7-8: Security Countermeasures

1. Implement and test Zone Transfer defenses
2. Implement and test Cache Poisoning defenses
3. Document security countermeasures

### Days 9-10: Video Production

1. Finalize script and record demonstrations
2. Edit video and add explanatory elements
3. Produce and test final video

## Getting Started

1. Start by reviewing [requirements.md](requirements.md) and [proposal.md](proposal.md) to understand the project scope
2. Follow the network setup in [topology.md](topology.md)
3. Implement the environment using [setup_instructions.md](setup_instructions.md)
4. Execute the attacks following [dns_zone_transfer_attack.md](dns_zone_transfer_attack.md) and [dns_cache_poisoning_attack.md](dns_cache_poisoning_attack.md)
5. Implement defenses using [dns_security_countermeasures.md](dns_security_countermeasures.md)
6. Record and edit the video according to [video_script.md](video_script.md)
7. Follow the [implementation_timeline.md](implementation_timeline.md) to stay on track

## Daily Checkpoint Meetings

- 30-minute morning meeting to assign daily tasks
- 30-minute evening meeting to verify progress and address issues
- Continuous communication via team chat/collaboration tools

## Important Dates

- Accelerated Completion Deadline: [Set date 10 days from start]
- Assignment Submission Deadline: April 4, 2025

## Additional Notes

- All attack demonstrations must be performed in an isolated lab environment
- Video must be submitted in WebM or MP4 format, playable in VLC
- Include the Declaration of Academic Integrity with the submission
