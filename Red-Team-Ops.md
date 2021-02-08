# Red Team Operations with Cobalt Strike (2019) #

[YouTube Playlist](https://www.youtube.com/playlist?reload=9&list=PL9HO6M_MU2nfQ4kHSCzAQMqxQxH47d1no "Red Team Operations with Cobalt Strike (2019)")

## Introduction ##

### Red Team Goals ###
1. Initial Access - Difficulties: AVs, Access Whitelists, EDR (Local Agent), Telemetry of the Event sent to a SOC that detects the malicious intent...
2. Code Executing - Difficulties: Firewalls, Proxies, Network Security Monitoring, TI...
3. Positive Control (C2) - Difficulties: EDR, Telemetry...
4. Post-Exploitation - Difficulties: EDR, Telemetry...

### Attack Chain ###
1. DMARC, DKIM, SPF
2. Mail Anti-Virus Gateway
3. Artifact on Target
4. Endpoint Security
5. Application Whitelisting
6. Instrumentation & Telemetry
7. Code Execution
8. Firewall and Proxy
9. Network Security Monitoring
10. Positive C&C
11. Post Exploitation
12. Instrumentation and Telemetry

#### How to succeed at evasion: ####

* Know your tools and behaviors
* Assess and understand the defenses
* Decide the best option to use


- - - -

## Operations ##

### Beacon ###
Cobalt Strike's Payload.

* It has two Communication Strategies:
    * Asynchronous -> "Low and Slow"
    * Interactive -> Real-Time Control

* It uses HTTP/S or DNS to egress a network. 
* It uses SMB or TCP for peer-to-peer C2.
* It has Remote Administration Tool Features.

### Malleable C2 ###
A domain-specific language to give you control over the indicators in the Beacon payload.
  - Network Traffic
  - In-memory Content, Characteristics and Behavior
  - Process Injection Behavior

### Aggressor Script ###
The scripting language built into Cobalt Strike v3.0 and later. It allows you to modify and extend the Cobalt Strike client, such as adding pop-up menus, defining new commands, responding to events... [Aggressor Script](https://www.cobaltstrike.com/aggressor-script/ "Aggressor Script")

### Structure ###

#### Server - Team Server ####
``` ./teamserver <IP> <Password> [Path to Malleable C2 Profile] [Kill Date for Beacon Payloads - YYYY-MM-DD]``` - To start the Team Server

#### Client - Target ####
``` ./cobaltstrike ``` - Starts the CS GUI Client. After inputing the connection information for the Team Server, it connects to it.

- The 'Event Log' can be used to send messages to the Team (Collaboration feature).

- A Client can connect to multiple Team Servers at the same time:
    * Cobalt Strike > New Connection - To connect to multiple Team Servers
    * Cobalt Strike > Close - To close a connection
    * [Team Server Button (at the bottom)] > Rename - To rename a Server

Multiple Team Servers is ideal because it is very probable that the first Server used for exploitation is discovered and shutdown, so dividing the tasks between Servers along the way will help in maintaining access to the target network.

### Scaling Red Ops ###
* Target Cells
    * Responsibble for objectives on specific networks
    * Gain access, post-exploitation and spreading laterally
    * Maintain local infrastructure these tasks
* Access Management Cell - It scales very well, it can handle many target cells
    * Holds accesses for all networks
    * Gain access and receivbe access from cells
    * Pass accesses to target cells as needed
    * Maintain global infrastructure for persistent callbacks

### Team Roles ###
* Access
    * Get in and expand foothold
* Post-Exploitation
    * Data Mining
    * Monitor Users
    * Keylogging
    * Screenshots
    * ...
* Local Access Manager (Shell Sherpa)
    * Manage Callbacks
    * Setup Infrastructure
    * Persistence
    * Pass Sessions to and from the Global Access Manager

### Logs ###
CS logs everyting on the Team Server under the folder ``` logs/ ```.

### Reports ###
CS has a Reporting menu. It can output as PDF and MS Word, generate custom reports and change logo, merges data from multiple Team Servers...

- - - -

## Infrastructure ##

- - - -

## C2 (Control) ##

- - - -

## Weaponization ##

- - - -

## Initial Access ##

- - - -

## Post Exploitation ##

- - - -

## Privilege Escalation ##

- - - -

## Lateral Movement ##

- - - - 

## Pivoting ##


