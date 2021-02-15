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

### Listener ###
A configuration for a CS Payload (and Payload Server). The name of the listener must be descriptive enough so that other teammates can understand which listener is which and for what it is used.

* Types of Listeners:

   * Egress: Payload that beacons out of a network
   * Peer-to-Peer: Payload that communicates through a parent payload
   * Alias: Reference to a payload handler elsewhere, for instance, in another toolset
      
* 'Cobalt Strike' > 'Listeners' - To manage the listeners

### Payload Staging ###
* Stager: Tiny program that downloads a payload and passes execution to it. It is needed for size-constrained attacks because of the limitation of space.

* Stageless Payload: Payload without a stager. It is more commonly used nowadays.

* Stagers are:

   * Less secure
   * More brittle
   * Easier to detect

CS is compatible with Metasploit payloads. It is also compatible with 'Foreign Listeners', other tools, like Metasploit, can be used to listen (open a session) to a CS payload.

### HTTP(/S) Beacon ###
The client will periodically make HTTP GET requests to the CS C2 (Controller) asking for 'something to do'. If the C2 responds with 'No', the client will go to sleep until next time it sends the request. When the client asks and the C2 has an action for it to perform, it sends the payload data. When the action is performed, the client will send back the result in an HTTP POST request (If there is no output, there's no HTTP POST request). 

The HTTPS Beacon works just the same, but with an SSL certificate.

### Listener Attacks ###
After configuring the listener, we can configure the attacks to send.

1. 'Attacks' > 'Web Drive-By' > 'Scripted Web Delivery (S)' - Provides a one-liner that downloads the file with the configured payload.
2. Run it on the victim machine - The Beacon listener will be activated

### Redirectors ###
To forward traffic to the CS Team Server.

* Iptables, socat... - ``` socat TCP4-LISTEN:80,fork TCP4:<Team Server IP>:80 ```
* Apache or Nginx Reverse Proxy config
* CDN (Content Delivery Network) as a redirector for HTTPS traffic

   * Use a valid SSL certificate
   * Allow HTTP POST and GET verbs
   * Consider HTTP-GET only C2
   * Disable all cache options
   * Be aware of transformed requests!

### Listing what's Running on a Local Port ###
``` netstat -nap | grep <Port> ```

### Running commands on the Background ###
1. ``` $ screen ```
2. ``` $ <Command> ```
3. <kbd>Ctrl+Z</kbd> - To send the command to the background
4. ``` $ bg ``` - To list the processes running in the background
5. ``` $ screen -d ``` - To detach from the session

### Domain Fronting ###
The CDN looks at the 'Host' header in an HTTP request from a client to determine which origin Server to pull from if the content is not in its cache. Domain Fronting takes advantage of this by making the HTTP Beacon client ask for the right domain, but changing the 'Host' header of the HTTP request to that of the C2, so that the request is pulled from the C2 instead of the original Server. In CS you can configure it in the 'HTTP Host Header' parameter on the listener.

HTTPS is more desirable in this scenario because some Proxies (& browsers?) when they notice the difference between the URL and the 'Host' header they automatically fix it, but in HTTPS, as the connection is encrypted, they can't do it so it arrives to the CDN untouched. (It can be fixed by Proxies that MiTM all the traffic of their organization, even the HTTPS traffic. But it is not done, in some cases, for client confidentiality reasons (finance, healthcare...), making it vulnerable to Domain Fronting).

Another mitigation: In HTTPS, in the TLS header, there's the SNI field, that has the value of the 'Host' header, if the CDN looks at this value, it can notice the difference.

### DNS Beacon ###
Payload that uses DNS lookups to communicate with the CS Team Server. It takes advantage of the recursive DNS query, making the query arrive to the CS Team Server that acts as a DNS Server (Listener - Payload: Beacon DNS), responding with a malicious response.

Modes to transmit the DNS records with the tasks:
* Mode: 'dns' -> DNS A Record
* Mode: 'dns6' -> DNS AAAA Record
* Mode: 'dns-txt' -> DNS TXT Record

After configuring the DNS Beacon Listener, and luring the victim to execute the one-liner in their machine, a 'Ghost Beacon' will appear on CS. It is not a ghost, it's just that we don't have the machine's metadata yet. To do so, we need for them to request a query, and interact with the CS TS, so just right-click on it and select 'Interact', enter a command such as 'sleep 5', and then the metadata for that Beacon will appear and will perform the actions instructed.

### SMB Beacon ###
Payload that uses name pipes to communicate peer-to-peer. Example: Target network where only one node is communicating with the CS Team Server, via DNS or HTTP Beacon, and then communicates with the other nodes in the network with the SMB Beacon, and communicates the actions from and to the CS Team Server of all the subnodes in the network. (Listener - Payload: Beacon SMB)

To assume control of an SMB Beacon:
* Connect to a Beacon peer - ``` link <host> <pipe> ```
* Disconnect from a Beacon peer - ``` unlink <host> <pid> ```

To see the 'Parent - Child' relationships between SMB Beacons, go to 'Cobalt Strike' > 'Visualization' > 'Pivot Graph'.

### TCP Beacon ###
Conceptually, is similar to SMB Beacon. (Listener - Payload: Beacon TCP)

To assume control of an TCP Beacon:
* Connect to a Beacon peer - ``` connect <host> <port> ```
* Disconnect from a Beacon peer - ``` unlink <host> <pid> ```

### External C2 ###
Specification that allows a third-party program or toolchain to control a Beacon and relay back to the CS Team Server. (Listener - Payload: External C2)

- - - -

## C2 (Control) ##

### Malleable C2 ###
A domain-specific language to give you control over the indicators in the Beacon payload. 

In the Beacon payload you can change:

* Network traffic
* In-memory content, characteristics and behavior
* Process injection behavior

``` ./teamserver <IP> <Password> <Malleable C2 Profile> ``` - To start a Team Server with a Malleable C2 Profile

#### Components of the profile ####
* Options - `set <key - http parameter> "<value>"` - Ex. `set useragent "Mozilla/5.0"`, `set uri "/image/"`
* Blocks - Groups indicators. There's three types:
   * http-get {} - Downloads tasks
      * client - HTTP Request
      * server - HTTP Response
   * http-post {} - Controls how Beacons upload output to the CS TS
     * client: id, output
     * server
   * http-stager {} - Shapes the content of the staging process
   * http-config {} - Consistent service headers. "Global Server config"
   * https-certificate {} - To configure the SSL certificate
* Extraneous Indicators - Way of decorating aspects of a transaction (HTTP Headers) - `header "<key>" "<value>"` 
* Transforms - Way of taking data that a Beacon has to send and transforms the way of dictating how the Beacon should transform the data to store it and send it - Ex. `metadata { netbios #It netbios-encodes the data; append "-.jpg"; uri-append;}` - This block can be followed to encode and recover the data, to encode read it from the top to the bottom, and to recover it, do it the other way round.

#### To test a new profile before using it ####
``` ./c2lint <Profile> ``` 

### Egress and Network Evasion ###
Steps to ensure that you have positive C2 over the Beacon payload.

#### The C2 Problem Set ####
* Deny all outbound traffic
* Allow egress only through a proxy device
   * Attack traffic must conform to expected protocol
   * Must pass other checks as well...
* Evade monitoring which may look for
   * Known IOCs or suspicious IOCs in requests - IOC = Indicator of Compromise
   * Infrastructure being identified as Cobalt Strike before use - It's best to use customized CS profiles

#### Profile Evasion Tips ####
* Don't use public profile examples - Use a customized profile
* Don't allow empty server responses
   * 'prepend' -> To add junk data
   * 'mask' -> To randomize the data
* Change URIs and use 'prepend' to mask IOCs in the http-stager block - Ex. Don't use the 'application/octet-stream' value as it is detected as suspicious.
* Use the http-config block to standardize server headers and header order in all HTTP server responses
* Use plausible 'set useragent' values
* Use 'HTTP Get-Only' C2 for difficult egress situations - Best chance to get Command & Control (C2)

#### Network Security Monitoring ####
* Use an Apache, Nginx or a CDN as a redirector
* Invest in your infrastructure
   * Host redirectors on different providers
   * Domains are better with age and categorization
   * Do not use IPv4 addresses for C2
   * Use a valid SSL certificate
* Operate "low and slow"
   * High Beacon sleep interval

#### DNS C2 Detections / Preventions ####
* Split-Split DNS - Organizations only allowing internal hosts to access an internal DNS Server that does not resolve to external queries
   * Don't use DNS C2
* Volume of requests
   * Use DNS C2 as "low&slow" fallback option only
* CS DNS C2 IOCs
   * Set 'dns_stager_prepend' and 'dns_stager_subhost'
* Bogon IP Address - Looking at responses and identifying non-valid IP address responses, such as 0.0.0.0
   * Change 'dns_idle' in profile
   * Avoid 'mode dns' - The IP Address field is used to send data back to the C2
* Length of request hostnames
   * Set 'dns_max_txt' to limit the TXT length
   * Set 'maxdns' to limit hostname length

### Infrastructure OPSEC ###
Having your C2 Server identified as a CS Server by online threat intelligence sites like 'Censys'.

* How to find CS Team Servers on the Internet / Countermeasures
   * Look for the default CS Self-Signed SSL Certificate
      * Use a valid SSL Certificate
      * Use Apache, Nginx or a CDN as a redirector
      * Only allow HTTP/S connections from redirectors
   * 0.0.0.0 DNS Responses
      * Set 'dns_idle' in Malleable C2 to avoid 0.0.0.0 IP Address responses
   * Open port 50050
      * Firewall port 50050 and access via SSH Tunnel
   * Empty index page, 404, Content-Type: text/plain
      * Host content on your redirectors
   * Payload config available to anyone
      * Set 'host_stage' to 'false' in Malleable C2 - But it loses the ability of 'staging'
   
* How to verify a CS Team Server
   ``` wget -U "Internet Explorer" http://<server>/vl6D ``` - Issuing a request for a payload

### Beacon Payload Security Features ###
* Beacon payload authenticates the Team Server
* Beacon tasks and output are encrypted
* Beacon has replay protection for tasks
* Payload stagers *do not have* security features

- - - -

## Weaponization ##

* Artifact: File that embeds something that will run a payload. It creates space in memory, copies the payload (or the stager that then will call the payload) and pass execution to where the payload resides in memory.

#### Hosting Files in the CS Web Server ####
* 'Attacks' > 'Web Drive-By' > 'Host File' - To host a file
* 'Attacks' > 'Web Drive-By' > 'Manage' - To manage and remove hosted files
* 'View' > 'Web Log' - To see the web server activity

#### Artifact Kit ####
It is a source code Framework to generate EXEs, DLLs and Service EXEs. ('Help' > 'Arsenal' - To download it, then 'Modify and Build it' and finally, 'Cobalt Strike' > 'Script Manager' to load it.). It obfuscates known bad in unknown executables, fools AVs to stop emulating the executable, and de-obfuscates known bad and executes it.

### Methods ###

#### Executables and DLLs ####
'Attacks' > 'Packages' > 'Windows EXE (S)' - Generate an executable or DLL for a Stageless Beacon

``` rundll32(/64/86).exe <whatever>.dll,StartW ``` - To run the DLL

Run the application via a whitelisted program for a better result:
   * MS Office Macro
   * PowerShell
   * LOLbins
   * DLL Sideloading

#### Scripted Web Delivery ####
'Attacks' > 'Web Drive-By' > 'Scripted Web Delivery (S)' - Provides an executable one-liner 

#### Resource Kit ####
It enables you to change the HTA, PowerShell, Python, VBA and VBS Script templates that CS uses in its workflows. 'Help' > 'Arsenal' to download it and modify 'resources.cna'. 'Cobalt Strike' > 'Script Manager' to load it.

#### User-Driven Attacks ####
'Attacks' > 'Packages'/'Web Drive-By'. Beware that these attacks use stagers.

* HTML Application - Resource Kit
* Java Signed Applet Attack - Applet Kit
* MS Office Document Macros - Resource Kit
* Windows Dropper - Artifact Kit

#### Metasploit Framework Exploits ####
Metasploit can be used to create payloads to be loaded into CS and downloadable from the victim.

#### Go Custom! ####
* 'Attacks' > 'Packages' > 'Windows EXE (S)' - To export a raw stageles artifact
* 'Attacks' > 'Packages' > 'Payload Generator' - To export a raw stager artifact
* Use with a third-party artifact or tool
* (Optional) Build a script to integrate

### Tradecraft: Detections ###
Goal: Code Execution. 

* EXE and Script Content
   * Functions and strings from offense tools - Obfuscate
   * Base64 encoded DLL or shellcode - Obfuscate
* Behavior
   * Write a file to disk - Avoid
   * Execute a program - Spoof parent PID
   * Inject into new or existing process - Obfuscate
* Payload Content (Memory Injected DLL) - Evade
* Process Context
   * explorer.exe, notepad.exe, powershell.exe, rundll32.exe, svchost.exe - Avoid
   * Commonly abused applications - Avoid

#### In-Memory Detection Strategies ####
* Thread Start Address
   * No module associated with the start address
* Memory Permissions
   * RWX, RWX permissions
   * Odd 'AllocationProtect, Protect' pairs
* Memory Content
   * Signs of a PE file
   * Strings associated with toolset or common techniques
   
#### Malleable PE ####
Extends Malleable C2 to modify Beacon's DLL, such as:

* Prepending and appending data
* Replacing strings
* Embedding arbitrary strings
* Edit PE header fields
* Set PE loader hints to enable obfuscations

#### In-Memory Detection Evasions ####
* Thread Start Address
   * Depends on the artifact or process injection routine that ran the Beacon payload
* Memory Permissions
   * Avoid artifacts that use RWX permissions
   * Avoid the use of stagers - they always allow the RWX permissions
   * Set 'userwx' to 'false' in Malleable C2 profile
   * Turn on module stomping: Set 'module_x86' and 'module_x64' to a 'large unused DLL' in profile.
* Memory Content
   * Set 'image_size_x86' and 'image_size_x64'
   * Use 'prepend' to offset PE in memory - needs valid x86 or x64 values
   * Set 'obfuscate' to 'true'
   * Set 'cleanup' to 'true'
   * If needed, use 'strrep' to edit troublesome strings
   * Set 'sleep_mask' to 'true'

#### Artifact Tradecraft ####
Avoid 'module-less threads' and 'RWX memory'.

- - - -

## Initial Access ##

#### Client-Side Attacks ####
Making the user create the initial access to the CS Team Server. Ex. E-mail with a malicious file.

Steps:
1. Map the client-side attack surface
2. Create a VM for testing purposes
3. Use the VM to best select the attack
4. Configure and disguise the attack
5. Email attack package to the victim

#### Spear Phishing ####
Getting the weaponized content to the target.

Steps:
1. Create a target list
   "targets.txt":
   <email><tab><name>
   <email><tab><name>
      ...
2. Create a template
3. Choose mail server to send through
4. Send the message

#### Tradecraft ####
Nowadays, it's difficult that an email passes the securities imposed by the providers: Aggressive spam filtering, higher standards, email antivirus, DMARC (Domain-Based Message Authentication, Reporting and Conformance), DKIM (DomainKeys Identified Mail), SPF (Sender Policy Framework)...

#### Assume Breach ####
If you're in the network, know lateral creds but do not have access to CS: Windows 7 VM w/out AV and execute the payload there.

- - - -

## Post Exploitation ##

- - - -

## Privilege Escalation ##

### Escalation Options ###
``` elevate ``` in the Beacon console to spawn an elevated session

``` runasadmin ``` to run w/ elevated privileges

'Cobalt Strike' > 'Script Manager' > Load 'Elevate Kit' - Gives more elevation and runasadmin options

#### SharpUp ####
Privilege Escalation "vulnerability scanner" that looks for misconfigurations in the system.

``` execute-assembly /<local-path>/SharpUp.exe all ```

#### Kerberoasting ####
1. Query the domain controller for accounts with SPNs (Service Principle Name) - service logon accounts associated with a service
2. Request a TGS Ticket for the associated service
3. Try to recover the password by cracking the TGS ticket - because part of it is encrypted with the domain user's password hash

``` execute-assembly /<local-path>/rubeus.exe kerberoast /outfile:hashes.txt ```

``` hashcat -m 13100 -a 0 --force -o <output>.txt <input - hashes.txt> <wordlist> ``` - To crack the hashes

### Bypass User Access Control (UAC) and Get SYSTEM ###
* Use ` elevate uac-token-duplication <listener> ` - Fixed in Windows 10 RS5 (Oct 2018)
* Use ` runasadmin uac-cmstplua <command> ` 
* Use options in the Elevate Kit

#### Access Token ####
Concept not present in Linux, only Windows. It is a data structure managed within lsas, created after logon and associated with each process and thread, and persists in memory until reboot.

It contains:
* User and Group Information
* A list of privileges on the local computer
* Restrictions
* Reference to credentials

``` run whoami /priv ``` - To get the privileges on the present token

``` getprivs ``` - To enable the disabled privileges

The 'SYSTEM' token is one way to obtain full privileges over the machine. 

``` getsystem ``` - To search for and impersonate the SYSTEM token

``` elevate svc-exe <listener> ``` - To spawn a session via a service executable

### Credential and Hash Harvesting ###
* ``` logonpasswords ``` - Recovers credentials - Risky, alternatives: 'GhostPack SafetyKatz.exe', 'Internal Monologue (current user)'
* ``` hashdump ``` - Recovers local account hashes - Risky, alternatives: 'dcsync', '```mimikatz !lsadump::sam ```(local)'

In CS, 'View' > 'Credentials' - To manage credentials 

### Mimikatz in Beacon ###
Mimikatz is a post-exploitation toolset for:
* Advanced Persistence
* Harvest 'Trust Material'
* Re-purpose 'Trust Material'

``` mimikatz <command> <arguments> ``` - Run mimikatz command

``` mimikatz !<command> <arguments> ``` - Elevate to SYSTEM and run mimikatz command

``` mimikatz @<command> <arguments> ``` - Use current token to run mimikatz command

[Mimikatz Github Wiki](https://github.com/gentilkiwi/mimikatz/wiki "Mimikatz Github Wiki")

- - - -

## Lateral Movement ##

- - - - 

## Pivoting ##


