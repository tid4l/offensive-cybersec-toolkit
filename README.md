# Offensive Cybersecurity Toolkit

This repository was created to host tools and resources for offensive cybersecurity. The section headers below are inspired by the [Mitre ATT&CK Framework](https://attack.mitre.org/).

Other resources that don't fit neatly within one of these categories or those that may not be offensive tools can be found in the overflow page, [_All Things Cybersecurity_](all-things.md).

This project will not remain static; the intent is that it will continue to grow over time.

---

- [Reconnaissance/Discovery](#reconnaissancediscovery)

- [Initial Access](#initial-access)

- [Execution](#execution)

- [Persistence](#persistence)
    
- [Privilege Escalation](#privilege-escalation)

- [Defense Evasion](#defense-evasion)

- [Credential Access](#credential-access)
    
- [Lateral Movement](#lateral-movement)
    
- [Collection](#collection)

- [Command & Control](#command--control)
    
- [Exfiltration](#exfiltration)

- [Impact](#impact)

---

## Reconnaissance/Discovery

|Name|Description|Link|
|----|-----------|----|
|ADHuntTool|official repo for the AdHuntTool (part of the old RedTeamCSharpScripts repo)|https://github.com/Mr-Un1k0d3r/ADHuntTool|
|AutoRecon|AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.|https://github.com/Tib3rius/AutoRecon|
|Go-Dork|The fastest dork scanner written in Go.|https://github.com/dwisiswant0/go-dork|
|GoBuster|Directory/File, DNS and VHost busting tool written in Go|https://github.com/OJ/gobuster|
|It Was All A Dream|A PrintNightmare (CVE-2021-34527) Python Scanner. Scan entire subnets for hosts vulnerable to the PrintNightmare RCE|https://github.com/byt3bl33d3r/ItWasAllADream|
|Responder|Responder is a LLMNR, NBT-NS and MDNS poisoner, with built-in HTTP/SMB/MSSQL/FTP/LDAP rogue authentication server supporting NTLMv1/NTLMv2/LMv2, Extended Security NTLMSSP and Basic HTTP authentication.|https://github.com/lgandx/Responder|
|Seatbelt|Seatbelt is a C# project that performs a number of security oriented host-survey "safety checks" relevant from both offensive and defensive security perspectives.|https://github.com/GhostPack/Seatbelt|
|SharpCGHunter| Receive the status of Windows Defender Credential Guard on network hosts.|https://github.com/chdav/SharpCGHunter|
|SharpHound|C# Data Collector for the BloodHound Project, Version 3|https://github.com/BloodHoundAD/SharpHound3|
|SharpView|C# implementation of harmj0y's PowerView|https://github.com/tevora-threat/SharpView|
|Situational Awareness BOF|Situational Awareness commands implemented using Beacon Object Files|https://github.com/trustedsec/CS-Situational-Awareness-BOF|
|Watson|Enumerate missing KBs and suggest exploits for useful Privilege Escalation vulnerabilities|https://github.com/rasta-mouse/Watson|

## Initial Access

|Name|Description|Link|
|----|-----------|----|
|GoPhish|Open-Source Phishing Toolkit|https://github.com/gophish/gophish|
|Impacket|Impacket is a collection of Python classes for working with network protocols.|https://github.com/SecureAuthCorp/impacket|
|Phishmonger|Phishing Framework for Pentesters|https://github.com/fkasler/phishmonger|
|Reverse Shell Generator|Hosted Reverse Shell generator with a ton of functionality. -- (Great for CTFs)|https://github.com/0dayCTF/reverse-shell-generator|
|Yersinia|A framework for layer 2 attacks|https://github.com/tomac/yersinia|

## Execution

|Name|Description|Link|
|----|-----------|----|
|Donut|Generates x86, x64, or AMD64+x86 position-independent shellcode that loads .NET Assemblies, PE files, and other Windows payloads from memory and runs them with parameters|https://github.com/TheWover/donut|
|Evasor|A tool to be used in post exploitation phase for blue and red teams to bypass APPLICATIONCONTROL policies|https://github.com/cyberark/Evasor|
|LimeLighter|A tool for generating fake code signing certificates or signing real ones|https://github.com/Tylous/Limelighter|
|LOLBAS|Living Off The Land Binaries And Scripts - (LOLBins and LOLScripts)|https://github.com/api0cradle/LOLBAS|
|Mythic-Macro-Generator|Python3 script to generate a macro to launch a Mythic payload. Author: Cedric Owens|https://github.com/cedowens/Mythic-Macro-Generator|
|ScareCrow|ScareCrow - Payload creation framework designed around EDR bypass.|https://github.com/optiv/ScareCrow|
|SharpSploit| SharpSploit is a .NET post-exploitation library written in C# |https://github.com/cobbr/SharpSploit|
|SharpZipRunner|Executes position independent shellcode from an encrypted zip|https://github.com/jfmaes/SharpZipRunner|

## Persistence

|Name|Description|Link|
|----|-----------|----|
|SharpGPOAbuse|SharpGPOAbuse is a .NET application written in C# that can be used to take advantage of a user's edit rights on a Group Policy Object (GPO) in order to compromise the objects that are controlled by that GPO.|https://github.com/FSecureLABS/SharpGPOAbuse|
|SharpStay|.NET project for installing Persistence|https://github.com/0xthirteen/SharpStay|
|StayKit|Cobalt Strike kit for Persistence|https://github.com/0xthirteen/StayKit|
    
## Privilege Escalation

|Name|Description|Link|
|----|-----------|----|
|ElevateKit|The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.|https://github.com/rsmudge/ElevateKit|
|PEASS|Privilege Escalation Awesome Scripts SUITE (with colors)|https://github.com/carlospolop/PEASS-ng|
|SharpUp|SharpUp is a C# port of various PowerUp functionality.|https://github.com/Raikia/SharpUp|
|Traitor|Automatic Linux privesc via exploitation of low-hanging fruit e.g. gtfobins, polkit, docker socket|https://github.com/liamg/traitor|
|Windows-Exploit-Suggester|This tool compares a targets patch levels against the Microsoft vulnerability database in order to detect potential missing patches on the target. It also notifies the user if there are public exploits and Metasploit modules available for the missing bulletins.|https://github.com/AonCyberLabs/Windows-Exploit-Suggester|

## Defense Evasion

|Name|Description|Link|
|----|-----------|----|
|BOF NET|A .NET Runtime for Cobalt Strike's Beacon Object Files|https://github.com/CCob/BOF.NET|
|Chimera|Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.|https://github.com/tokyoneon/Chimera|
|EXOCET|AV-evading, undetectable, payload delivery tool|https://github.com/tanc7/EXOCET-AV-Evasion|
|Fully Undetectable Techniques|Research on Fully UnDetectable (FUD) techniques and tools (includes ransomware).|https://github.com/gnxbr/Fully-Undetectable-Techniques| 
|Hell's Gate|Original C Implementation of the Hell's Gate VX Technique|https://github.com/am0nsec/HellsGate|
|Invoke-Obfuscation| PowerShell Obfuscator|https://github.com/danielbohannon/Invoke-Obfuscation|
|Managed Injector|This project implements a .NET Assembly injection library (it is inspired by the snoopwpf project). The remote process can be a managed or unmanaged one.|https://github.com/enkomio/ManagedInjector|
|nps|Not PowerShell|https://github.com/Ben0xA/nps|
|SharpBlock|A method of bypassing EDR's active projection DLL's by preventing entry point execution|https://github.com/CCob/SharpBlock|
|SourcePoint|SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.|https://github.com/Tylous/SourcePoint|
|Thread Stack Spoofer|Thread Stack Spoofing - PoC for an advanced In-Memory evasion technique allowing to better hide injected shellcode's memory allocation from scanners and analysts.|https://github.com/mgeeky/ThreadStackSpoofer|

## Credential Access

|Name|Description|Link|
|----|-----------|----|
|Certify|Certify is a C# tool to enumerate and abuse misconfigurations in Active Directory Certificate Services (AD CS).|https://github.com/GhostPack/Certify|
|CertStealer|A .NET tool for exporting and importing certificates without touching disk.|https://github.com/TheWover/CertStealer|
|ForgeCert|ForgeCert uses the BouncyCastle C# API and a stolen Certificate Authority (CA) certificate + private key to forge certificates for arbitrary users capable of authentication to Active Directory.|https://github.com/GhostPack/ForgeCert|
|mimikatz|A little tool to play with Windows security|https://github.com/gentilkiwi/mimikatz|
|Rubeus|Rubeus is a C# toolset for raw Kerberos interaction and abuses.|https://github.com/GhostPack/Rubeus|

## Lateral Movement

|Name|Description|Link|
|----|-----------|----|
|CrackMapExec|A swiss army knife for pentesting networks|https://github.com/byt3bl33d3r/CrackMapExec|
|MoveKit|Cobalt Strike kit for Lateral Movement|https://github.com/0xthirteen/MoveKit| 
|SCShell|Fileless lateral movement tool that relies on ChangeServiceConfigA to run command|https://github.com/Mr-Un1k0d3r/SCShell|
|SharpNoPSExec|Get file less command execution for lateral movement.|https://github.com/juliourena/SharpNoPSExec|
|SharpSpray|Active Directory password spraying tool. Auto fetches user list and avoids potential lockouts.|https://github.com/iomoath/SharpSpray|
    
## Collection

|Name|Description|Link|
|----|-----------|----|
|Bettercap|The Swiss Army knife for 802.11, BLE, IPv4 and IPv6 networks reconnaissance and MITM attacks. |https://github.com/bettercap/bettercap|
|Ettercap|A suite for man in the middle attacks|https://github.com/Ettercap/ettercap|
|sslstrip|A tool for exploiting Moxie Marlinspike's SSL "stripping" attack.|https://github.com/moxie0/sslstrip|

## Command & Control

|Name|Description|Link|
|----|-----------|----|
|Empire|Empire is a PowerShell and Python 3.x post-exploitation framework.|https://github.com/BC-SECURITY/Empire|
|Merlin|Merlin is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in golang.|https://github.com/Ne0nd0g/merlin|
|Mythic|A collaborative, multi-platform, red teaming framework|https://github.com/its-a-feature/Mythic|
|Prelude|All open-source resources for the Prelude Operator C2 platform|https://github.com/preludeorg/community| 
|Sliver|Adversary Emulation Framework|https://github.com/BishopFox/sliver|
    
## Exfiltration

|Name|Description|Link|
|----|-----------|----|
|DNSExfiltrator|Data exfiltration over DNS request covert channel|https://github.com/Arno0x/DNSExfiltrator|
|MFTdotNET|$MFT exporter built for .NET Framework 3.5|https://github.com/Wra7h/MFTdotNET|
|Ratnet|Ratnet is a prototype anonymity network for mesh routing and embedded scenarios.|https://github.com/awgh/ratnet|
|SharpExfiltrate|Modular C# framework to exfiltrate loot over secure and trusted channels.|https://github.com/Flangvik/SharpExfiltrate|

## Impact

|Name|Description|Link|
|----|-----------|----|
|Hidden Tear|An open source ransomware-like file crypter kit|https://github.com/0x0mar/hidden-tear|
|Racketeer|The goal of this project is to provide a way for teams to simulate and test detection of common ransomware operation, in a controlled manner, against a set of company assets and network endpoints.|https://github.com/dsnezhkov/racketeer| 