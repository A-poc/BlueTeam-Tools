# BlueTeam-Tools

<p align="center">
<img src="https://user-images.githubusercontent.com/100603074/210680535-40d8c113-2336-4417-bdb4-4825a7477164.png" height="300">
</p> 

This github repository contains a collection of **65+** **tools** and **resources** that can be useful for **blue teaming activities**. 

Some of the tools may be specifically designed for blue teaming, while others are more general-purpose and can be adapted for use in a blue teaming context.

> 🔗 If you are a Red Teamer, check out [RedTeam-Tools](https://github.com/A-poc/RedTeam-Tools)

> **Warning** 
> 
> *The materials in this repository are for informational and educational purposes only. They are not intended for use in any illegal activities.*

> **Note** 
> 
> *Hide Tool List headings with the arrow.*
> 
> *Click 🔙 to get back to the list.*

# Tool List

<details open>
    <summary><b>Blue Team Tips</b> 4 tips</summary>
    <ul>
        <ul>
            <li><b><a href="#payload-extraction-with-process-hacker">Payload extraction with Process Hacker</a></b><i> @embee_research</i></li>
            <li><b><a href="#prevent-script-execution-via-double-click">Prevent Script Execution via Double Click</a></b><i> Default Application GPO Change</i></li>
            <li><b><a href="#detect-cryptojacking-malware-with-proxy-logs">Detect Cryptojacking Malware with Proxy Logs</a></b><i> Dave Mckay</i></li>
            <li><b><a href="#remove-null-bytes-in-cyberchef-malware-analysis">Remove null bytes in CyberChef malware analysis</a></b><i> @Securityinbits</i></li>
        </ul>
    </ul>
</details>

<details open>
    <summary><b>Network Discovery and Mapping</b> 6 tools</summary>
    <ul>
        <ul>
            <li><b><a href="#nmap">Nmap</a></b><i> Network scanner</i></li>
            <li><b><a href="#nuclei">Nuclei</a></b><i> Vulnerability scanner</i></li>
            <li><b><a href="#masscan">Masscan</a></b><i> Fast network scanner</i></li>
            <li><b><a href="#angry-ip-scanner">Angry IP Scanner</a></b><i> IP/port scanner</i></li>
            <li><b><a href="#zmap">ZMap</a></b><i> Large network scanner</i></li>
            <li><b><a href="#shodan">Shodan</a></b><i> Internet facing asset search engine</i></li>
        </ul>
    </ul>
</details>

<details open>
    <summary><b>Vulnerability Management</b> 4 tools</summary>
    <ul>
        <ul>
            <li><b><a href="#openvas">OpenVAS</a></b><i> Open-source vulnerability scanner</i></li>
            <li><b><a href="#nessus-essentials">Nessus Essentials</a></b><i> Vulnerability scanner</i></li>
            <li><b><a href="#nexpose">Nexpose</a></b><i> Vulnerability management tool</i></li>
            <li><b><a href="#hackerone">HackerOne</a></b><i> Bug Bounty Management Platform</i></li>
        </ul>
    </ul>
</details>

<details open>
    <summary><b>Security Monitoring</b> 10 tools</summary>
    <ul>
        <ul>
            <li><b><a href="#sysmon">Sysmon</a></b><i> System Monitor for Windows</i></li>
            <li><b><a href="#kibana">Kibana</a></b><i> Data visualization and exploration</i></li>
            <li><b><a href="#logstash">Logstash</a></b><i> Data collection and processing</i></li>
            <li><b><a href="#parsedmarc">parsedmarc</a></b><i> Email DMARC data visualisation</i></li>
            <li><b><a href="#phishing-catcher">Phishing Catcher</a></b><i> Phishing catcher using Certstream</i></li>
            <li><b><a href="#maltrail">maltrail</a></b><i> Malicious traffic detection system</i></li>
            <li><b><a href="#autorunstowineventlog">AutorunsToWinEventLog</a></b><i> Windows AutoRuns Event Parser</i></li>
            <li><b><a href="#procfilter">procfilter</a></b><i> YARA-integrated process denial framework</i></li>
            <li><b><a href="#velociraptor">velociraptor</a></b><i> Endpoint visibility and collection tool</i></li>
            <li><b><a href="#sysmonsearch">SysmonSearch</a></b><i> Sysmon event log visualisation</i></li>
        </ul>
    </ul>
</details>

<details open>
    <summary><b>Threat Tools and Techniques</b> 11 tools</summary>
    <ul>
        <ul>
            <li><b><a href="#lolbas-projectgithubio">lolbas-project.github.io</a></b><i> Living Off The Land Windows Binaries</i></li>
            <li><b><a href="#gtfobinsgithubio">gtfobins.github.io</a></b><i> Living Off The Land Linux Binaries</i></li>
            <li><b><a href="#filesecio">filesec.io</a></b><i> Attacker file extensions</i></li>
            <li><b><a href="#kql-search">KQL Search</a></b><i> KQL query aggregator</i></li>
            <li><b><a href="#unprotect-project">Unprotect Project</a></b><i> Malware evasion techniques knowledge base</i></li>
            <li><b><a href="#chainsaw">chainsaw</a></b><i> Fast Windows Forensic Artefacts Searcher</i></li>
            <li><b><a href="#freq">freq</a></b><i> Domain generation algorithm malware detection</i></li>
            <li><b><a href="#yargen">yarGen</a></b><i> YARA rule generator</i></li>
            <li><b><a href="#emailanalyzer">EmailAnalyzer</a></b><i> Suspicious emails analyser</i></li>
            <li><b><a href="#vcg">VCG</a></b><i> Code security scanning tool</i></li>
            <li><b><a href="#cyberchef">CyberChef</a></b><i> GCHQ online data manipulation platform</i></li>
        </ul>
    </ul>
</details>

<details open>
    <summary><b>Threat Intelligence</b> 4 tools</summary>
    <ul>
        <ul>
            <li><b><a href="#maltego">Maltego</a></b><i> Threat Intelligence Platform</i></li>
            <li><b><a href="#misp">MISP</a></b><i> Malware Information Sharing Platform</i></li>
            <li><b><a href="#threatconnect">ThreatConnect</a></b><i> Threat data aggregation</i></li>
            <li><b><a href="#adversary-emulation-library">Adversary Emulation Library</a></b><i> An open library of adversary emulation plans</i></li>
        </ul>
    </ul>
</details>

<details open>
    <summary><b>Incident Response Planning</b> 5 tools</summary>
    <ul>
        <ul>
            <li><b><a href="#nist">NIST</a></b><i> Cybersecurity Framework</i></li>
            <li><b><a href="#incident-response-plan">Incident Response Plan</a></b><i> Framework for incident response</i></li>
            <li><b><a href="#ransomware-response-plan">Ransomware Response Plan</a></b><i> Framework for ransomware response</i></li>
            <li><b><a href="#incident-response-reference-guide">Incident Response Reference Guide</a></b><i> Incident preparation guidance paper</i></li>
            <li><b><a href="#awesome-incident-response">Awesome Incident Response</a></b><i> List of tools for incident response</i></li>
        </ul>
    </ul>
</details>

<details open>
    <summary><b>Malware Detection and Analysis</b> 11 tools</summary>
    <ul>
        <ul>
            <li><b><a href="#virustotal">VirusTotal</a></b><i> Malicious IOC Sharing Platform</i></li>
            <li><b><a href="#ida">IDA</a></b><i> Malware disassembler and debugger</i></li>
            <li><b><a href="#ghidra">Ghidra</a></b><i> Malware reverse engineering tool</i></li>
            <li><b><a href="#decode-vbe">decode-vbe</a></b><i> Encoded VBE script decoder</i></li>
            <li><b><a href="#pafish">pafish</a></b><i> Virtual machine sandbox detector</i></li>
            <li><b><a href="#lookyloo">lookyloo</a></b><i> Phishing domain mapping</i></li>
            <li><b><a href="#yara">YARA</a></b><i> Malware identification via pattern matching</i></li>
            <li><b><a href="#cuckoo-sandbox">Cuckoo Sandbox</a></b><i> Malware analysis sandbox</i></li>
            <li><b><a href="#radare2">Radare2</a></b><i> Reverse engineering framework</i></li>
            <li><b><a href="#dnspy">dnSpy</a></b><i> .NET debugger and assembly editor</i></li>
            <li><b><a href="#malware-traffic-analysisnet">malware-traffic-analysis.net</a></b><i> Malware and packet capture samples</i></li>
        </ul>
    </ul>
</details>

<details open>
    <summary><b>Data Recovery</b> 3 tools</summary>
    <ul>
        <ul>
            <li><b><a href="#recuva">Recuva</a></b><i> File recovery</i></li>
            <li><b><a href="#extundelete">Extundelete</a></b><i> Ext3 or ext4 partition recovery</i></li>
            <li><b><a href="#testdisk">TestDisk</a></b><i> Data Recovery</i></li>
        </ul>
    </ul>
</details>

<details open>
    <summary><b>Digital Forensics</b> 3 tools</summary>
    <ul>
        <ul>
            <li><b><a href="#sans-sift">SANS SIFT</a></b><i> Forensic toolkit</i></li>
            <li><b><a href="#the-sleuth-kit">The Sleuth Kit</a></b><i> Disk images analysis tools</i></li>
            <li><b><a href="#autopsy">Autopsy</a></b><i> Digital forensics platform</i></li>
        </ul>
    </ul>
</details>

<details open>
    <summary><b>Security Awareness Training</b> 3 tools</summary>
    <ul>
        <ul>
            <li><b><a href="#tryhackme">TryHackMe</a></b><i> Cyber security challenges platform</i></li>
            <li><b><a href="#hackthebox">HackTheBox</a></b><i> Cyber security challenges platform</i></li>
            <li><b><a href="#phishme">PhishMe</a></b><i> Phishing training</i></li>
        </ul>
    </ul>
</details>

<details open>
    <summary><b>Communication and Collaboration</b> 2 tools</summary>
    <ul>
        <ul>
            <li><b><a href="#twitter">Twitter</a></b><i> Cyber Security Accounts</i></li>
            <li><b><a href="#facebook-theatexchange">Facebook TheatExchange</a></b><i> Malicious indicators sharing platform</i></li>
        </ul>
    </ul>
</details>

Blue Team Tips
====================

*Learn from Blue Teamers with a collection of Blue Teaming Tips. These tips cover a range of tactics, tools, and methodologies to improve your blue teaming abilities.*

### [🔙](#tool-list)Payload extraction with Process Hacker

![image](https://user-images.githubusercontent.com/100603074/217382117-acb26f85-d352-43b3-8818-6c5a0d90f350.png)

**Description:** 
*'Malware Analysis Tip  - Use Process Hacker to watch for suspicious .NET assemblies in newly spawned processes. Combined with DnSpy - it's possible to locate and extract malicious payloads without needing to manually de-obfuscate.'*

**Credit:** [@embee_research](https://twitter.com/embee_research)

**Link:** [Twitter](https://twitter.com/embee_research/status/1614871485931458560)

### [🔙](#tool-list)Prevent Script Execution via Double Click

![image](https://user-images.githubusercontent.com/100603074/218200763-53f9fc80-59e1-468a-93e2-69b84d1c7196.png)

**Description:** 
*On Windows, it's common to see threat actors achieve initial execution via malicious script files masquerading as Microsoft Office files. A nice way to prevent this attack chain is to alter the default application associated with these files (HTA, JS, VBA, VBS) to `notepad.exe`. Now when a user is successfully tricked into clicking a HTA file on disk it will open the script in notepad and execution will not occur*.

**Credit:** [bluesoul](https://bluesoul.me/)

**Link:** [Blog](https://bluesoul.me/2016/05/12/use-gpo-to-change-the-default-behavior-of-potentially-malicious-file-extensions/)

### [🔙](#tool-list)Detect Cryptojacking Malware with Proxy Logs

**Description:** *Cryptojacking malware is becoming more suffisticated, with mining malware leveraging DLL sideloading to hide on machine and reducing CPU load to stay below detection thresholds. One thing they all have in common is they have to make connections to mining pools, this is where we can find them. Monitor your proxy and DNS logs for connections containing common mining pool strings (e.g `*xmr.*` OR `*pool.com` OR `*pool.org` OR `pool.*`).*

**Credit:** [Dave Mckay](https://www.howtogeek.com/author/davidmckay/)

**Link:** [Blog](https://www.howtogeek.com/devops/how-to-detect-and-defeat-cryptominers-in-your-network/)

### [🔙](#tool-list)Remove null bytes in CyberChef malware analysis

![image](https://user-images.githubusercontent.com/100603074/223865015-00128d71-0093-4422-b271-e26dac723013.png)

**Description:** *'After decoding base64 for Unicode string during malware analysis, you may encounter null bytes. Keep your code readable by using the "Remove null bytes" operation in CyberChef'.*

**Credit:** [Ayush Anand](https://twitter.com/Securityinbits)

**Link:** [Twitter](https://twitter.com/securityinbits/status/1628364983661694976)

Network Discovery and Mapping
====================

*Tools for scanning and mapping out the network, discovering devices and services, and identifying potential vulnerabilities.*

### [🔙](#tool-list)[Nmap](https://nmap.org)

Nmap (short for Network Mapper) is a free and open-source network scanner tool used to discover hosts and services on a computer network, and to probe for information about their characteristics.

It can be used to determine which ports on a network are open and what services are running on those ports. Including the ability to identify security vulnerabilities on the network.

**Install:** 

You can download the latest release from [here](https://nmap.org/download).

**Usage:** 

```bash
# Scan a single IP
nmap 192.168.1.1

# Scan a range
nmap 192.168.1.1-254

# Scan targets from a file
nmap -iL targets.txt

# Port scan for port 21
nmap 192.168.1.1 -p 21

# Enables OS detection, version detection, script scanning, and traceroute
nmap 192.168.1.1 -A

```

Nice usage [cheat sheet](https://www.stationx.net/nmap-cheat-sheet/).

![image](https://user-images.githubusercontent.com/100603074/210288428-01875d96-72e6-4857-b18d-4e10d80863ad.png)

*Image used from https://kirelos.com/nmap-version-scan-determining-the-version-and-available-services/*

### [🔙](#tool-list)[Nuclei](https://nuclei.projectdiscovery.io/nuclei/get-started/)

A specialized tool designed to automate the process of detecting vulnerabilities in web applications, networks, and infrastructure.

Nuclei uses pre-defined templates to probe a target and identify potential vulnerabilities. It can be used to test a single host or a range of hosts, and can be configured to run a variety of tests to check for different types of vulnerabilities.

**Install:** 

```bash
git clone https://github.com/projectdiscovery/nuclei.git; \
cd nuclei/v2/cmd/nuclei; \
go build; \
mv nuclei /usr/local/bin/; \
nuclei -version;
```

**Usage:** 

```bash
# All the templates gets executed from default template installation path.
nuclei -u https://example.com

# Custom template directory or multiple template directory
nuclei -u https://example.com -t cves/ -t exposures/

# Templates can be executed against list of URLs
nuclei -list http_urls.txt

# Excluding single template
nuclei -list urls.txt -t cves/ -exclude-templates cves/2020/CVE-2020-XXXX.yaml
```

Full usage information can be found [here](https://nuclei.projectdiscovery.io/nuclei/get-started/#running-nuclei).

![image](https://user-images.githubusercontent.com/100603074/210288448-c2d9da7d-e68f-4d06-9066-b702ce4b5cb3.png)

*Image used from https://www.appsecsanta.com/nuclei*

### [🔙](#tool-list)[Masscan]()

A port scanner that is similar to nmap, but is much faster and can scan a large number of ports in a short amount of time.

Masscan uses a novel technique called "SYN scan" to scan networks, which allows it to scan a large number of ports very quickly.

**Install: (Apt)** 

```bash
sudo apt install masscan
```

**Install: (Git)** 

```bash
sudo apt-get install clang git gcc make libpcap-dev
git clone https://github.com/robertdavidgraham/masscan
cd masscan
make
```

**Usage:** 

```bash
# Scan for a selection of ports (-p22,80,445) across a given subnet (192.168.1.0/24)
masscan -p22,80,445 192.168.1.0/24

# Scan a class B subnet for ports 22 through 25
masscan 10.11.0.0/16 -p22-25

# Scan a class B subnet for the top 100 ports at 100,000 packets per second
masscan 10.11.0.0/16 ‐‐top-ports 100 ––rate 100000

# Scan a class B subnet, but avoid the ranges in exclude.txt
masscan 10.11.0.0/16 ‐‐top-ports 100 ‐‐excludefile exclude.txt
```

![image](https://user-images.githubusercontent.com/100603074/210288465-fa4d7b45-d7ff-4c5e-82a6-e0d480b387c7.png)

*Image used from https://kalilinuxtutorials.com/masscan/*

### [🔙](#tool-list)[Angry IP Scanner](https://angryip.org/)

A free and open-source tool for scanning IP addresses and ports. 

It's a cross-platform tool, designed to be fast and easy to use, and can scan an entire network or a range of IP addresses to find live hosts.

Angry IP Scanner can also detect the hostname and MAC address of a device, and can be used to perform basic ping sweeps and port scans.

**Install:** 

You can download the latest release from [here](https://angryip.org/download/).

**Usage:** 

Angry IP Scanner can be used via the GUI.

Full usage information and documentation can be found [here](https://angryip.org/documentation/).

![image](https://user-images.githubusercontent.com/100603074/210288485-711924ca-504e-4655-9e91-a0ecf32b2e63.png)

*Image used from https://angryip.org/screenshots/*

### [🔙](#tool-list)[ZMap](https://github.com/zmap/zmap)

ZMap is a network scanner designed to perform comprehensive scans of the IPv4 address space or large portions of it.

On a typical desktop computer with a gigabit Ethernet connection, ZMap is capable scanning the entire public IPv4 address space in under 45 minutes.

**Install:** 

You can download the latest release from [here](https://github.com/zmap/zmap/releases).

**Usage:** 

```bash
# Scan only 10.0.0.0/8 and 192.168.0.0/16 on TCP/80
zmap -p 80 10.0.0.0/8 192.168.0.0/16
```

Full usage information can be found [here](https://github.com/zmap/zmap/wiki).

![image](https://user-images.githubusercontent.com/100603074/210288512-fe050de5-fe7a-4c90-aab3-f307146f2b20.png)

*Image used from https://www.hackers-arise.com/post/zmap-for-scanning-the-internet-scan-the-entire-internet-in-45-minutes*

### [🔙](#tool-list)[Shodan]()

Shodan is a search engine for internet-connected devices.

It crawls the internet for assets, allowing users to search for specific devices and view information about them. 

This information can include the device's IP address, the software and version it is running, and the type of device it is.

**Install:** 

The search engine can be accessed at [https://www.shodan.io/dashboard](https://www.shodan.io/dashboard).

**Usage:** 

[Shodan query fundamentals](https://help.shodan.io/the-basics/search-query-fundamentals)

[Shodan query examples](https://www.shodan.io/search/examples)

[Nice query cheatsheet](https://www.osintme.com/index.php/2021/01/16/ultimate-osint-with-shodan-100-great-shodan-queries/)

![image](https://user-images.githubusercontent.com/100603074/191689282-70f99fe9-aa08-4cd3-b881-764eface8546.png)

*Image used from https://www.shodan.io/*

Vulnerability Management
====================

*Tools for identifying, prioritizing, and mitigating vulnerabilities in the network and on individual devices.*

### [🔙](#tool-list)[OpenVAS](https://openvas.org/)

OpenVAS is an open-source vulnerability scanner that helps identify security vulnerabilities in software and networks.

It is a tool that can be used to perform network security assessments and is often used to identify vulnerabilities in systems and applications so that they can be patched or mitigated. 

OpenVAS is developed by the Greenbone Networks company and is available as a free and open-source software application.

**Install: (Kali)** 

```bash
apt-get update
apt-get dist-upgrade
apt-get install openvas
openvas-setup
```

**Usage:** 

```bash
openvas-start
```

Visit https://127.0.0.1:9392, accept the SSL certificate popup and login with admin credentials:

- username:admin
- password:(*Password in openvas-setup command output*)

![image](https://user-images.githubusercontent.com/100603074/210452918-aa8d7be0-e557-4556-937c-334df02702dc.png)

*Image used from https://www.kali.org/blog/openvas-vulnerability-scanning/*

### [🔙](#tool-list)[Nessus Essentials](https://www.tenable.com/products/nessus/nessus-essentials)

Nessus is a vulnerability scanner that helps identify and assess the vulnerabilities that exist within a network or computer system.

It is a tool that is used to perform security assessments and can be used to identify vulnerabilities in systems and applications so that they can be patched or mitigated.

Nessus is developed by Tenable, Inc. and is available in both free and paid versions: 

- The free version, called Nessus Essentials, is available for personal use only and is limited in its capabilities compared to the paid version. 
- The paid version, called Nessus Professional, is more fully featured and is intended for use in a professional setting.

**Install:** 

Register for a Nessus Essentials activation code [here](https://www.tenable.com/products/nessus/nessus-essentials) and download.

Purchase Nessus Professional from [here](https://www.tenable.com/products/nessus/nessus-professional).

**Usage:** 

Extensive documentation can be found [here](https://docs.tenable.com/nessus/Content/GetStarted.htm).

[Nessus Plugins Search](https://www.tenable.com/plugins/search)

[Tenable Community](https://community.tenable.com/)

![image](https://user-images.githubusercontent.com/100603074/210452954-6208f96a-d180-4c8d-9579-313613d2cbe2.png)

*Image used from https://www.tenable.com*

### [🔙](#tool-list)[Nexpose](https://www.rapid7.com/products/nexpose/)

Nexpose is a vulnerability management tool developed by Rapid7. It is designed to help organizations identify and assess vulnerabilities in their systems and applications in order to mitigate risk and improve security.

Nexpose can be used to scan networks, devices, and applications in order to identify vulnerabilities and provide recommendations for remediation.

It also offers features such as asset discovery, risk prioritization, and integration with other tools in the Rapid7 vulnerability management platform.

**Install:** 

For detailed installation instructions see [here](https://docs.rapid7.com/nexpose/install/).

**Usage:** 

For full login information see [here](https://docs.rapid7.com/nexpose/log-in-and-activate).

For usage and scan creation instructions see [here](https://docs.rapid7.com/nexpose/create-and-scan-a-site).

![image](https://user-images.githubusercontent.com/100603074/210452992-cf9976ee-6b93-465d-bc1c-6e23cc387dba.png)

*Image used from https://www.rapid7.com/products/nexpose/*

### [🔙](#tool-list)[HackerOne](https://www.hackerone.com/)

HackerOne is a bug bounty management company that can be used to create and manage bug bounty programs for your business.

Bug bounty programs are a great way to outsource external vulnerability assessments, with the platform offering both private and public programs with the ability set program scopes and rules of engagement.

HackerOne also offer initial triage and management of external bug reports from researchers, with the ability to compensate researchers directly through the platform.

![image](https://user-images.githubusercontent.com/100603074/217382232-b8df098a-c74b-4552-b344-f5228c84c383.png)

*Image used from https://www.hackerone.com/product/bug-bounty-platform*

Security Monitoring
====================

*Tools for collecting and analyzing security logs and other data sources to identify potential threats and anomalous activity.*

### [🔙](#tool-list)[Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

Sysmon is a Windows system monitor that tracks system activity and logs it to the Windows event log.

It provides detailed information about system activity, including process creation and termination, network connections, and changes to file creation time.

Sysmon can be configured to monitor specific events or processes and can be used to alert administrators of suspicious activity on a system.

**Install:** 

Download the sysmon binary from [here](https://download.sysinternals.com/files/Sysmon.zip).

**Usage:** 

```bash
# Install with default settings (process images hashed with SHA1 and no network monitoring)
sysmon -accepteula -i

# Install Sysmon with a configuration file (as described below)
sysmon -accepteula -i c:\windows\config.xml

# Uninstall
sysmon -u

# Dump the current configuration
sysmon -c
```

Full event filtering information can be found [here](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-filtering-entries).

The Microsoft documentation page can be found [here](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).

![image](https://user-images.githubusercontent.com/100603074/210621009-b3c31c2b-f789-450a-acbf-7578fa943abd.png)

*Image used from https://nsaneforums.com/topic/281207-sysmon-5-brings-registry-modification-logging/*

### [🔙](#tool-list)[Kibana](https://www.elastic.co/kibana/)

Kibana is an open-source data visualization and exploration tool that is often used for log analysis in combination with Elasticsearch.

Kibana provides a user-friendly interface for searching, visualizing, and analyzing log data, which can be helpful for identifying patterns and trends that may indicate a security threat.

Kibana can be used to analyze a wide range of data sources, including system logs, network logs, and application logs. It can also be used to create custom dashboards and alerts to help security teams stay informed about potential threats and respond quickly to incidents.

**Install:** 

You can download Kibana from [here](https://www.elastic.co/downloads/kibana).

Installation instructions can be found [here](https://www.elastic.co/guide/en/kibana/current/install.html).

**Usage: (Visualize and explore log data)** 

Kibana provides a range of visualization tools that can help you identify patterns and trends in your log data. You can use these tools to create custom dashboards that display relevant metrics and alerts.

**Usage: (Threat Alerting)**

Kibana can be configured to send alerts when it detects certain patterns or anomalies in your log data. You can set up alerts to notify you of potential security threats, such as failed login attempts or network connections to known malicious IP addresses.

Nice [blog](https://phoenixnap.com/kb/kibana-tutorial) about querying and visualizing data in Kibana.

![image](https://user-images.githubusercontent.com/100603074/210621061-badf3acf-2680-42c5-bbd9-43bca7a85cf2.png)

*Image used from https://www.pinterest.co.uk/pin/analysing-honeypot-data-using-kibana-and-elasticsearch--684758318328369269/*

### [🔙](#tool-list)[Logstash](https://www.elastic.co/logstash/)

Logstash is a open-source data collection engine with real-time pipelining capabilities. It is a server-side data processing pipeline that ingests data from a multitude of sources simultaneously, transforms it, and then sends it to a "stash" like Elasticsearch.

Logstash has a rich set of plugins, which allows it to connect to a variety of sources and process the data in multiple ways. It can parse and transform logs, translate data into a structured format, or send it to another tool for further processing.

With its ability to process large volumes of data quickly, Logstash is an integral part of the ELK stack (Elasticsearch, Logstash, and Kibana) and is often used to centralize, transform, and monitor log data.

**Install:** 

Download logstash from [here](https://www.elastic.co/downloads/logstash).

**Usage:** 

Full logstash documentation [here](https://www.elastic.co/guide/en/logstash/current/introduction.html).

Configuration examples [here](https://www.elastic.co/guide/en/logstash/current/config-examples.html).

![image](https://user-images.githubusercontent.com/100603074/210621111-e7630493-bc1c-41fa-af98-0261fbf6e293.png)

*Image used from https://www.elastic.co/guide/en/logstash/current/logstash-modules.html*

### [🔙](#tool-list)[parsedmarc](https://github.com/domainaware/parsedmarc)

A Python module and CLI utility for parsing DMARC reports. 

When used with Elasticsearch and Kibana (or Splunk), it works as a self-hosted open source alternative to commercial DMARC report processing services such as Agari Brand Protection, Dmarcian, OnDMARC, ProofPoint Email Fraud Defense, and Valimail.

Features:

- Parses draft and 1.0 standard aggregate/rua reports
- Parses forensic/failure/ruf reports
- Can parse reports from an inbox over IMAP, Microsoft Graph, or Gmail API
- Transparently handles gzip or zip compressed reports
- Consistent data structures
- Simple JSON and/or CSV output
- Optionally email the results
- Optionally send the results to Elasticsearch and/or Splunk, for use with premade dashboards
- Optionally send reports to Apache Kafka

![image](https://user-images.githubusercontent.com/100603074/217382301-064ac450-3690-469d-9c86-c2e3c6cdeca9.png)

*Image used from https://github.com/domainaware/parsedmarc*

### [🔙](#tool-list)[Phishing Catcher](https://github.com/x0rz/phishing_catcher)

As a business, phishing can cause reputational and financial damage to you and your customers. Being able to proactively identify phishing infrastructure targeting your business helps to reduce the risk of these damages.

Phish catcher allows you to catch possible phishing domains in near real time by looking for suspicious TLS certificate issuances reported to the Certificate Transparency Log (CTL) via the CertStream API. 

"Suspicious" issuances are those whose domain name scores beyond a certain threshold based on a configuration file.

![image](https://user-images.githubusercontent.com/100603074/217382453-400a044b-720d-47ce-adff-0a23e5511ae1.png)

*Image used from https://github.com/x0rz/phishing_catcher*

### [🔙](#tool-list)[maltrail](https://github.com/stamparm/maltrail)

Maltrail is a malicious traffic detection system, utilizing publicly available lists containing malicious and/or generally suspicious trails, along with static trails compiled from various AV reports and custom user defined lists. A trail can be anything from domain name, URL, IP address or HTTP User-Agent header value.

A demo page for this tool can be found [here](https://maltraildemo.github.io/).

**Install:** 

```bash
sudo apt-get install git python3 python3-dev python3-pip python-is-python3 libpcap-dev build-essential procps schedtool
sudo pip3 install pcapy-ng
git clone --depth 1 https://github.com/stamparm/maltrail.git
cd maltrail
```

**Usage:** 

```bash
sudo python3 sensor.py
```

![image](https://user-images.githubusercontent.com/100603074/217382540-fa1283d7-9825-4529-a92f-11f447e4657b.png)

*Image used from https://github.com/stamparm/maltrail*

### [🔙](#tool-list)[AutorunsToWinEventLog](https://github.com/palantir/windows-event-forwarding/tree/master/AutorunsToWinEventLog)

Autoruns is a tool developed by Sysinternals that allows you to view all of the locations in Windows where applications can insert themselves to launch at boot or when certain applications are opened. Malware often takes advantages of these locations to ensure that it runs whenever your computer boots up.

Autoruns conveniently includes a non-interactive command line utility. This code generates a CSV of Autoruns entries, converts them to JSON, and finally inserts them into a custom Windows Event Log. By doing this, we can take advantage of our existing WEF infrastructure to get these entries into our SIEM and start looking for signs of malicious persistence on endpoints and servers.

**Install:** 

Download [AutorunsToWinEventLog](https://github.com/palantir/windows-event-forwarding/tree/master/AutorunsToWinEventLog).

**Usage:** 

From an Admin Powershell console run `.\Install.ps1` 

This script does the following:

- Creates the directory structure at c:\Program Files\AutorunsToWinEventLog
- Copies over AutorunsToWinEventLog.ps1 to that directory
- Downloads Autorunsc64.exe from https://live.sysinternals.com
- Sets up a scheduled task to run the script daily @ 11am

![image](https://user-images.githubusercontent.com/100603074/218199447-40e7add1-68ee-44e2-a297-3bf03c977a9c.png)

*Image used from https://www.detectionlab.network/usage/autorunstowineventlog/*

### [🔙](#tool-list)[procfilter](https://github.com/godaddy/procfilter)

ProcFilter is a process filtering system for Windows with built-in [YARA](https://github.com/virustotal/yara) integration. YARA rules can be instrumented with custom meta tags that tailor its response to rule matches. It runs as a Windows service and is integrated with [Microsoft's ETW API](https://msdn.microsoft.com/en-us/library/windows/desktop/bb968803%28v=vs.85%29.aspx), making results viewable in the Windows Event Log. Installation, activation, and removal can be done dynamically and does not require a reboot.

ProcFilter's intended use is for malware analysts to be able to create YARA signatures that protect their Windows environments against a specific threat. It does not include a large signature set. Think lightweight, precise, and targeted rather than broad or all-encompassing. ProcFilter is also intended for use in controlled analysis environments where custom plugins can perform artifact-specific actions.

**Install:** 

[ProcFilter x86/x64 Release/Debug Installers](https://github.com/godaddy/procfilter/releases)

*Note: Unpatched Windows 7 systems require hotfix 3033929 to load the driver component. More information can be found here.*

Nice configuration template file [here](https://github.com/godaddy/procfilter/blob/master/files/procfilter.ini).

**Usage:** 

```
procfilter -start
```

Usage screenshots can be found [here](https://github.com/godaddy/procfilter#screenshots).

![image](https://user-images.githubusercontent.com/100603074/218200282-f2465b93-169a-43d6-8e12-dea61ed9272c.png)

*Image used from https://github.com/godaddy/procfilter*

### [🔙](#tool-list)[velociraptor](https://github.com/Velocidex/velociraptor)

Velociraptor is a unique, advanced open-source endpoint monitoring, digital forensic and cyber response platform.

It was developed by Digital Forensic and Incident Response (DFIR) professionals who needed a powerful and efficient way to hunt for specific artifacts and monitor activities across fleets of endpoints. Velociraptor provides you with the ability to more effectively respond to a wide range of digital forensic and cyber incident response investigations and data breaches:

Features:

- Reconstruct attacker activities through digital forensic analysis
- Hunt for evidence of sophisticated adversaries
- Investigate malware outbreaks and other suspicious network activities
- Monitory continuously for suspicious user activities, such as files copied to USB devices
- Discover whether disclosure of confidential information occurred outside the network
- Gather endpoint data over time for use in threat hunting and future investigations


**Install:** 

Download the binary from the [release page](https://github.com/Velocidex/velociraptor/releases).

**Usage:** 

```
velociraptor gui
```

Full usage information can be found [here](https://docs.velociraptor.app/).

![image](https://user-images.githubusercontent.com/100603074/218200327-3f5ab599-11f1-46dc-8f28-b27c1258224a.png)

*Image used from https://docs.velociraptor.app*

### [🔙](#tool-list)[SysmonSearch](https://github.com/JPCERTCC/SysmonSearch)

SysmonSearch makes event log analysis more effective and less time consuming, by aggregating event logs generated by Microsoft's Sysmon.

  SysmonSearch uses Elasticserach and Kibana (and Kibana plugin).
  * **Elasticserach**  
    Elasticsearch collects/stores Sysmon's event log.
  * **Kibana**  
    Kibana provides user interface for your Sysmon's event log analysis. The following functions are implemented as Kibana plugin.
    * Visualizes Function  
      This function visualizes Sysmon's event logs to illustrate correlation of processes and networks.
    * Statistical Function  
      This function collects the statistics of each device or Sysmon's event ID.
    * Monitor Function  
      This function monitor incoming logs based on the preconfigured rules, and trigers alert.
  * **StixIoC server**  
    You can add search/monitor condition by uploading STIX/IOC file. From StixIoC server Web UI, you can upload STIXv1, STIXv2 and OpenIOC format files.

**Install: (Linux)** 

```bash
git clone https://github.com/JPCERTCC/SysmonSearch.git
```

[Modify Elasticsearch configuration](https://github.com/JPCERTCC/SysmonSearch/wiki/Install#elasticsearch-server-setup)

[Modify Kibana configuration](https://github.com/JPCERTCC/SysmonSearch/wiki/Install#kibana-server-setup)

Full installation instructions can be found [here](https://github.com/JPCERTCC/SysmonSearch/wiki/Install).

**Usage:** 

*Once Elasticsearch and Kibana configurations have been modified, restart the services and navigate to your Kibana interface. The SysmonSearch ribbon should be visible.*

[Visualize the Sysmon log to investigate suspicious behavior](https://blogs.jpcert.or.jp/ja/2018/09/SysmonSearch.html)

![image](https://user-images.githubusercontent.com/100603074/218200383-84e4c9f4-3e34-4973-b37c-a9160a74b5e0.png)

*Image used from https://blogs.jpcert.or.jp/ja/2018/09/SysmonSearch.html*

Threat Tools and Techniques
====================

*Tools for identifying and implementing detections against TTPs used by threat actors.*

### [🔙](#tool-list)[lolbas-project.github.io](https://lolbas-project.github.io/)

Living off the land binaries (LOLBins) are legitimate Windows executables that can be used by threat actors to carry out malicious activities without raising suspicion. 

Using LOLBins allows attackers to blend in with normal system activity and evade detection, making them a popular choice for malicious actors.

The LOLBAS project is a MITRE mapped list of LOLBINS with commands, usage and detection information for defenders.

Visit [https://lolbas-project.github.io/](https://lolbas-project.github.io/).

**Usage:** 

Use the information for detection opportunities to harden your infrastructure against LOLBIN usage. 

Here are some project links to get started:

- [Bitsadmin.exe](https://lolbas-project.github.io/lolbas/Binaries/Bitsadmin/)
- [Certutil.exe](https://lolbas-project.github.io/lolbas/Binaries/Certutil/)
- [Cscript.exe](https://lolbas-project.github.io/lolbas/Binaries/Cscript/)

![image](https://user-images.githubusercontent.com/100603074/210625466-9ab87233-e822-4961-a68a-f863f56ef830.png)

*Image used from https://lolbas-project.github.io/*

### [🔙](#tool-list)[gtfobins.github.io](https://gtfobins.github.io/)

GTFOBins (short for "Get The F* Out Binaries") is a collection of Unix binaries that can be used to escalate privileges, bypass restrictions, or execute arbitrary commands on a system.

They can be used by threat actors to gain unauthorized access to systems and carry out malicious activities.

The GTFOBins project is a list of Unix binaries with command and usage information for attackers. This information can be used to implement unix detections.

Visit [https://gtfobins.github.io/](https://gtfobins.github.io/).

**Usage:** 

Here are some project links to get started:

- [base64](https://gtfobins.github.io/gtfobins/base64/)
- [curl](https://gtfobins.github.io/gtfobins/curl/)
- [nano](https://gtfobins.github.io/gtfobins/nano/)

![image](https://user-images.githubusercontent.com/100603074/210625527-6a037b81-e3fe-4282-a193-1cc4b9c06f75.png)

*Image used from https://gtfobins.github.io/*

### [🔙](#tool-list)[filesec.io](https://filesec.io/)

Filesec is a list of file extensions that can be used by attackers for phishing, execution, macros etc.

This is a nice resource to understand the malicious use cases of common file extentions and ways that you can defend against them.

Each file extension page contains a description, related operating system and recommendations.

Visit [https://filesec.io/](https://filesec.io/).

**Usage:** 

Here are some project links to get started:

- [.Docm](https://filesec.io/docm)
- [.Iso](https://filesec.io/iso)
- [.Ppam](https://filesec.io/ppam)

![image](https://user-images.githubusercontent.com/100603074/210625626-58223992-2821-42c6-878a-e6aea4b9a508.png)

*Image used from https://filesec.io/*

### [🔙](#tool-list)[KQL Search](https://www.kqlsearch.com/)

KQL stands for "Kusto Query Language", and it is a query language used to search and filter data in Azure Monitor logs. It is similar to SQL, but is more optimized for log analytics and time-series data.

KQL query language is particularly useful for blue teamers because it allows you to quickly and easily search through large volumes of log data to identify security events and anomalies that may indicate a threat.

KQL Search is a web app created by [@ugurkocde](https://twitter.com/ugurkocde) that aggregates KQL queries that are shared on GitHub.

You can visit the site at [https://www.kqlsearch.com/](https://www.kqlsearch.com/).

More information about Kusto Query Language (KQL) can be found [here](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/).

![image](https://user-images.githubusercontent.com/100603074/210736862-1e0cf987-7c85-40c1-b51c-1f3a1f946f7d.png)

*Image used from https://www.kqlsearch.com/*

### [🔙](#tool-list)[Unprotect Project](https://unprotect.it/about/)

Malware authors spend a great deal of time and effort to develop complex code to perform malicious actions against a target system. It is crucial for malware to remain undetected and avoid sandbox analysis, antiviruses or malware analysts. 

With this kind of technics, malware are able to pass under the radar and stay undetected on a system. The goal of this free database is to centralize the information about malware evasion techniques.

The project aims to provide Malware Analysts and Defenders with actionable insights and detection capabilities to shorten their response times.

The project can be found at [https://unprotect.it/](https://unprotect.it/).

The project has an API - Docs [here](https://unprotect.it/api/).

![image](https://user-images.githubusercontent.com/100603074/210743650-6adaddce-ecb3-41bb-854b-292482b73d55.png)

*Image used from https://unprotect.it/map/*

### [🔙](#tool-list)[chainsaw](https://github.com/WithSecureLabs/chainsaw)

Chainsaw provides a powerful ‘first-response’ capability to quickly identify threats within Windows forensic artefacts such as Event Logs and MFTs. Chainsaw offers a generic and fast method of searching through event logs for keywords, and by identifying threats using built-in support for Sigma detection rules, and via custom Chainsaw detection rules.

Features:

- Hunt for threats using Sigma detection rules and custom Chainsaw detection rules
- Search and extract forensic artefacts by string matching, and regex patterns
- Lightning fast, written in rust, wrapping the EVTX parser library by @OBenamram
- Clean and lightweight execution and output formats without unnecessary bloat
- Document tagging (detection logic matching) provided by the TAU Engine Library
- Output results in a variety of formats, such as ASCII table format, CSV format, and JSON format
- Can be run on MacOS, Linux and Windows

**Install:** 

```bash
git clone https://github.com/countercept/chainsaw.git
cargo build --release
git clone https://github.com/SigmaHQ/sigma
git clone https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git
```

**Usage:** 

```bash
./chainsaw hunt EVTX-ATTACK-SAMPLES/ -s sigma/ --mapping mappings/sigma-event-logs-all.yml
```

![image](https://user-images.githubusercontent.com/100603074/217382675-1834c13d-1789-4ea7-a46e-25808477bcf0.png)

*Image used from https://twitter.com/FranticTyping/status/1433386064429916162/*

### [🔙](#tool-list)[freq](https://github.com/MarkBaggett/freq)

Adversaries attempt to bypass signature based/pattern matching/blacklist techniques by introducing random: filenames, service names, workstation names, domains, hostnames, SSL cert subjects and issuer subjects, etc.

Freq is a python API designed by Mark Baggett to handle mass entropy testing. It was designed to be used in conjunction with a SIEM solutions but can work with anything that can submit a web request.

The tool uses frequency tables that map how likely one character will follow another

**Install:** 

```bash
git clone https://github.com/MarkBaggett/freq
cd freq
```

**Usage:** 

```bash
# Running freq_server.py on port 10004 and using a frequency table of /opt/freq/dns.freq
/usr/bin/python /opt/freq/freq_server.py 10004 /opt/freq/dns.freq
```

### [🔙](#tool-list)[yarGen](https://github.com/Neo23x0/yarGen)

yarGen is a generator for YARA rules

The main principle is the creation of yara rules from strings found in malware files while removing all strings that also appear in goodware files. Therefore yarGen includes a big goodware strings and opcode database as ZIP archives that have to be extracted before the first use.

The rule generation process also tries to identify similarities between the files that get analyzed and then combines the strings to so called super rules. The super rule generation does not remove the simple rule for the files that have been combined in a single super rule. This means that there is some redundancy when super rules are created. You can suppress a simple rule for a file that was already covered by super rule by using --nosimple.

**Install:** 

Download the latest [release](https://github.com/Neo23x0/yarGen/releases).

```bash
pip install -r requirements.txt
python yarGen.py --update
```

**Usage:** 

```bash
# Create a new strings and opcodes database from an Office 2013 program directory
yarGen.py -c --opcodes -i office -g /opt/packs/office2013

# Update the once created databases with the "-u" parameter
yarGen.py -u --opcodes -i office -g /opt/packs/office365
```

Usage examples can be found [here](https://github.com/Neo23x0/yarGen#examples).

![image](https://user-images.githubusercontent.com/100603074/218200487-8476950d-c63e-4d5a-a03c-f2969b6001cc.png)

*Image used from https://github.com/Neo23x0/yarGen*

### [🔙](#tool-list)[EmailAnalyzer](https://github.com/keraattin/EmailAnalyzer)

With EmailAnalyzer you can able to analyze your suspicious emails. You can extract headers, links and hashes from the .eml file

**Install:** 

```bash
git clone https://github.com/keraattin/EmailAnalyzer
cd EmailAnalyzer
```

**Usage:** 

```bash
# View headers in eml file
python3 email-analyzer.py -f <eml file> --headers

# Get hashes 
python3 email-analyzer.py -f <eml file> --digests

# Get links
python3 email-analyzer.py -f <eml file> --links

# Get attachments
python3 email-analyzer.py -f <eml file> --attachments
```

![image](https://user-images.githubusercontent.com/100603074/218200574-d9917b8c-433b-4bab-8db0-b6628b0d9424.png)

*Text used from https://github.com/keraattin/EmailAnalyzer*

### [🔙](#tool-list)[VCG](https://github.com/nccgroup/VCG)

VCG is an automated code security review tool that handles C/C++, Java, C#, VB and PL/SQL. It has a few features that should hopefully make it useful to anyone conducting code security reviews, particularly where time is at a premium:

- In addition to performing some more complex checks it also has a config file for each language that basically allows you to add any bad functions (or other text) that you want to search for
- It attempts to find a range of around 20 phrases within comments that can indicate broken code (“ToDo”, “FixMe”, “Kludge”, etc.)
- It provides a nice pie chart (for the entire codebase and for individual files) showing relative proportions of code, whitespace, comments, ‘ToDo’ style comments and bad code

**Install:** 

You can install the pre-compiled binary here.

Open the project .sln, choose "Release", and build.

**Usage:** 

```
STARTUP OPTIONS:
	(Set desired starting point for GUI. If using console mode these options will set target(s) to be scanned.)
	-t, --target <Filename|DirectoryName>:	Set target file or directory. Use this option either to load target immediately into GUI or to provide the target for console mode.
	-l, --language <CPP|PLSQL|JAVA|CS|VB|PHP|COBOL>:	Set target language (Default is C/C++).
	-e, --extensions <ext1|ext2|ext3>:	Set file extensions to be analysed (See ReadMe or Options screen for language-specific defaults).
	-i, --import <Filename>:	Import XML/CSV results to GUI.

OUTPUT OPTIONS:
	(Automagically export results to a file in the specified format. Use XML or CSV output if you wish to reload results into the GUI later on.)
	-x, --export <Filename>:	Automatically export results to XML file.
	-f, --csv-export <Filename>:	Automatically export results to CSV file.
	-r, --results <Filename>:	Automatically export results to flat text file.

CONSOLE OPTIONS:
	-c, --console:		Run application in console only (hide GUI).
	-v, --verbose:		Set console output to verbose mode.
	-h, --help:		Show help.
```

### [🔙](#tool-list)[CyberChef](https://gchq.github.io/CyberChef/)

CyberChef is a free, web-based tool that allows users to manipulate and transform data using a wide range of techniques.

With CyberChef, you can perform a wide range of operations on data, such as converting between different data formats (e.g., hexadecimal, base64, ASCII), encoding and decoding data, searching and replacing text etc.

The tool also includes a recipe system, which allows you to save and share data manipulation workflows with others.

The tool can be used from [here](https://gchq.github.io/CyberChef/).

![image](https://user-images.githubusercontent.com/100603074/223865168-433fcd56-12e9-44a2-83aa-1531d711383d.png)

*Image used from https://gchq.github.io/CyberChef/*

Threat Intelligence
====================

*Tools for gathering and analyzing intelligence about current and emerging threats, and for generating alerts about potential threats.*

### [🔙](#tool-list)[Maltego](https://www.maltego.com/solutions/cyber-threat-intelligence/)

Maltego is a commercial threat intelligence and forensics tool developed by Paterva. It is used by security professionals to gather and analyze information about domains, IP addresses, networks, and individuals in order to identify relationships and connections that might not be immediately apparent.

Maltego uses a visual interface to represent data as entities, which can be linked together to form a network of relationships. It includes a range of transforms, which are scripts that can be used to gather data from various sources, such as social media, DNS records, and WHOIS data.

Maltego is often used in conjunction with other security tools, such as SIEMs and vulnerability scanners, as part of a comprehensive threat intelligence and incident response strategy.

You can schedule a demo [here](https://www.maltego.com/get-a-demo/).

[Maltego handbook Handbook for Cyber Threat Intelligence](https://static.maltego.com/cdn/Handbooks/Maltego-Handbook-for-Cyber-Threat-Intelligence.pdf)

![image](https://user-images.githubusercontent.com/100603074/210655712-e1409206-de1d-4601-88a5-f5a6ac3928c7.png)

*Image used from https://www.maltego.com/reduce-your-cyber-security-risk-with-maltego/*

### [🔙](#tool-list)[MISP](https://www.misp-project.org/)

MISP (short for Malware Information Sharing Platform) is an open-source platform for sharing, storing, and correlating Indicators of Compromise (IOCs) of targeted attacks, threats, and malicious activity.

MISP includes a range of features, such as real-time sharing of IOCs, support for multiple formats, and the ability to import and export data to and from other tools. 

It also provides a RESTful API and various data models to facilitate the integration of MISP with other security systems. In addition to its use as a threat intelligence platform, MISP is also used for incident response, forensic analysis, and malware research.

**Install:** 

```bash
# Kali
wget -O /tmp/misp-kali.sh https://raw.githubusercontent.com/MISP/MISP/2.4/INSTALL/INSTALL.sh && bash /tmp/misp-kali.sh

# Ubuntu 20.04.2.0-server
wget -O /tmp/INSTALL.sh https://raw.githubusercontent.com/MISP/MISP/2.4/INSTALL/INSTALL.sh
bash /tmp/INSTALL.sh
```

Full installation instructions can be found [here](https://misp.github.io/MISP/).

**Usage:** 

MISP documentation can be found [here](https://www.misp-project.org/documentation/).

[MISP user guide](https://github.com/MISP/misp-book)

[MISP Training Cheat sheet](https://www.misp-project.org/misp-training/cheatsheet.pdf)

![image](https://user-images.githubusercontent.com/100603074/210655743-b7fd5ab0-a106-4277-815d-c674525a9a91.png)

*Image used from http://www.concordia-h2020.eu/blog-post/integration-of-misp-into-flowmon-ads/*

### [🔙](#tool-list)[ThreatConnect](https://threatconnect.com/threat-intelligence-platform/)

ThreatConnect is a threat intelligence platform that helps organizations aggregate, analyze, and act on threat data. It is designed to provide a single, unified view of an organization's threat landscape and enable users to collaborate and share information about threats.

The platform includes a range of features for collecting, analyzing, and disseminating threat intelligence, such as a customizable dashboard, integration with third-party data sources, and the ability to create custom reports and alerts.

It is intended to help organizations improve their security posture by providing them with the information they need to identify, prioritize, and respond to potential threats.

You can request a demo from [here](https://threatconnect.com/request-a-demo/).

[ThreatConnect for Threat Intel Analysts - PDF](https://threatconnect.com/wp-content/uploads/2022/12/Intel-Analysts-Datasheet.pdf)

![image](https://user-images.githubusercontent.com/100603074/210655770-4413ead0-6216-47fe-a933-cbe0be9f86a1.png)

*Image used from https://threatconnect.com/threat-intelligence-platform/*

### [🔙](#tool-list)[Adversary Emulation Library](https://github.com/center-for-threat-informed-defense/adversary_emulation_library)

This is a library of adversary emulation plans to enable you to evaluate your defensive capabilities against real-world threats.

Emulation plans are an essential component for organizations looking to prioritize defenses against behavior from specific threats.

The TTPs outlined in this resource can be used to design specific threat emulation activities to test your organisations defenses against specific threat actors.

Visit the resource [here](https://github.com/center-for-threat-informed-defense/adversary_emulation_library).

**Example (sandworm)**

- [Sandworm Emulated Software Source Code](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/tree/master/sandworm/Resources)
- [Sandworm Detection Scenario Walkthrough](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/tree/master/sandworm/Emulation_Plan/Scenario_1)
- [Sandworm Intelligence Summary](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/blob/master/sandworm/Intelligence_Summary/Intelligence_Summary.md)

![image](https://user-images.githubusercontent.com/100603074/223865356-c4d491c3-edba-40d6-80b2-5c41029bddfd.png)

*Image used from https://github.com/center-for-threat-informed-defense/adversary_emulation_library*

Incident Response Planning
====================

*Tools for creating and maintaining an incident response plan, including templates and best practices for responding to different types of incidents.*

### [🔙](#tool-list)[NIST](https://www.nist.gov/cyberframework)

The NIST Cybersecurity Framework (CSF) is a framework developed by the National Institute of Standards and Technology (NIST) to help organizations manage cybersecurity risks. It provides a set of guidelines, best practices, and standards for implementing and maintaining a robust cybersecurity program.

The framework is organized around five core functions: Identify, Protect, Detect, Respond, and Recover. These functions provide a structure for understanding and addressing the various components of cybersecurity risk.

The CSF is designed to be flexible and adaptable, and it can be customized to fit the specific needs and goals of an organization. It is intended to be used as a tool for improving an organization's cybersecurity posture and for helping organizations better understand and manage their cybersecurity risks.

**Useful Links:** 

[NIST Quickstart Guide](https://csrc.nist.gov/Projects/cybersecurity-framework/nist-cybersecurity-framework-a-quick-start-guide)

[Framework for Improving Critical Infrastructure Cybersecurity](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.04162018.pdf)

[Data Breach Response: A Guide for Business](https://www.ftc.gov/business-guidance/resources/data-breach-response-guide-business)

[NIST Events and Presentations](https://www.nist.gov/cyberframework/events-and-presentations)

[Twitter - @NISTcyber](https://www.twitter.com/NISTcyber)

![image](https://user-images.githubusercontent.com/100603074/210655795-f809707f-fb3e-4df9-b07d-c4fa0392f020.png)

*Image used from https://www.dell.com/en-us/blog/strengthen-security-of-your-data-center-with-the-nist-cybersecurity-framework/*

### [🔙](#tool-list)Incident Response Plan

An incident response plan is a set of procedures that a company puts in place to manage and mitigate the impact of a security incident, such as a data breach or a cyber attack. 

The theory behind an incident response plan is that it helps a company to be prepared for and respond effectively to a security incident, which can minimize the damage and reduce the chances of it happening again in the future.

There are several reasons why businesses need an incident response plan:

1. **To minimize the impact of a security incident:** An incident response plan helps a company to identify and address the source of a security incident as quickly as possible, which can help to minimize the damage and reduce the chances of it spreading.

2. **To meet regulatory requirements:** Many industries have regulations that require companies to have an incident response plan in place. For example, the Payment Card Industry Data Security Standard (PCI DSS) requires merchants and other organizations that accept credit cards to have an incident response plan.

3. **To protect reputation:** A security incident can damage a company's reputation, which can lead to a loss of customers and revenue. An incident response plan can help a company to manage the situation and minimize the damage to its reputation.

4. **To reduce the cost of a security incident:** The cost of a security incident can be significant, including the cost of remediation, legal fees, and lost business. An incident response plan can help a company to minimize these costs by providing a roadmap for responding to the incident.

**Useful Links:**

[National Cyber Security Centre - Incident Response overview](https://www.ncsc.gov.uk/collection/incident-management/incident-response)

[SANS - Security Policy Templates](https://www.sans.org/information-security-policy/)

[SANS - Incident Handler's Handbook](https://www.sans.org/white-papers/33901/)

[FRSecure - Incident Response Plan Template](https://frsecure.com/incident-response-plan-template/)

[Cybersecurity and Infrastructure Security Agency - CYBER INCIDENT RESPONSE](https://www.cisa.gov/cyber-incident-response)

[FBI - Incident Response Policy](https://www.fbi.gov/file-repository/incident-response-policy.pdf/view)

![image](https://user-images.githubusercontent.com/100603074/210656422-d75791ae-797b-4135-bbd5-8b84335892ba.png)

*Image used from https://www.ncsc.gov.uk/collection/incident-management/incident-response*

### [🔙](#tool-list)Ransomware Response Plan

Ransomware is a type of malicious software that encrypts a victim's files. The attackers then demand a ransom from the victim to restore access to the files; hence the name ransomware.

The theory behind a ransomware response plan is that it helps a company to be prepared for and respond effectively to a ransomware attack, which can minimize the impact of the attack and reduce the chances of it happening again in the future.

There are several reasons why businesses need a ransomware response plan:

1. **To minimize the impact of a ransomware attack:** A ransomware response plan helps a company to identify and address a ransomware attack as quickly as possible, which can help to minimize the damage and reduce the chances of the ransomware spreading to other systems.

2. **To protect against data loss:** Ransomware attacks can result in the loss of important data, which can be costly and disruptive for a business. A ransomware response plan can help a company to recover from an attack and avoid data loss.

3. **To protect reputation:** A ransomware attack can damage a company's reputation, which can lead to a loss of customers and revenue. A ransomware response plan can help a company to manage the situation and minimize the damage to its reputation.

4. **To reduce the cost of a ransomware attack:** The cost of a ransomware attack can be significant, including the cost of remediation, legal fees, and lost business. A ransomware response plan can help a company to minimize these costs by providing a roadmap for responding to the attack.

**Useful Links:**

[National Cyber Security Centre - Mitigating malware and ransomware attacks](https://www.ncsc.gov.uk/guidance/mitigating-malware-and-ransomware-attacks)

[NIST - Ransomware Protection and Response](https://csrc.nist.gov/Projects/ransomware-protection-and-response)

[Cybersecurity and Infrastructure Security Agency - Ransomware Guide](https://www.cisa.gov/stopransomware/ransomware-guide)

[Microsoft Security - Ransomware response](https://www.microsoft.com/en-us/security/blog/2019/12/16/ransomware-response-to-pay-or-not-to-pay/)

[Blog - Creating a Ransomware Response Plan](https://www.msp360.com/resources/blog/designing-a-ransomware-response-plan/)

![image](https://user-images.githubusercontent.com/100603074/210655863-d4044516-022a-4f6b-afaa-cf375c1f01b4.png)

*Image used from https://csrc.nist.gov/Projects/ransomware-protection-and-response*

### [🔙](#tool-list)[Incident Response Reference Guide](https://info.microsoft.com/rs/157-GQE-382/images/EN-US-CNTNT-emergency-doc-digital.pdf)

This is a “first aid” style of guidance for cybersecurity to help you prepare for a crisis and limit the potential damage in a crisis.

This includes tips and guidance for technical, operational, legal, and communications aspects of a major cybersecurity incident. 

**Key Takeaways**

- **Preparation pays off** – Preparing for a major incident can reduce damage to the organization, as well as reduce incident cost and management difficulty.
- **Operationalize your incident management processes** – Managing major cybersecurity incidents must be part of standard business risk management processes.
- **Coordination is critical** – Effective cybersecurity incident management requires collaboration and coordination of technical, operations, communications, legal, and governance functions.
- **Stay calm and do no harm in an incident** – Overreacting can be as damaging as underreacting.

You can read the paper [here](https://info.microsoft.com/rs/157-GQE-382/images/EN-US-CNTNT-emergency-doc-digital.pdf).

![image](https://user-images.githubusercontent.com/100603074/223865803-a026ad87-00dd-4458-bf17-416a091566dd.png)

*Image used from https://info.microsoft.com/rs/157-GQE-382/images/EN-US-CNTNT-emergency-doc-digital.pdf*

### [🔙](#tool-list)[Awesome Incident Response](https://github.com/meirwah/awesome-incident-response)

A curated list of tools and resources for security incident response, aimed to help security analysts and [DFIR](https://www.acronymfinder.com/Digital-Forensics%2c-Incident-Response-%28DFIR%29.html) teams.

This is a great resource full of links for different aspects of incident response, including:

- Adversary Emulation
- All-In-One Tools
- Books
- Communities
- Disk Image Creation Tools

Visit the resource [here](https://github.com/meirwah/awesome-incident-response).

![image](https://user-images.githubusercontent.com/100603074/223865479-b54a2f98-0c2c-4bf1-8072-58ea7bfe4fb0.png)

*Image used from https://github.com/meirwah/awesome-incident-response*

Malware Detection and Analysis
====================

*Tools for detecting and analyzing malware, including antivirus software and forensic analysis tools.*

### [🔙](#tool-list)[VirusTotal](https://www.virustotal.com/gui/home/search)

VirusTotal is a website and cloud-based tool that analyzes and scans files, URLs, and software for viruses, worms, and other types of malware.

When a file, URL, or software is submitted to VirusTotal, the tool uses various antivirus engines and other tools to scan and analyze it for malware. It then provides a report with the results of the analysis, which can help security professionals and blue teams identify and respond to potential threats. 

VirusTotal can also be used to check the reputation of a file or URL, and to monitor for malicious activity on a network.

Visit [https://www.virustotal.com/gui/home/search](https://www.virustotal.com/gui/home/search)

**Usage:** 

```bash
# Recently created documents with macros embedded, detected at least by 5 AVs
(type:doc OR type: docx) tag:macros p:5+ generated:30d+

# Excel files bundled with powershell scripts and uploaded to VT for the last 10
days
(type:xls OR type:xlsx) tag:powershell fs:10d+

# Follina-like exploit payloads
entity:file magic:"HTML document text" tag:powershell have:itw_url

# URLs related to specified parent domain/subdomain with a specific header in
the response
entity:url header_value:"Apache/2.4.41 (Ubuntu)" parent_domain:domain.org

# Suspicious URLs with a specific HTML title
entity:url ( title:"XY Company" or title:"X.Y. Company" or title:"XYCompany" ) p:5+
```

Full documentation can be found [here](https://support.virustotal.com/hc/en-us/categories/360000162878-Documentation).

[VT INTELLIGENCE CHEAT SHEET](https://storage.googleapis.com/vtpublic/reports/VTI%20Cheatsheet.pdf)

![image](https://user-images.githubusercontent.com/100603074/210655958-9a39783e-637e-46a3-a80c-4c64b389de60.png)

*Image used from https://www.virustotal.com/gui/home/search*

### [🔙](#tool-list)[IDA](https://hex-rays.com/ida-free/)

IDA (Interactive Disassembler) is a powerful tool used to reverse engineer and analyze compiled and executable code. 

It can be used to examine the inner workings of software, including malware, and to understand how it functions. IDA allows users to disassemble code, decompile it into a higher-level programming language, and view and edit the resulting source code. This can be useful for identifying vulnerabilities, analyzing malware, and understanding how a program works. 

IDA can also be used to generate graphs and charts that visualize the structure and flow of code, which can make it easier to understand and analyze.

**Install:** 

Download IDA from [here](https://hex-rays.com/ida-free/#download).

**Usage:** 

[IDA Practical Cheatsheet](https://github.com/AdamTaguirov/IDA-practical-cheatsheet)

[IDAPython cheatsheet](https://gist.github.com/icecr4ck/7a7af3277787c794c66965517199fc9c)

[IDA Pro Cheatsheet](https://hex-rays.com/products/ida/support/freefiles/IDA_Pro_Shortcuts.pdf)

![image](https://user-images.githubusercontent.com/100603074/210655977-e52a66eb-7698-4769-b002-a9d6f1503b85.png)

*Image used from https://www.newton.com.tw/wiki/IDA%20Pro*

### [🔙](#tool-list)[Ghidra](https://ghidra-sre.org/)

Ghidra is a free, open-source software reverse engineering tool developed by the National Security Agency (NSA). It is used to analyze compiled and executable code, including malware. 

Ghidra allows users to disassemble code, decompile it into a higher-level programming language, and view and edit the resulting source code. This can be useful for identifying vulnerabilities, analyzing malware, and understanding how a program works. 

Ghidra also includes a range of features and tools that support SRE tasks, such as debugging, code graphing, and data visualization. Ghidra is written in Java and is available for Windows, MacOS, and Linux.

**Install:** 

1. Download the latest release from [here](https://github.com/NationalSecurityAgency/ghidra/releases).
2. Extract the zip

Full installation and error fix information can be found [here](https://ghidra-sre.org/InstallationGuide.html#Install).

**Usage:** 

1. Navigate to the unzipped folder

```bash
# Windows
ghidraRun.bat

# Linux
./ghidraRun
```

If Ghidra failed to launch, see the [Troubleshooting](https://ghidra-sre.org/InstallationGuide.html#Troubleshooting) link.

![image](https://user-images.githubusercontent.com/100603074/210656000-9b31d5fc-7b95-447e-94ed-94aef602de46.png)

*Image used from https://www.malwaretech.com/2019/03/video-first-look-at-ghidra-nsa-reverse-engineering-tool.html*


### [🔙](#tool-list)[decode-vbe](https://github.com/DidierStevens/DidierStevensSuite/blob/master/decode-vbe.py)

Script Encoding was introduced by Microsoft (long ago) to prevent people from being able to read, understand and alter VBScript files. 

Encoded scripts are unreadable but still able to execute, making it a popular mechanism with threat actors looking to hide their malicious code, IOCs, hardcoded C2 domains etc whilst still being able to achieve execution.

The decode-vbe script can be used to convert encoded VBE files back to plaintext for analysis. 

Nice blog about VBE files [here](https://bromiley.medium.com/malware-monday-vbscript-and-vbe-files-292252c1a16).

**Install:** 

```bash
git clone https://github.com/DidierStevens/DidierStevensSuite/
cd DidierStevensSuite
```

**Usage:** 

```bash
# Decode literal string
decode-vbe.py "##@~^DgAAAA==\ko$K6,JCV^GJqAQAAA==^#~@"

# Decode hexadecimal (prefix #h#)
decode-vbe.py #h#23407E5E4467414141413D3D5C6B6F244B362C4A437F565E474A7141514141413D3D5E237E40

# Decode base64 (prefix #b#)
decode-vbe.py #b#I0B+XkRnQUFBQT09XGtvJEs2LEpDf1ZeR0pxQVFBQUE9PV4jfkA=
```

### [🔙](#tool-list)[pafish](https://github.com/a0rtega/pafish)

Pafish is a testing tool that uses different techniques to detect virtual machines and malware analysis environments in the same way that malware families do.

The project is free and open source; the code of all the anti-analysis techniques is publicly available. Pafish executables for Windows (x86 32-bit and 64-bit) can be downloaded from the [releases page](https://github.com/a0rtega/pafish/releases).

**Install: (Build)** 

Pafish is written in C and can be built with Mingw-w64 and make.

The wiki page "[How to build](https://github.com/a0rtega/pafish/wiki/How-to-build)" contains detailed instructions.

**Usage:** 

```bash
pafish.exe
```
![image](https://user-images.githubusercontent.com/100603074/218870623-4c149ec7-2002-42ea-9c24-0d35f562bb8c.png)

*Image used from https://github.com/a0rtega/pafish*

### [🔙](#tool-list)[lookyloo](https://github.com/Lookyloo/lookyloo)

Lookyloo is a web interface that captures a webpage and then displays a tree of the domains, that call each other.

Use Lookyloo to map the journey a website page takes - from entering the initial URL address to the various redirects to third-party affiliations. 

**Install:** 

```bash
git clone https://github.com/Lookyloo/lookyloo.git
cd lookyloo
poetry install
echo LOOKYLOO_HOME="'`pwd`'" > .env
```

Full installation instructions can be found [here](https://www.lookyloo.eu/docs/main/install-lookyloo.html).

**Usage:** 

Once installed and running, lookyloo can be operated via the web interface hosted locally.

![image](https://user-images.githubusercontent.com/100603074/218870701-24d0b7c1-50d9-4b7d-9b9d-b76c98b4e10f.png)

*Image used from https://www.lookyloo.eu/*

### [🔙](#tool-list)[YARA](https://github.com/virustotal/yara)

YARA is a tool aimed at (but not limited to) helping malware researchers to identify and classify malware samples. With YARA you can create descriptions of malware families (or whatever you want to describe) based on textual or binary patterns. 

Each description, a.k.a rule, consists of a set of strings and a boolean expression which determine its logic.

**Install:** 

```bash
tar -zxf yara-4.2.0.tar.gz
cd yara-4.2.0
./bootstrap.sh
sudo apt-get install automake libtool make gcc pkg-config
git clone https://github.com/VirusTotal/yara
cd yara
./bootstrap.sh
./configure
make
sudo make install
```

Full installation instructions can be found [here](https://yara.readthedocs.io/en/stable/gettingstarted.html#compiling-and-installing-yara).

**Usage:** 

```bash
# Apply rule in /foo/bar/rules to all files in the current directory
yara /foo/bar/rules  .

# Scan all files in the /foo directory and its subdirectories:
yara /foo/bar/rules -r /foo
```

Nice YARA cheatsheet [here](https://github.com/mattnotmax/DFIR-notes/blob/master/cheatsheet_yara.md).

![image](https://user-images.githubusercontent.com/100603074/218871209-da726de1-1563-40b4-857c-3234f7415fdb.png)

*Image used from https://virustotal.github.io/yara/*

### [🔙](#tool-list)[Cuckoo Sandbox](https://cuckoosandbox.org/)

Cuckoo is an open source automated malware analysis system.

It’s used to automatically run and analyze files and collect comprehensive analysis results that outline what the malware does while running inside an isolated operating system.

It can retrieve the following type of results:

- Traces of calls performed by all processes spawned by the malware.
- Files being created, deleted and downloaded by the malware during its execution.
- Memory dumps of the malware processes.
- Network traffic trace in PCAP format.
- Screenshots taken during the execution of the malware.
- Full memory dumps of the machines.

**Install:** 

For installation follow the docs [here](https://cuckoo.readthedocs.io/en/latest/installation/).

**Usage:** 

For usage follow the docs [here](https://cuckoo.readthedocs.io/en/latest/usage/).

### [🔙](#tool-list)[radare2](https://github.com/radareorg/radare2)

Radare2 provides a set of libraries, tools and plugins to ease reverse engineering tasks.

r2 is a featureful low-level command-line tool with support for scripting. r2 can edit files on local hard drives, view kernel memory, and debug programs locally or via a remote gdb server. r2's wide architecture support allows you to analyze, emulate, debug, modify, and disassemble any binary.

**Install:** 

```bash
git clone https://github.com/radareorg/radare2
radare2/sys/install.sh
```

**Usage:** 

```bash
$ r2 /bin/ls   # open the binary in read-only mode
> aaa          # same as r2 -A, analyse the binary
> afl          # list all functions (try aflt, aflm)
> px 32        # print 32 byte hexdump current block
> s sym.main   # seek to the given offset (by flag name, number, ..)
> f~foo        # filter flags with ~grep (same as |grep)
> iS;is        # list sections and symbols (same as rabin2 -Ss)
> pdf; agf     # print function and show control-flow-graph in ascii-art
> oo+;w hello  # reopen in rw mode and write a string in the current offset
> ?*~...       # interactive filter all command help messages
> q            # quit
```

Great usage book [here](https://book.rada.re/).

![image](https://user-images.githubusercontent.com/100603074/218871325-90800880-ee58-4a61-9372-fa9cb09f6bf3.png)

*Image used from https://github.com/radareorg/radare2*

### [🔙](#tool-list)[dnSpy](https://github.com/dnSpy/dnSpy)

dnSpy is a debugger and .NET assembly editor. You can use it to edit and debug assemblies. 

Main features:

- Debug .NET and Unity assemblies
- Edit .NET and Unity assemblies

**Install: (Build)** 

```bash
git clone --recursive https://github.com/dnSpy/dnSpy.git
cd dnSpy
./build.ps1 -NoMsbuild
```

**Usage:** 

```bash
dnSpy.exe
```

Nice tutorial page [here](https://7d2dsdx.github.io/Tutorials/index.html?StartingdnSpy.html).

![image](https://user-images.githubusercontent.com/100603074/218871411-7eb20cb7-f2e8-4d29-98a9-d5820a138c8e.png)

*Image used from https://7d2dsdx.github.io/Tutorials/index.html?StartingdnSpy.html*

### [🔙](#tool-list)[malware-traffic-analysis.net](https://www.malware-traffic-analysis.net/)

This is a site with over 2,200 blog entries about malicious network traffic. Almost every post on the site has pcap files or malware samples (or both).

The site also contains a number of traffic analysis exercises, including technical blog posts outlining techniques being used by threat actors.

**Usage:** 

Visit [https://www.malware-traffic-analysis.net/](https://www.malware-traffic-analysis.net/).

![image](https://user-images.githubusercontent.com/100603074/218871486-f782e3f1-fcea-4e68-a99b-235146490b84.png)

*Image used from https://www.malware-traffic-analysis.net/*

Data Recovery
====================

*Tools for recovering data from damaged or corrupted systems and devices.*

### [🔙](#tool-list)[Recuva](https://www.ccleaner.com/recuva)

Recuva is a data recovery tool that can be used to recover deleted files from your computer. 

It is often used to recover deleted files that may contain valuable information, such as deleted logs or documents that could be used to investigate a security incident. 

Recuva can recover files from hard drives, USB drives, and memory cards, and it is available for Windows and Mac operating systems.

**Install:** 

You can download the tool from [here](https://www.ccleaner.com/recuva).

**Usage:** 

Nice step by step [guide](https://toolbox.iskysoft.com/data-recovery-tips/recuva-windows-10.html).

![image](https://user-images.githubusercontent.com/100603074/210668891-58312f55-d4d0-4f77-9cd6-f716bbdb5b44.png)

*Image used from https://www.softpedia.com/blog/recuva-explained-usage-video-and-download-503681.shtml*

### [🔙](#tool-list)[Extundelete](https://extundelete.sourceforge.net/)

Extundelete is a utility that can be used to recover deleted files from an ext3 or ext4 file system. 

It works by searching the file system for blocks of data that used to belong to a file, and then attempting to recreate the file using those blocks of data. It is often used to recover important files that have been accidentally or maliciously deleted. 

**Install:** 

You can download the tool from [here](https://sourceforge.net/project/platformdownload.php?group_id=260221).

**Usage:** 

```bash
# Prints information about the filesystem from the superblock.
--superblock

# Attemps to restore the file which was deleted at the given filename, called as "--restore-file dirname/filename".
--restore-file path/to/deleted/file

# Restores all files possible to undelete to their names before deletion, when possible. Other files are restored to a filename like "file.NNNN".
--restore-all
```

Full usage information can be found [here](https://extundelete.sourceforge.net/options.html).

![image](https://user-images.githubusercontent.com/100603074/210669234-0d2d4920-7856-4731-b81c-3d7132f752ad.png)

*Image used from https://theevilbit.blogspot.com/2013/01/backtrack-forensics-ext34-file-recovery.html*

### [🔙](#tool-list)[TestDisk](https://www.cgsecurity.org/wiki/TestDisk_Download)

TestDisk is a free and open-source data recovery software tool that is designed to help recover lost partitions and make non-booting disks bootable again. It is useful for both computer forensics and data recovery. 

It can be used to recover data that has been lost due to a variety of reasons, such as accidental deletion, formatting, or corruption of the partition table. 

TestDisk can also be used to repair damaged boot sectors, recover deleted partitions, and recover lost files. It supports a wide range of file systems, including FAT, NTFS, and ext2/3/4, and can be used to recover data from disks that are damaged or formatted with a different file system than the one they were originally created with.

**Install:** 

You can download the tool from [here](https://www.cgsecurity.org/wiki/TestDisk_Download).

**Usage:** 

Full usage examples [here](https://www.cgsecurity.org/wiki/Data_Recovery_Examples).

[Step by step guide](https://www.cgsecurity.org/wiki/TestDisk_Step_By_Step)

[TestDisk Documentation PDF - 60 Pages](https://www.cgsecurity.org/testdisk.pdf)

![image](https://user-images.githubusercontent.com/100603074/210668956-4ed75998-bd6d-48cf-a2e7-dfa75656eece.png)

*Image used from https://www.cgsecurity.org/wiki/*

Digital Forensics
====================

*Tools for conducting forensic investigations of digital devices and systems, including tools for collecting and analyzing evidence.*

### [🔙](#tool-list)[SANS SIFT](https://www.sans.org/tools/sift-workstation/)

SANS SIFT (SANS Investigative Forensic Toolkit) is a powerful toolkit for forensic analysis and incident response. 

It is a collection of open source and commercial tools that can be used to perform forensic analysis on a wide range of systems, including Windows, Linux, and Mac OS X. The SANS SIFT kit is designed to be run on a forensic workstation, which is a specialized computer that is used to perform forensic analysis on digital evidence.

The SANS SIFT kit is particularly useful for blue teamers, as it provides a wide range of tools and resources that can be used to investigate incidents, respond to threats, and perform forensic analysis on compromised systems.

**Install:** 

1. Visit [https://www.sans.org/tools/sift-workstation/](https://www.sans.org/tools/sift-workstation/).

2. Click the 'Login to Download' button and input (or create) your SANS Portal account credentials to download the virtual machine. 

3. Once you have booted the virtual machine, use the credentials below to gain access.

```
Login = sansforensics
Password = forensics
```

**Note:** *Use to elevate privileges to root while mounting disk images.*

Additional install options [here](https://www.sans.org/tools/sift-workstation/).

**Usage:** 

```bash
# Registry Parsing - Regripper
rip.pl -r <HIVEFILE> -f <HIVETYPE>

# Recover deleted registry keys
deleted.pl <HIVEFILE>

# Mount E01 Images
ewfmount image.E01 mountpoint
mount -o

# Stream Extraction
bulk_extractor <options> -o output_dir
```

Full usage guide [here](https://www.sans.org/posters/sift-cheat-sheet/).

![image](https://user-images.githubusercontent.com/100603074/210668984-bdec731b-ce80-4c3b-9696-9431dd77f9b0.png)

*Image used from https://securityboulevard.com/2020/08/how-to-install-sift-workstation-and-remnux-on-the-same-system-for-forensics-and-malware-analysis/*

### [🔙](#tool-list)[The Sleuth Kit](https://sleuthkit.org/sleuthkit/)

The Sleuth Kit is a collection of command line tools that can be used to analyze disk images and recover files from them. 

It is primarily used by forensic investigators to examine digital evidence after a computer has been seized or an image of a disk has been made. It can be useful because it can help understand what happened during a security incident and identify any malicious activity. 

The tools in The Sleuth Kit can be used to extract deleted files, analyze disk partition structures, and examine the file system for evidence of tampering or unusual activity.

**Install:** 

Download tool from [here](https://sleuthkit.org/sleuthkit/download.php).

**Usage:** 

Link to [documentation](https://sleuthkit.org/sleuthkit/docs.php).

![image](https://user-images.githubusercontent.com/100603074/210669006-6dfab59d-b50e-49db-b390-b9ef27cab6fe.png)

*Image used from http://www.effecthacking.com/2016/09/the-sleuth-kit-digital-forensic-tool.html*

### [🔙](#tool-list)[Autopsy](https://www.autopsy.com/)

Autopsy is a digital forensics platform and graphical interface to The Sleuth Kit and other digital forensics tools.

It is used by law enforcement, military, and corporate examiners to investigate what happened on a computer. You can use it to analyze disk images and recover files, as well as to identify system and user activity. 

Autopsy is used by "blue teams" (the cybersecurity professionals who defend organizations against attacks) to conduct forensic analysis and incident response. It can help blue teams understand the nature and scope of an attack, and identify any malicious activity that may have occurred on a computer or network.

**Install:** 

Download the tool from [here](https://www.autopsy.com/download/).

**Usage:** 

[Autopsy User Guide](http://sleuthkit.org/autopsy/docs/user-docs/4.19.3//)

[SANS - Introduction to using the AUTOPSY Forensic Browser](https://www.sans.org/blog/a-step-by-step-introduction-to-using-the-autopsy-forensic-browser/)

![image](https://user-images.githubusercontent.com/100603074/210669037-449e7790-85c8-4b8c-97b9-2b46a1ea6e61.png)

*Image used from https://www.kitploit.com/2014/01/autopsy-digital-investigation-analysis.html*

Security Awareness Training
====================

*Tools for training employees and other users on how to recognize and prevent potential security threats.*

### [🔙](#tool-list)[TryHackMe](https://tryhackme.com/dashboard)

TryHackMe is a platform that offers a variety of virtual machines, known as "rooms," which are designed to teach cybersecurity concepts and skills through hands-on learning. 

These rooms are interactive and gamified, allowing users to learn about topics such as web vulnerabilities, network security, and cryptography by solving challenges and completing tasks. 

The platform is often used for security awareness training, as it provides a safe and controlled environment for users to practice their skills and learn about different types of cyber threats and how to defend against them.

Visit [https://tryhackme.com/](https://tryhackme.com/) and create an account.

[TryHackMe - Getting Started Guide](https://docs.tryhackme.com/docs/teaching/teaching-getting-started/)

**Useful links:** 

[Pre-Security Learning Path](https://tryhackme.com/path-action/presecurity/join)

[introduction to Cyber Security Learning Path](https://tryhackme.com/path-action/introtocyber/join)

Visit the [hacktivities](https://tryhackme.com/hacktivities) tab for a full list of available rooms and modules.

![image](https://user-images.githubusercontent.com/100603074/210669062-dba079b7-a677-4b7a-ac99-6892ba894ac8.png)

*Image used from https://www.hostingadvice.com/blog/learn-cybersecurity-with-tryhackme/*

### [🔙](#tool-list)[HackTheBox](https://www.hackthebox.com/)

HackTheBox is a platform for practicing and improving your hacking skills. 

It consists of a set of challenges that simulate real-world scenarios and require you to use your knowledge of various hacking techniques to solve them. These challenges are designed to test your knowledge of topics such as network security, cryptography, web security, and more. 

HackTheBox is often used by security professionals as a way to practice and improve their skills, and it can also be a useful resource for security awareness training. By working through the challenges and learning how to solve them, individuals can gain a better understanding of how to identify and mitigate common security threats.

Visit [https://app.hackthebox.com/login](https://app.hackthebox.com/login) and create an account.

**Useful links:** 

[Blog - Introduction to Hack The Box](https://help.hackthebox.com/en/articles/5185158-introduction-to-hack-the-box)

[Blog - Learn to Hack with Hack The Box: The Beginner's Bible](https://www.hackthebox.com/blog/learn-to-hack-beginners-bible)

[Blog - Introduction to Starting Point](https://help.hackthebox.com/en/articles/6007919-introduction-to-starting-point)

![image](https://user-images.githubusercontent.com/100603074/210669087-d00d76d1-300f-48c9-8f7f-4b9b5157626e.png)

*Image used from https://www.hackthebox.com/login*

### [🔙](#tool-list)[PhishMe](https://cofense.com/product-services/phishme/)

PhishMe is a company that provides security awareness training to help organizations educate their employees about how to identify and prevent phishing attacks. 

PhishMe's training programs aim to teach employees how to recognize and report phishing attempts, as well as how to protect their personal and professional accounts from these types of attacks. 

The company's training programs can be customized to fit the needs of different organizations and can be delivered through a variety of mediums, including online courses, in-person training, and simulations.

Request a demo from [here](https://go.cofense.com/live-demo/).

**Useful links:** 

[Cofense Blog](https://cofense.com/blog/)

[Cofense Knowledge Center](https://cofense.com/knowledge-center-hub/)

![image](https://user-images.githubusercontent.com/100603074/210669120-1b29007a-f7f6-40f6-922b-9b5b251f6447.png)

*Image used from https://cofense.com/product-services/phishme/*

Communication and Collaboration
====================

Tools for coordinating and communicating with team members during an incident, including chat, email, and project management software.

### [🔙](#tool-list)[Twitter](https://twitter.com/)

Twitter is a great platform for sharing information about cyber security. 

It's a platform that is widely used by security professionals, researchers, and experts, giving you access to an endless amount of new information.

Some great accounts to follow:

- [@vxunderground](https://twitter.com/vxunderground)
- [@Alh4zr3d](https://twitter.com/Alh4zr3d)
- [@3xp0rtblog](https://twitter.com/3xp0rtblog)
- [@C5pider](https://twitter.com/C5pider)
- [@_JohnHammond](https://twitter.com/_JohnHammond)
- [@mrd0x](https://twitter.com/mrd0x)
- [@TheHackersNews](https://twitter.com/TheHackersNews)
- [@pancak3lullz](https://twitter.com/pancak3lullz)
- [@GossiTheDog](https://twitter.com/GossiTheDog)
- [@briankrebs](https://twitter.com/briankrebs)
- [@SwiftOnSecurity](https://twitter.com/SwiftOnSecurity)
- [@schneierblog](https://twitter.com/schneierblog)
- [@mikko](https://twitter.com/mikko)
- [@campuscodi](https://twitter.com/campuscodi)

### [🔙](#tool-list)[Facebook TheatExchange](https://developers.facebook.com/docs/threat-exchange/getting-started)

Facebook ThreatExchange is a platform for security professionals to share and analyze information about cyber threats. 

It was designed to help organizations better defend against threats by allowing them to share threat intelligence with each other in a private and secure way. 

It is intended to be used by "blue teams", who are responsible for the security of an organization and work to prevent, detect, and respond to cyber threats.

**Usage:**

To request access to ThreatExchange, you have to submit an application via [https://developers.facebook.com/products/threat-exchange/](https://developers.facebook.com/products/threat-exchange/).

**Useful links:** 

[Welcome to ThreatExchange!](https://developers.facebook.com/docs/threat-exchange/getting-started)

[ThreatExchange UI Overview](https://developers.facebook.com/docs/threat-exchange/ui)

[ThreatExchange API Reference](https://developers.facebook.com/docs/threat-exchange/reference/apis)

[GitHub - ThreatExchange](https://github.com/facebook/ThreatExchange/tree/main/python-threatexchange)
