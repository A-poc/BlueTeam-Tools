# BlueTeam-Tools

<p align="center">
<img src="https://user-images.githubusercontent.com/100603074/210630295-7b06d894-cea8-4ed7-9bd2-816b0d98d968.png" height="370">
</p>

This github repository contains a collection of **20+** **tools** and **resources** that can be useful for **blue teaming** and **incident response activities**. 

Some of the tools may be specifically designed for blue teaming, while others are more general-purpose and can be adapted for use in a blue teaming context.

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
    <summary><b>Network Discovery and Mapping</b> $\textcolor{gray}{\text{6 tools}}$</summary>
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
    <summary><b>Vulnerability Management</b> $\textcolor{gray}{\text{3 tools}}$</summary>
    <ul>
        <ul>
            <li><b><a href="#openvas">OpenVAS</a></b><i> Open-source vulnerability scanner</i></li>
            <li><b><a href="#nessus-essentials">Nessus Essentials</a></b><i> Vulnerability scanner</i></li>
            <li><b><a href="#nexpose">Nexpose</a></b><i> Vulnerability management tool</i></li>
        </ul>
    </ul>
</details>

<details open>
    <summary><b>Security Monitoring</b> $\textcolor{gray}{\text{3 tools}}$</summary>
    <ul>
        <ul>
            <li><b><a href="#sysmon">Sysmon</a></b><i> System Monitor for Windows.</i></li>
            <li><b><a href="#kibana">Kibana</a></b><i> Data visualization and exploration.</i></li>
            <li><b><a href="#logstash">Logstash</a></b><i> Data collection and processing.</i></li>
        </ul>
    </ul>
</details>

<details open>
    <summary><b>Threat Tools and Techniques</b> $\textcolor{gray}{\text{3 tools}}$</summary>
    <ul>
        <ul>
            <li><b><a href="#lolbas-projectgithubio">lolbas-project.github.io</a></b><i> Living Off The Land Windows Binaries</i></li>
            <li><b><a href="#gtfobinsgithubio">gtfobins.github.io</a></b><i> Living Off The Land Linux Binaries</i></li>
            <li><b><a href="#filesecio">filesec.io</a></b><i> Attacker file extensions</i></li>
        </ul>
    </ul>
</details>

<details open>
    <summary><b>Threat Intelligence</b> $\textcolor{gray}{\text{3 tools}}$</summary>
    <ul>
        <ul>
            <li><b><a href="#maltego">Maltego</a></b><i> Threat Intelligence Platform</i></li>
            <li><b><a href="#misp">MISP</a></b><i> Malware Information Sharing Platform</i></li>
            <li><b><a href="#threatconnect">ThreatConnect</a></b><i> Threat data aggregation</i></li>
        </ul>
    </ul>
</details>

<details open>
    <summary><b>Incident Response Planning</b> $\textcolor{gray}{\text{3 tools}}$</summary>
    <ul>
        <ul>
            <li><b><a href="#nist">NIST</a></b><i> Cybersecurity Framework</i></li>
            <li><b><a href="#incident-response-plan">Incident Response Plan</a></b><i> Framework for incident response</i></li>
            <li><b><a href="#ransomware-response-plan">Ransomware Response Plan</a></b><i> Framework for ransomware response</i></li>
        </ul>
    </ul>
</details>

<details open>
    <summary><b>Malware Detection and Analysis</b> $\textcolor{gray}{\text{3 tools}}$</summary>
    <ul>
        <ul>
            <li><b><a href="#virustotal">VirusTotal</a></b><i> Malicious IOC Sharing Platform</i></li>
            <li><b><a href="#ida">IDA</a></b><i> Malware disassembler and debugger</i></li>
            <li><b><a href="#ghidra">Ghidra</a></b><i> Malware reverse engineering tool</i></li>
        </ul>
    </ul>
</details>

<details open>
    <summary><b>Data Recovery</b> $\textcolor{gray}{\text{0 tools}}$</summary>
    <ul>
        <ul>
            <li><b><a href="#x">x</a></b><i> x</i></li>
        </ul>
    </ul>
</details>

<details open>
    <summary><b>Digital Forensics</b> $\textcolor{gray}{\text{0 tools}}$</summary>
    <ul>
        <ul>
            <li><b><a href="#x">x</a></b><i> x</i></li>
        </ul>
    </ul>
</details>

<details open>
    <summary><b>Security Awareness Training</b> $\textcolor{gray}{\text{0 tools}}$</summary>
    <ul>
        <ul>
            <li><b><a href="#x">x</a></b><i> x</i></li>
        </ul>
    </ul>
</details>

<details open>
    <summary><b>Communication and Collaboration</b> $\textcolor{gray}{\text{0 tools}}$</summary>
    <ul>
        <ul>
            <li><b><a href="#x">x</a></b><i> x</i></li>
        </ul>
    </ul>
</details>

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

Threat Tools and Techniques
====================

*Tools for identifying and implementing detections against TTPs used by threat actors.*

### [🔙](#tool-list)[lolbas-project.github.io](https://lolbas-project.github.io/)

Living off the land binaries (LOLBins) are legitimate Windows executables that can be used by threat actors to carry out malicious activities without raising suspicion. 

Using LOLBins allows attackers to blend in with normal system activity and evade detection, making them a popular choice for malicious actors.

The LOLBAS project is a MITRE mapped list of LOLBINS with commands, usage and detection information for defenders.

**Install:** 

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

**Install:** 

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

**Install:** 

Visit [https://filesec.io/](https://filesec.io/).

**Usage:** 

Here are some project links to get started:

- [.Docm](https://filesec.io/docm)
- [.Iso](https://filesec.io/iso)
- [.Ppam](https://filesec.io/ppam)

![image](https://user-images.githubusercontent.com/100603074/210625626-58223992-2821-42c6-878a-e6aea4b9a508.png)

*Image used from https://filesec.io/*

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

Malware Detection and Analysis
====================

*Tools for detecting and analyzing malware, including antivirus software and forensic analysis tools.*

### [🔙](#tool-list)[VirusTotal](https://www.virustotal.com/gui/home/search)

VirusTotal is a website and cloud-based tool that analyzes and scans files, URLs, and software for viruses, worms, and other types of malware.

When a file, URL, or software is submitted to VirusTotal, the tool uses various antivirus engines and other tools to scan and analyze it for malware. It then provides a report with the results of the analysis, which can help security professionals and blue teams identify and respond to potential threats. 

VirusTotal can also be used to check the reputation of a file or URL, and to monitor for malicious activity on a network.

**Install:** 

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

Data Recovery
====================

*Tools for recovering data from damaged or corrupted systems and devices.*

### [🔙](#tool-list)[]()

a

**Install:** 

```bash

```

**Usage:** 

```bash

```

*Image used from *

Digital Forensics
====================

*Tools for conducting forensic investigations of digital devices and systems, including tools for collecting and analyzing evidence.*

### [🔙](#tool-list)[]()

a

**Install:** 

```bash

```

**Usage:** 

```bash

```


*Image used from *

Security Awareness Training
====================

*Tools for training employees and other users on how to recognize and prevent potential security threats.*

### [🔙](#tool-list)[]()

a

**Install:** 

```bash

```

**Usage:** 

```bash

```


*Image used from *

Communication and Collaboration
====================

Tools for coordinating and communicating with team members during an incident, including chat, email, and project management software.

### [🔙](#tool-list)[]()

a

**Install:** 

```bash

```

**Usage:** 

```bash

```


*Image used from *
