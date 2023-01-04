# BlueTeam-Tools

<p align="center">
<img src="https://user-images.githubusercontent.com/100603074/210630295-7b06d894-cea8-4ed7-9bd2-816b0d98d968.png" height="370">
</p>

This github repository contains a collection of **10+** **tools** and **resources** that can be useful for **blue teaming** and **incident response activities**. 

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
    <summary><b>Threat Intelligence</b> $\textcolor{gray}{\text{0 tools}}$</summary>
    <ul>
        <ul>
            <li><b><a href="#x">x</a></b><i> x</i></li>
        </ul>
    </ul>
</details>

<details open>
    <summary><b>Incident Response Planning</b> $\textcolor{gray}{\text{0 tools}}$</summary>
    <ul>
        <ul>
            <li><b><a href="#x">x</a></b><i> x</i></li>
        </ul>
    </ul>
</details>

<details open>
    <summary><b>Malware Detection and Analysis</b> $\textcolor{gray}{\text{0 tools}}$</summary>
    <ul>
        <ul>
            <li><b><a href="#x">x</a></b><i> x</i></li>
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

### [🔙](#tool-list)[]()

a

**Install:** 

```bash

```

**Usage:** 

```bash

```

Incident Response Planning
====================

*Tools for creating and maintaining an incident response plan, including templates and best practices for responding to different types of incidents.*

### [🔙](#tool-list)[]()

a

**Install:** 

```bash

```

**Usage:** 

```bash

```

Malware Detection and Analysis
====================

*Tools for detecting and analyzing malware, including antivirus software and forensic analysis tools.*

### [🔙](#tool-list)[]()

a

**Install:** 

```bash

```

**Usage:** 

```bash

```

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
