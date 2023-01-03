# BlueTeam-Tools

<p align="center">
<img src="https://user-images.githubusercontent.com/100603074/210274584-956a15fb-0431-46bd-a748-74b79b6ddab0.png" height="370">
</p>

This github repository contains a collection of **5+** **tools** and **resources** that can be useful for **blue teaming** and **incident response activities**. 

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
    <summary><b>Vulnerability Management</b> $\textcolor{gray}{\text{0 tools}}$</summary>
    <ul>
        <ul>
            <li><b><a href="#x">x</a></b><i> x</i></li>
        </ul>
    </ul>
</details>

<details open>
    <summary><b>Security Monitoring</b> $\textcolor{gray}{\text{0 tools}}$</summary>
    <ul>
        <ul>
            <li><b><a href="#x">x</a></b><i> x</i></li>
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

### [🔙](#tool-list)[]()

a

**Install:** 

```bash

```

**Usage:** 

```bash

```

Security Monitoring
====================

*Tools for collecting and analyzing security logs and other data sources to identify potential threats and anomalous activity.*

### [🔙](#tool-list)[]()

a

**Install:** 

```bash

```

**Usage:** 

```bash

```

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
