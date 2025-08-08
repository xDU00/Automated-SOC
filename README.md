# Automated SOC with Open-Source Tools (Wazuh, VirusTotal, DFIR-IRIS, Shuffle)

![Architecture]([https://raw.githubusercontent.com/xDU00/blogstuff/refs/heads/main/archblog.png](https://raw.githubusercontent.com/xDU00/blogstuff/refs/heads/main/0_95jwPCsxkDj40Mgo.png))

A next-generation **Security Operations Center (SOC)** built with open-source tools: **Wazuh** (SIEM), **VirusTotal** (threat intelligence), **Shuffle** (SOAR), and **DFIR-IRIS** (incident management). This guide provides a step-by-step setup to automate threat detection, enrichment, and response, tested with a Mimikatz attack scenario.

[![Wazuh](https://img.shields.io/badge/Wazuh-v4.7.2-blue)](https://wazuh.com/)
[![VirusTotal](https://img.shields.io/badge/VirusTotal-API-green)](https://www.virustotal.com/)
[![Shuffle](https://img.shields.io/badge/Shuffle-SOAR-orange)](https://shuffler.io/)
[![DFIR-IRIS](https://img.shields.io/badge/DFIR--IRIS-Incident%20Management-purple)](https://docs.dfir-iris.org/)

## Table of Contents
- [Why Automate a SOC?](#why-automate-a-soc)
- [Prerequisites](#prerequisites)
- [Architecture](#architecture)
- [Setup and Configuration](#setup-and-configuration)
  - [Wazuh](#wazuh)
  - [DFIR-IRIS](#dfir-iris)
  - [Shuffle](#shuffle)
  - [VirusTotal Integration](#virustotal-integration)
- [Testing with Mimikatz](#testing-with-mimikatz)
- [Conclusion](#conclusion)
- [Resources](#resources)

## Why Automate a SOC?
Modern threats demand automation to:
- **Enhance Visibility**: Monitor endpoints, networks, and cloud in real-time.
- **Reduce Response Time**: Automate alert triage and escalation.
- **Improve Accuracy**: Enrich alerts with threat intelligence.
- **Ensure Compliance**: Centralized logs for GDPR, PCI DSS, etc.

## Prerequisites
- **VM Setup** (single or multiple):
  - OS: Ubuntu 20.04 LTS (Kernel 5.15+)
  - CPU: 6 cores
  - Memory: 32 GB
  - Storage: 466 GB
- **Tools**: Docker, Docker Compose
- **Test Environment**: Windows 10 and Ubuntu endpoints
- **APIs**: VirusTotal API key, IRIS API key

## Architecture
The SOC integrates:
- **Wazuh**: SIEM for threat detection
- **VirusTotal**: Threat intelligence for alert enrichment
- **Shuffle**: SOAR for automation
- **DFIR-IRIS**: Incident management and collaboration

![Architecture Diagram](https://raw.githubusercontent.com/xDU00/blogstuff/refs/heads/main/archblog.png)

## Setup and Configuration

### Wazuh
1. **Deploy Wazuh**:
   - Run services using Docker Compose.
   - Access the Wazuh dashboard at `https://<VM_IP>`.
   - ![Wazuh Dashboard](https://raw.githubusercontent.com/xDU00/blogstuff/refs/heads/main/Capture_dcran_2025-02-19_184816.png)

2. **Install Wazuh Agents**:
   - Select OS and input VM IP in the Wazuh dashboard.
   - Copy and run the agent deployment command.
   - ![Agent Deployment](https://raw.githubusercontent.com/xDU00/blogstuff/refs/heads/main/Screenshot%202025-06-01%20123426.png)
   - Verify agent status in the dashboard.

### DFIR-IRIS
1. **Deploy IRIS**:
   - Run services using Docker Compose.
   - Access the IRIS web interface at `https://<VM_IP>:8443`.
   - ![IRIS Setup](https://raw.githubusercontent.com/xDU00/blogstuff/refs/heads/main/Screenshot%202025-06-18%20005108.png)

2. **Integrate with Wazuh**:
   - Create and run the following script to configure integration:
     ```bash
     #!/bin/bash
     # integrate_wazuh_iris.sh
     echo "Enter IRIS API Key:"
     read IRIS_API_KEY
     echo "Enter IRIS URL (e.g., https://<VM_IP>:8443):"
     read IRIS_URL
     cat <<EOF >> /var/ossec/etc/ossec.conf
     <ossec_config>
       <integration>
         <name>iris</name>
         <api_key>$IRIS_API_KEY</api_key>
         <hook_url>$IRIS_URL/api/case</hook_url>
         <alert_format>json</alert_format>
       </integration>
     </ossec_config>
     EOF
     sudo docker-compose restart
     ```

     - Run the script:
     ```bash
     chmod +x integrate_wazuh_iris.sh
     ./integrate_wazuh_iris.sh
     ```
   


## Shuffle
   - Run the services:
   ![shuffle](https://raw.githubusercontent.com/xDU00/blogstuff/refs/heads/main/shuffleisntal.png)
   - Access the Shuffle web interface at `https://<VM_IP>:3443`.
### Integrate Shuffle with Wazuh
   - Create a script to configure webhook notifications:
     ```bash
     #!/bin/bash
     # File: integrate_shuffle_wazuh.sh
     echo "Enter Shuffle Hook URL (e.g., https://<VM_IP>:3443/hooks/wazuh):"
     read SHUFFLE_URL
     cat <<EOF >> /var/ossec/etc/ossec.conf
     <ossec_config>
       <integration>
         <name>shuffle</name>
         <hook_url>$SHUFFLE_URL</hook_url>
         <level>3</level>
         <alert_format>json</alert_format>
       </integration>
     </ossec_config>
     EOF
     sudo docker-compose restart
     ```
   - Run the script:
     ```bash
     chmod +x integrate_shuffle_wazuh.sh
     ./integrate_shuffle_wazuh.sh
     ```

## Integrate with IRIS and VirusTotal
   - In the Shuffle web interface, create a workflow:
     - **Trigger**: Configure a Wazuh webhook trigger (use the hook URL from above).
     - **Actions**:
       - Add a VirusTotal module to query file hashes (configure with your VirusTotal API key).
       - Add an IRIS module to create cases (configure with IRIS API key and URL).
   

### Test the SOC with a Mimikatz Attack Scenario
To validate the automated SOC, simulate a credential-dumping attack using Mimikatz, a common post-exploitation tool.

1. **Set Up Test Environment**:
   - Deploy a Windows 10 VM with the Wazuh agent installed.
   - Download Mimikatz from a trusted source (e.g., GitHub) for testing purposes only.
   - **Screenshot**:


2. **Configure Wazuh Detection Rules**:
   - Edit `/var/ossec/etc/rules/local_rules.xml` on the Wazuh Manager:
     ```xml
     <group name="mimikatz,">
       <rule id="100000" level="12">
         <if_group>sysmon_event1</if_group>
         <field name="win.eventdata.image">mimikatz.exe</field>
         <description>Mimikatz executable detected</description>
       </rule>
       <rule id="100001" level="12">
         <if_group>sysmon_event1</if_group>
         <field name="win.eventdata.targetObject">lsass.exe</field>
         <description>Suspicious access to LSASS process</description>
       </rule>
       <rule id="100002" level="12">
         <if_group>sysmon_event1</if_group>
         <field name="win.eventdata.callTrace">mimikatz</field>
         <description>Mimikatz-related call trace detected</description>
       </rule>
     </group>
     ```
   - Restart Wazuh services:
     ```bash
     sudo docker-compose restart
     ```
   - **Screenshot**:
     

3. **Run Mimikatz**:
   - Execute Mimikatz on the Windows 10 VM (e.g., `mimikatz.exe` in a test directory).
   - This triggers the Wazuh agent to detect suspicious activity.

4. **Verify Workflow**:

5. **Analyze Results**:
   - The workflow should complete in ~23 seconds, from detection to notification.
   - IRIS should log the incident with a timeline, evidence, and task assignments:
    

## Conclusion
This automated SOC leverages Wazuh, VirusTotal, Shuffle, and DFIR-IRIS to create a robust, scalable, and efficient cybersecurity framework. The Mimikatz test scenario demonstrates its ability to detect, enrich, and respond to threats in real-time, reducing manual effort and response times. By following this guide and including the provided screenshots, you can replicate this setup for your organization, enhancing your cybersecurity posture with open-source tools.

For further details, refer to the official documentation:
- [Wazuh](https://documentation.wazuh.com/current/)
- [VirusTotal](https://docs.virustotal.com/docs/how-it-works)
- [Shuffle](https://shuffler.io/)
- [DFIR-IRIS](https://docs.dfir-iris.org/latest/)

Happy hacking, and stay secure!

xDU0
