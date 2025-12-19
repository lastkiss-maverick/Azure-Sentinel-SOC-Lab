
## Introduction
This project demonstrates the setup and implementation of a cloud-native **SIEM (Microsoft Sentinel)** to monitor security telemetry from an **Ubuntu Pro Virtual Machine**. Instead of standard Windows event monitoring, this lab focuses on **Linux Syslog ingestion**, using **KQL (Kusto Query Language)** to parse raw logs, and enriching data with a **Custom GeoIP Watchlist** to identify and visualize global brute-force attacks in real-time.

---

## Technical Architecture
* **Virtual Machine:** Ubuntu Pro 22.04 LTS (Acting as a "Honey-Pot")
* **SIEM:** Microsoft Sentinel
* **Log Management:** Azure Log Analytics Workspace
* **Telemetry Agent:** Azure Monitor Agent (AMA)
* **Data Enrichment:** Custom Watchlist (CSV mapping for Geolocation)
* **Automation:** Sentinel Analytics Rules for Incident Generation

---

## Architecture Diagram
<img width="502" height="832" alt="SIEM diagram  drawio" src="https://github.com/user-attachments/assets/8ddab00e-247b-48f1-b81c-8c7d8fd7a8a1" />

---

## Technologies & Protocols
* **KQL:** Developed advanced queries for data parsing and threat hunting.
* **Linux Syslog:** Specifically monitoring `auth` and `authpriv` facilities.
* **Regex:** Used to extract structured data from unstructured string messages.
* **Azure Monitor Agent (AMA):** Managed data collection rules for efficient telemetry.

---

## Lab Implementation Steps

### 1. Environment Deployment

* Deployed an **Ubuntu Pro VM** in Azure with a Public IP.
  <img width="1470" height="767" alt="Screenshot 2025-12-19 at 9 52 37 AM" src="https://github.com/user-attachments/assets/a1e245fe-18d8-4ca8-bc1d-caa3eec699df" />

* Configured a **Log Analytics Workspace (LAW)**.
  <img width="1209" height="766" alt="Screenshot 2025-12-19 at 9 53 41 AM" src="https://github.com/user-attachments/assets/390f3578-bd53-4f80-a2c7-3e5076cf91b2" />

* Enabled **Microsoft Sentinel** on the workspace to begin security operations.
  <img width="1213" height="762" alt="Screenshot 2025-12-19 at 9 54 38 AM" src="https://github.com/user-attachments/assets/73e31b2f-fa5e-42dc-9833-b0a0a10473b8" />


### 2. Linux Telemetry Configuration
I configured a **Data Collection Rule (DCR)** using the Azure Monitor Agent to capture authentication logs from the Ubuntu machine. This ensures that every SSH login attempt (successful or failed) is streamed into the `Syslog` table.
<img width="1212" height="760" alt="Screenshot 2025-12-19 at 9 56 44 AM" src="https://github.com/user-attachments/assets/bd80c9da-7c3d-4e7a-93f0-fe96b558f614" />


### 3. Data Engineering & KQL Parsing
Since Linux logs are stored in a single `SyslogMessage` string, I wrote custom KQL to extract the **Attacker IP** and the **Targeted Username**. This mimics the "Event ID 4625" structure found in Windows.
<img width="934" height="623" alt="Screenshot 2025-12-19 at 9 58 09 AM" src="https://github.com/user-attachments/assets/c8293f7b-0c05-488c-b25c-3f397aee5160" />


### 4. Custom Watchlist Enrichment
To move beyond basic logs, I integrated a GeoIP Watchlist. By performing a lookup join between the live logs and the watchlist, I enriched the alerts with **geographical data** (City, Country, Latitude, Longitude).

**Enrichment Query:**
let geoip_data = _GetWatchlist('geoip');
Syslog
| where SyslogMessage has "Failed password"
| extend Attacker_IP = extract("from ([0-9.]+)", 1, SyslogMessage)
| lookup kind=leftouter geoip_data on $left.Attacker_IP == $right.SearchKey
| project TimeGenerated, Attacker_IP, country, city, Latitude, Longitude
<img width="921" height="628" alt="Screenshot 2025-12-19 at 10 03 11 AM" src="https://github.com/user-attachments/assets/32e26982-2eed-4320-8cc4-b16950269311" />



### 5. Incident detection and automated the setup
I developed a Scheduled Analytics Rule that triggers a Security Incident if an IP address generates more than 5 failed login attempts in 5 minutes.
Entity Mapping: Configured AttackerIP and Computer (Host) as entities to allow for visual investigation.
<img width="1209" height="717" alt="Screenshot 2025-12-19 at 10 07 04 AM" src="https://github.com/user-attachments/assets/099094ad-7a28-470e-9a48-ff2887f01d79" />

Investigation: Utilized the Sentinel Investigation Graph to view the blast radius and connection between the attacker and the victim VM.
<img width="1215" height="727" alt="Screenshot 2025-12-19 at 10 07 45 AM" src="https://github.com/user-attachments/assets/1355e8dc-544f-4fb8-b501-953cb586a182" />



**KQL Query for Data Extraction:**
```kusto
Syslog
| where Facility == "auth" or Facility == "authpriv"
| where SyslogMessage has "Failed password"
| extend Attacker_User = extract("Failed password for (?:invalid user )?([^ ]+)", 1, SyslogMessage)
| extend Attacker_IP = extract("from ([0-9.]+)", 1, SyslogMessage)
| project TimeGenerated, Attacker_User, Attacker_IP, Computer, SyslogMessage
| sort by TimeGenerated desc
