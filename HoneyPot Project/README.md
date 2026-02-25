# Honey Pot Report  

## What I Learned While Playing with Honeypots: A Day with T-Pot  

**Author:** Susana Noto  
**Date:** February 25, 2026  

---

## Figure 1  
*Full dashboard by T-Pot from my honeypot that was up for about 52 minutes.*

---

# 1. Executive Summary  

## The Objective  

During an informational interview, we discussed honeypots and their application in the cybersecurity workforce. Having never encountered one in my academic studies, I decided to deploy a simple honeypot using **T-Pot** and **Microsoft Azure**.

## Key Discovery  

Over a period of about **52 minutes**, my honeypot received:

- **659 hits**
- Averaging **12+ attacks per minute**
- Traffic from **at least 10 different countries**

Credential analysis also revealed repeated use of **“orangepi”** during brute-force attempts.

---

# 2. The Methodology  

## 2.1 Infrastructure & Environment  

To observe real-world attacker behavior, I deployed a high-interaction honeypot using the **T-Pot (Telekom Security)** ecosystem.

I followed this guide from CyberNow:

https://www.cybernoweducation.com/post/how-to-make-a-honeypot-in-30-minutes

The deployment involved:

- A **Microsoft Azure Virtual Machine**
- A **Network Security Group (NSG)**
- All inbound ports (0–65535) open to allow unrestricted traffic

---

## 2.2 The Monitoring Stack  

T-Pot utilizes the **ELK Stack** (Elasticsearch, Logstash, Kibana) to aggregate and visualize attack data.

The primary components deployed were:

- **Cowrie** – Captures SSH and Telnet interactions  
- **Honeytrap** – Acts as a wide-range “catch-all” listener  
- **Suricata** – Intrusion Detection System (IDS) for exploit signature detection  

---

# 3. Data Visualization & Global Analysis  

## 3.1 Geographic Origin of Attacks  

## Figure 2  
*Real-time geographic distribution of attack origins.*

Attacks originated globally, spanning nearly all continents.

Observations:

- Majority from **United States** and **Western Europe**
- Moderate activity from **Asia**
- Minimal activity from **Africa** and **Oceania**

This demonstrates how quickly internet-exposed infrastructure is discovered by automated scanners.

---

## 3.2 Attack Volume & Frequency  

## Figure 3  
*Distribution of activity across various honeypot services.*

With all ports exposed:

- **659 distinct attacks**
- Approximately **11–12 attacks per minute**
- Total runtime: ~52 minutes

This highlights the speed at which automated threat actors discover and probe internet-facing systems.

While this VM was intentionally empty, an insecure real-world deployment could have resulted in serious compromise.

---

# 4. The Investigation  

## 4.1 The "Orangepi" IoT Botnet Pattern  

## Figure 4  
*Common credentials attempted during brute-force sessions.*

During deployment, repeated login attempts used:

```text
username: orangepi
password: orangepi
```

Orange Pi manufactures single-board computers widely used in IoT devices.

Many devices ship with default credentials:

- Username: `orangepi`
- Password: `orangepi`
- Root password: `orangepi`

Attackers commonly scan the internet for exposed IoT devices and attempt default credentials to quickly compromise them for botnets.

---

## 4.2 Exploits and Signature Identification  

## Figure 5  
*IDS alerts identifying specific CVE exploitation attempts.*

Detected CVEs:

- **CVE-2002-0013** – SNMPv1 privilege escalation / DoS  
- **CVE-2002-0012** – SNMPv1 vulnerability  
- **CVE-1999-0517** – Default/null SNMP community names  
- **CVE-2019-11500** – Dovecot / Pigeonhole null-character processing issue  
- **CVE-2021-3449** – OpenSSL TLS ClientHello DoS vulnerability  
- **CVE-2024-14007** – Privilege escalation in NVMS-9000 firmware  

---

## 4.3 Ports Accessed  

## Figure 6  
*Ports accessed by attackers during honeypot deployment.*

Most commonly targeted ports:

- **443** – HTTPS  
- **2323** – Alternate Telnet  
- **8087** – Internal diagnostics/services  
- **8090** – Alternate HTTP  
- **8728** – MikroTik RouterOS API  

---

# 5. Lessons Learned & Defensive Strategy  

Based on observed data, the following security recommendations are critical:

### 1. Eliminate Default Credentials  
Immediately change default usernames and passwords on all devices, especially IoT systems.

### 2. Strict Port Management  
Only expose necessary ports. Close unused services.

### 3. Proactive Monitoring  
Continuously monitor:

- Network activity  
- Open ports  
- Authentication logs  

Investigate anomalies immediately and protect credential confidentiality.

---

# Final Reflection  

This experiment demonstrated how rapidly exposed systems are targeted by automated scanners and botnets. Even a short 52-minute window produced significant malicious traffic.

Honeypots provide valuable insight into real-world attacker behavior and reinforce fundamental cybersecurity principles:

- Least privilege  
- Defense in depth  
- Secure configuration  
