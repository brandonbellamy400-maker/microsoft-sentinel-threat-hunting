 # 🛡️ Microsoft Sentinel SIEM & Identity Threat Hunting Lab

## 🏢 Business Scenario: The Brute-Force Break-In
**Company Problem:** Global enterprise logistics provider *BrandonTech* noticed a massive surge in unauthorized sign-in attempts targeting standard corporate accounts. The IT department was completely blind to these credential-stuffing patterns because authentication data lived exclusively in raw identity dumps inside Microsoft Entra ID, completely detached from a security monitoring framework. 

**The Solution:** As a Security Engineer, I architected and deployed a cloud-native **SIEM (Security Information and Event Management)** pipeline using **Microsoft Sentinel**. By establishing a diagnostic data stream from the Identity Provider (IdP) to a central Log Analytics Workspace, I engineered custom **Kusto Query Language (KQL)** hunting queries to automatically isolate, aggregate, and surface brute-force attack signatures before an adversary could achieve initial access.

---

## 🛠️ Skills and Technologies Demonstrated
* **SIEM Management:** Microsoft Sentinel Workspace Deployment
* **Data Engineering:** Log Ingestion Pipelines & Entra ID Connectors
* **Threat Hunting:** Advanced Data Analysis using Kusto Query Language (KQL)
* **Incident Response:** Authentication Error Mapping (`ResultType 50126`)

---

## 🚀 Step-by-Step Lab Walkthrough

### Phase 1: Environment & Sandbox Architecture
To ensure zero impact on production assets, I initialized a dedicated Azure sandbox directory. I provisioned enterprise user identities—including a target test profile for `Alice Smith` (`asmith`)—to replicate a standard corporate directory framework exposed to public internet endpoints.

<img width="1920" height="1200" alt="Screenshot 2026-05-23 154737" src="https://github.com/user-attachments/assets/98c91373-09f4-4a7c-85eb-f40522179b90" />

---

### Phase 2: Deploying the SIEM Log Pipeline
I established a centralized Log Analytics Workspace named `law-sentinel-core` to serve as the structural data retention vault and initialized Microsoft Sentinel on top of the workspace engine.

<img width="1920" height="1200" alt="Screenshot 2026-05-23 160244" src="https://github.com/user-attachments/assets/c055e765-3b6b-4b60-b0b2-630d2d73772d" />

Next, I opened the Microsoft Sentinel configuration console to map data flows from our primary tenant directory assets.

<img width="1920" height="1200" alt="Screenshot 2026-05-23 160436" src="https://github.com/user-attachments/assets/21f47502-6abb-48c3-a3a1-ae3db74dd96d" />

---

### Phase 3: Adversarial Threat Simulation
Operating from an isolated browser session, I executed an external adversarial simulation by running a targeted brute-force/credential-harvesting attack—intentionally triggering consecutive failed login sequences against the directory infrastructure to generate explicit audit trails.

<img width="1920" height="1200" alt="Screenshot 2026-05-23 160750" src="https://github.com/user-attachments/assets/b8e905b1-b2e6-4969-b2d4-d3fd86a4debc" />

---

### Phase 4: KQL Cyber Hunting & Log Aggregation
I pivoted into the Sentinel Logs console to construct precise, high-visibility detection scripts. I engineered a query targeting the **`50126` ResultType** (the precise cryptographic error code for a bad password entry) to isolate the malicious source IP address and trace user-targeting patterns.

```kusto
SigninLogs
| where UserPrincipalName contains "admin"
| summarize FailedAttempts = count() by UserPrincipalName, IPAddress
