# 🛡️ Microsoft Sentinel Identity Threat Hunting Lab

A home lab where I sent Microsoft Entra ID sign-in logs into Microsoft Sentinel, simulated a brute-force attack against a test account, and wrote KQL to detect it.

**Logs exist → I collected them → I attacked → I caught it.**

---

## 🏢 Scenario

A fictional company, *BrandonTech*, is seeing a spike in failed sign-ins against employee accounts. Entra ID records every sign-in, but no one is monitoring those logs, so the attack goes unnoticed.

**Goal:** Centralize identity logs in a SIEM and build a query that surfaces brute-force activity: many failed password attempts from one source in a short window.

> All work was done in an isolated sandbox tenant with test accounts. No real users or production systems were involved.

---

## 🛠️ Skills and Technologies

| Area | What I used |
|---|---|
| Identity | Microsoft Entra ID (test users, sign-in logs) |
| SIEM | Microsoft Sentinel on a Log Analytics Workspace |
| Data ingestion | Entra ID data connector / diagnostic settings → `SigninLogs` table |
| Threat hunting | Kusto Query Language (KQL) |
| Detection logic | Entra error code `50126` (invalid username or password) |

**Note:** Exporting Entra ID sign-in logs to a Log Analytics Workspace requires an Entra ID P1 or P2 license.

---

## 🚀 Lab Walkthrough

### Phase 1: Sandbox Setup

I created a dedicated Entra ID tenant and provisioned test users, including **Alice Smith (`asmith`)**, who served as the attack target.

<img width="1920" height="1200" alt="Sandbox tenant test users" src="https://github.com/user-attachments/assets/98c91373-09f4-4a7c-85eb-f40522179b90" />

### Phase 2: Building the Log Pipeline

1. Created a Log Analytics Workspace named `law-sentinel-core`.
2. Enabled Microsoft Sentinel on that workspace.
3. Connected Entra ID so sign-in logs flow into the `SigninLogs` table.

<img width="1920" height="1200" alt="Log Analytics Workspace law-sentinel-core" src="https://github.com/user-attachments/assets/c055e765-3b6b-4b60-b0b2-630d2d73772d" />
<img width="1920" height="1200" alt="Microsoft Sentinel configuration" src="https://github.com/user-attachments/assets/21f47502-6abb-48c3-a3a1-ae3db74dd96d" />

### Phase 3: Simulating the Attack

From a private browser session, I repeatedly tried to sign in as `asmith` with wrong passwords. This generated a burst of real failed sign-in events, each logged with error code `50126`.

This simulates a **brute-force attack**: many password guesses against one account.

<img width="1920" height="1200" alt="Simulated failed sign-in attempts" src="https://github.com/user-attachments/assets/b8e905b1-b2e6-4969-b2d4-d3fd86a4debc" />

### Phase 4: Hunting with KQL

In the Sentinel Logs console, I wrote a query to find the attack:

```kql
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType == "50126"
| summarize FailedAttempts = count(), UsersTargeted = dcount(UserPrincipalName)
    by IPAddress, bin(TimeGenerated, 10m)
| where FailedAttempts >= 5
| order by FailedAttempts desc
```

**What each line does:**

| Line | Purpose |
|---|---|
| `SigninLogs` | Entra ID sign-in events |
| `TimeGenerated > ago(1h)` | Only look at the last hour |
| `ResultType == "50126"` | Only keep bad-password failures |
| `summarize ... by IPAddress, bin(TimeGenerated, 10m)` | Count failures per IP in 10-minute windows, and count how many different accounts each IP hit |
| `FailedAttempts >= 5` | Threshold to filter out normal mistyped passwords |
| `order by ...` | Noisiest sources first |

To see exactly which accounts a suspicious IP targeted:

```kql
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType == "50126"
| summarize FailedAttempts = count() by UserPrincipalName, IPAddress
| order by FailedAttempts desc
```

---

## 📊 Results

- The query surfaced the burst of failed sign-ins against `asmith` and the source IP address.
- The `UsersTargeted` column separates two attack types:
  - **Brute force:** one IP, one account, many attempts (what this lab simulated)
  - **Password spraying:** one IP, many accounts, few attempts each (high `UsersTargeted`)

### Possible false positives

- A real user who forgot their password, especially right after a reset
- A device or app retrying an old saved password in the background

The threshold and the number of accounts per IP help separate these from real attacks.

---

## 🔒 Detection vs. Prevention

This lab focuses on **detection**. In a real environment I would pair it with identity controls that **prevent** the attack from succeeding:

- **MFA** enforced through Conditional Access
- **Entra Smart Lockout** to lock out repeated guessing
- **Blocking legacy authentication**, which bypasses MFA

---

## ⏭️ Next Steps

- [ ] Convert the hunting query into a **scheduled analytics rule** so Sentinel creates an incident automatically
- [ ] Add a **playbook (Logic App)** to notify an admin or disable the targeted account
- [ ] Add a separate query for **password spraying** across many accounts
- [ ] Add a screenshot of the query results
- [ ] Map the detection to **MITRE ATT&CK T1110 (Brute Force)**

---

## 💡 What I Learned

- How identity logs move from Entra ID into a SIEM
- How to read Entra sign-in error codes
- How to write KQL that aggregates events into a useful signal instead of raw noise
- Why detection and prevention need to work together in IAM
