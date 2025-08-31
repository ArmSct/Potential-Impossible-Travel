# Potential Impossible Travel
<img width="534" height="266" alt="image" src="https://github.com/user-attachments/assets/e0d3fee8-4ffc-4b60-aea4-fdccf4342b8c" />

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)

## Scenario
In this lab, I simulate and investigate an unusual login behavior scenario using Microsoft Sentinel. The goal is to detect when a user logs in from multiple geographic locations within a 7-day period, which could indicate erratic login patterns and potential security concerns.

---
## Create an Alert Rule
I insert a Sentinel Scheduled Query Rule within Log Analytics that will discover when a user logs in to more than a certain number of locations within a given time period. 

<img width="597" height="285" alt="image" src="https://github.com/user-attachments/assets/cd4e6cc8-b0a6-4403-ac88-56dc57f12216" />

Many Impossible Travel instances were found.

<img width="516" height="254" alt="image" src="https://github.com/user-attachments/assets/c0650ee8-b50a-4198-aae5-6f5c3ccd0bac" />

---
## Create a Schedule Query Rule

<img width="682" height="540" alt="image" src="https://github.com/user-attachments/assets/e5ea4af1-2acc-48ec-b019-fcc14456a3a7" />

```kql
let TimePeriodThreshold = timespan(7d); 
let NumberOfDifferentLocationsAllowed = 2;
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| summarize Count = count() by UserPrincipalName, UserId, City = tostring(parse_json(LocationDetails).city), State = tostring(parse_json(LocationDetails).state), Country = tostring(parse_json(LocationDetails).countryOrRegion)
| project UserPrincipalName, UserId, City, State, Country
| summarize PotentialImpossibleTravelInstances = count() by UserPrincipalName, UserId
| where PotentialImpossibleTravelInstances > NumberOfDifferentLocationsAllowed
```

---
## Event triggered
Check event triggered. Assigned event to self.

<img width="1318" height="414" alt="image" src="https://github.com/user-attachments/assets/c2d6eef7-5aba-4b76-b8a8-01584ce77fc2" />

Visual of the incident and the various accounts that triggered the incident.

<img width="833" height="480" alt="image" src="https://github.com/user-attachments/assets/a04d4bca-fb51-44f7-9675-23be033743f1" />

Investigated one account. Nothing really alarming, all the logins were from the same location.
<img width="431" height="183" alt="brave_zHqp1PRK0Y" src="https://github.com/user-attachments/assets/c54dd193-ba99-460c-9496-3bf758507990" />

Investigated a second account as well. Aall the logins were also from the same location.
<img width="360" height="168" alt="brave_HYSLuDh0Yt" src="https://github.com/user-attachments/assets/143a9db2-5d4f-4dbe-96bc-32d0c8c1ef8c" />

The logins from the rest of the accounts were all okay as well.

Containment, Eradication, and Recovery

It it was determined that the alert was a TRUE BENIGN. Users and logged into only one country, there was no evidence of Impossible Travel. The users accounts were left intact due to expected behavior (not disabled). There was no threat to remove, further action may be taken pending a decision from management.

Post-Incident Activities

Explored the option of implmenting a geo-fencing policy within azure that prevents logins outside of certain regions. 
Documented findings and lessons learned. 
Recorded notes within the incident. 
Closed out the Incident within Sentinel as a “Benign Positive”.

<img width="614" height="467" alt="image" src="https://github.com/user-attachments/assets/b40f4da2-0d7f-4f26-9c1e-58b2f132447f" />


---
## Work Incident

---
## ?????

