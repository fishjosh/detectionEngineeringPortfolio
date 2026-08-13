# Working through BOTS v3 questions  

For quick reference, I'm trying to keep the following in mind as I learn:  
Who? → Firewall/VPN (ties identity to IP)  
Where did they go? → HTTP proxy or DNS  
What ran on the machine? → Sysmon  
What did Windows record? → WinEventLog  
Did the network notice anything? → Suricata  

| I want to find | First place to look | Splunk sourcetype |
|---|---|---|
| Person → IP address | Firewall (user-ID mapping) or VPN logs | pan:traffic, vpn, fgt_traffic |
| IP → websites visited | Web proxy or firewall outbound | stream:http, pan:traffic |
| IP → domains resolved | DNS logs | stream:dns |
| Process → what it did on disk | Sysmon | XmlWinEventLog:Microsoft-Windows-Sysmon/Operational |
| Process → network connections | Sysmon Event ID 3 | same as above |
| User → login activity | Windows Security logs | WinEventLog:Security (Event ID 4624) |
| File → was it executed? | Sysmon Event ID 1 (process create) | Sysmon |
| Email → sender/recipient/attachment | SMTP stream | stream:smtp |
| Host → what's installed/running | OSQuery | osquery_results |
| Outbound connection → IDS flagged it? | Suricata | suricata |
| USB device plugged in | OSQuery or Sysmon | osquery_results |

Q1: What is the name of the company that makes the software that you are using for this competition? Answer guidance: A six-letter word with no punctuation.  
Splunk  

Q2: List out the IAM users that accessed an AWS service (successfully or unsuccessfully) in Frothly’s AWS environment? Answer guidance: Comma separated without spaces, in alphabetical order. (Example: ajackson,mjones,tmiller)
This one felt pretty straightforward:  
index="botsv3" earliest=0 IAM sourcetype="aws:cloudtrail"  
In the interesting fields list, one caught my eye: userIdentity.userName  
So with this index="botsv3" earliest=0 IAM sourcetype="aws:cloudtrail" | stats values(userIdentity.userName) we get:  
bstoll, btun, splunk_access, web_admin

Q3: What field would you use to alert that AWS API activity have occurred without MFA (multi-factor authentication)? Answer guidance: Provide the full JSON path. (Example: iceCream.flavors.traditional)  
Similar search as before but we're going to go by the consoleLogin instead  
index="botsv3" earliest=0 sourcetype="aws:cloudtrail" ConsoleLogin  
In here there's a field for additionalEventData.MFAUsed set to No for all 4 events that popped up  
We would filter on this field  

Q4: What is the processor number used on the web servers? Answer guidance: Include any special characters/punctuation. (Example: The processor number for Intel Core i7-8650U is i7-8650U.)
To start, let's look back at the sourcetypes  
index=botsv3 earliest=0 | stats count by sourcetype  
Scrolling through to get an idea, hardware seemed to stand out as a pretty good sourcetype.  
After adding that to the search  
index=botsv3 earliest=0 sourcetype = hardware  
Only one CPU_type came back, it was Intel(R) Xeon(R) CPU E5-2676 v3 @ 2.40GHz  
It tells us to just list the processor number which is E5-2676  

Q5: Bud accidentally makes an S3 bucket publicly accessible. What is the event ID of the API call that enabled public access? Answer guidance: Include any special characters/punctuation.
Using what we know, let's start with just:  
index="botsv3" earliest=0 "Bud"  
userDisplayName shows us his name is Bud Stoll, so we can assume bstoll is the name we'll want to search with  
index="botsv3" earliest=0 sourcetype="aws:cloudtrail" "bstoll"  
We also know that he gave public access and also that the S3 bucket was used. So let's try:  
index="botsv3" earliest=0 sourcetype="aws:cloudtrail" "bstoll" \*bucket\* "AllUsers"  
This comes up with just one result. After searching through the AcessControlPolicy, we verify that AllUsers were granted Full_Control and the eventID is at the top  
ab45689d-69cd-41e7-8705-5350402cf7ac
