# Working through BOSS challenges and my process to work through it

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



100 Series Questions
Q101: Amber Turing was hoping for Frothly to be acquired by a potential competitor which fell through, but visited their website to find contact information for their executive team. What is the website domain that she visited?  

Because of the outline above I started with:  
index="botsv2" earliest=0 sourcetype="pan:traffic" amber  
The question asks us to find a website so I know to look for an ip and found the src_ip of 10.0.2.101  
Added that to my search and traded out the sourcetype for "steam:http"
Now that we're here we also should see the names of all the sites so this is where we would also add in "| table site | dedup site" at the end of our search
This is where I got stuck because the site I found this on didn't really help in what I should be looking for  
So I search for the initial BOSS challenge and found this  
<img width="390" height="287" alt="image" src="https://github.com/user-attachments/assets/3343f579-e4d6-4c93-96e7-b66b050b5c9c" />  
Still didn't help a ton because I added \*brew\* to my search and came up empty  
So, I just manually went through the data, as the total account was only 191 results  
I then found www.berkbeer.com, which in hindsight, "beer" would have been a good search term. Oh well.  
On to question 2:  

Q102: Amber found the executive contact information and sent him an email. What image file displayed the executive’s contact information? Answer example: /path/image.ext  
This one was pretty straightforward, we see that she found the contact on the site so we just add the site to our search  
After scrolling, we can see that there are several uri paths with image paths  
Clicking on the uri_path field we get this:  
<img width="682" height="582" alt="image" src="https://github.com/user-attachments/assets/edebb3ce-6f7b-4507-9216-10942e7f6617" />  
There is an image path with the title CEO in it so we can gather the image path is:  
/images/ceoberk.png

Q103: What is the CEO’s name? Provide the first and last name.  
Now that she has his contact information and know she sent him an email so my search was:  
index="botsv2" sourcetype="stream:smtp" amber \*ceo\*
Only one was from sender Amber Turing <aturing@froth.ly>  
It was to a Heinz Bernhard but the subject was about contact information  
The receiver alias mentioned berkbeer.com so I decided to search for that  
index="botsv2" sourcetype="stream:smtp" amber berkbeer.com  
And found two promising emails:  
One from Heinz Berhnhard and one from Martin Berk  
Looking into the content body of these emails it appears that Amber was initially discussing the acquisition with Martin Berk  

Q104: What is the CEO’s email address?  
This was answered on the way to the last question but it is mberk@berkbeer.com  

Q105: After the initial contact with the CEO, Amber contacted another employee at this competitor. What is that employee’s email address?  
This was also answered through Q103: hbernhard@berkbeer.com  

Q106: What is the name of the file attachment that Amber sent to a contact at the competitor?  
Simply going to that record and going to attachment_filename gives us: Saccharomyces_cerevisiae_patent.docx

Q107: What is Amber's personal email address?  
Their email's content body shows Bernhard asking Amber for her personal email address. 
In Q103, I stumbled upon a subject of an email address titled "RE: Heinz Bernhard Contact Information", so I can only assume that was her response since this one was titled "Heinz Bernhard Contact Information"
I went to the email record with the subject I found in Q103 but the content body of this seemed to be encoded.  
I searched the raw data for "amber" and "@" just to see if something easy would show up but came up short, so then I looked for more clues.  
I then found that the content_transfer_encoding was base64  
So I just looked up a base64 decoder and entered that first block to decode and found this:  
"Thanks for taking the time today, As discussed here is the document I was referring to.  Probably better to take this offline. Email me from now on at ambersthebest@yeastiebeastie.com<mailto:ambersthebest@yeastiebeastie.com>"  
So the answer is ambersthebest@yeastiebeastie.com

That's it for the 100 series questions  
On to the 200!  

Q201: What version of TOR Browser did Amber install to obfuscate her web browsing? Answer guidance: Numeric with one or more delimiter.  
Since there was an install that occurred, my first instinct was to try  
index="botsv2" sourcetype="osquery_results" amber  
That came up with basically one result about a yeast.png so that wasn't very helpful.  
I then turned to xmlwineventlog since something happened to the disk and included amber and tor to the search  
index="botsv2" Amber sourcetype=xmlwineventlog install  
One result came up that said C:\Users\amber.turing\Downloads\torbrowser-install-7.0.4_en-US.exe  
So, we can assume it was version 7.0.4

Q202: What is the public IPv4 address of the server running www.brewertalk.com?  
This is a public IP so we know to search for sourcetype="stream:http" and site = "www.brewertalk.com", let's try that  
index="botsv2" sourcetype="stream:http" site=www.brewertalk.com  
We know to look for the dest_ip and there are luckily just 2 results  
172.31.4.249 and 52.42.208.228  
Private ips fall within this range, so the other one must be the public one  
<img width=  "805" height="272" alt="image" src="https://github.com/user-attachments/assets/b2efa869-dfc0-4261-9a74-ee3338b380c1" /> 
52.42.208.228 

Q203: Provide the IP address of the system used to run a web vulnerability scan against www.brewertalk.com.  
For this one, I just worked with what we had. The website name and the word scan. Low and behold it returned two records one source ip  
index="botsv2" site=www.brewertalk.com scan  
45.77.65.211  

Q204: The IP address from Q#3 is also being used by a likely different piece of software to attack a URI path. What is the URI path?  
We know the ip address before so let's see what we get by trying to find the top uri_path  
index="botsv2" 45.77.65.211 | top uri_path  
/member.php is by far the leading uri_path so it's likely under attack  








