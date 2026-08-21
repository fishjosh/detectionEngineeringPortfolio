# LSASS Granted Access Rule  
Filename: proc_access_win_lsass_grantedaccess.yml  

### What this project did  
Built a Sigma detection rule for LSASS credential dumping (MITRE ATT&CK T1003.001). I combined suspicious `GrantedAccess` 
mask values with well-known LSASS-dumping tools (procdump, mimikatz, rundll32) that access `lsass.exe`.

### Known Limitations
This uses exact mask matching instead of bit masking or substring matching. Will add that in the next version.  
The tool names are also specific and rather low on the Pyramid of Pain. Can be circumvented by changing the names. 
Recognizing that shortcoming and will fix in a future version.  

Looking to get more use from the EVTX file below by creating a detection rule for eventID 11 as well.

### Testing
Results when using ssbouseaden's evtx sample: `sysmon_10_11_outlfank_dumpert_and_andrewspecial_memdump`  
([EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES))  
  
Can be found at GrantedAccessZircolite.txt and GrantedAccessChainsaw.txt in this folder  

### What I learned
Learned a lot in my research for MITRE ATT&CK T1003.001.  
I've never worked with Chainsaw nor Zircolite before. Very useful and nice to compare the results.  
Still learning how to write my detecions cleanly and thining through false positives.  
