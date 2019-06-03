# Goal

Detect the malicious use of scriptable protocol handlers via inline script execution.

# Categorization

This ADS addresses procedures that fall within the following MITRE ATT&CK categorizes:

* [Mshta](https://attack.mitre.org/techniques/T1170/)
* [Rundll32](https://attack.mitre.org/techniques/T1085/)

# Strategy Abstract

To detect the malicious use of Scriptable Protocol Handlers we use the following steps:

* Record mshta.exe and rundll32.exe process execution events with their associated command line parameters via Sysmon
* Send process execution events to Elasticsearch
* Identify mshta.exe or rundll32.exe processes that are using scriptable protocol handlers (vbscript: or javascript:)
* Analyze results to understand if activity is malicious of benign
* Investigate the script being executed to determine if activity is benign or malicious
* The following Kibana queries will display instances of mshta and rundll32, and will also narrow in on those processes being used specifically to execute inline scripts via scriptable protocol handlers:

```
event_id: 1 AND (process_name: mshta.exe OR process_name: rundll32.exe) AND (process_command_line: *vbscript:* OR process_command_line: *javascript:*)
```

# Technical Context

A Protocol Handler defines how web aware applications like Internet Explorer, Google Chrome, Firefox, and Microsoft HTML Application Host (mshta) handle interpreting URI schemes like http:, https:, ftp:, etc. Protocol Handlers can be enumerated through the HKEY_CLASSES_ROOT\PROTOCOLS\Handler registry key. Windows comes stock with many protocol handlers including two "scriptable" protocol handlers, namely javascript: and vbscript:. These scriptable protocol handlers are meant for use with the mshta application to provide better flexibility when authoring Microsoft HTML Applications (HTA). Mshta relies on the RunHTMLApplication function within mshtml.dll to interpret the scriptable handler and execute the code as written. Attackers have identified that this code can be executed without the HTA file being written to disk through "inline execution".

This type of activity has been observed to be used by numerous threats and have been described in the following reports:

* [Red Canary - MSHTA Abuse Part Deux](https://redcanary.com/blog/microsoft-html-application-hta-abuse-part-deux/)
* [Operation Dust Storm](https://www.cylance.com/content/dam/cylance/pdfs/reports/Op_Dust_Storm_Report.pdf)
* [FIN7 Evolution and the Phishing LNK](https://www.fireeye.com/blog/threat-research/2017/04/fin7-phishing-lnk.html)
* [Fileless Malware - A Behavioral Analysis of Kovter Persistence](http://blog.airbuscybersecurity.com/post/2016/03/FILELESS-MALWARE-%E2%80%93-A-BEHAVIOURAL-ANALYSIS-OF-KOVTER-PERSISTENCE)
* [Iranian Threat Group Updates Tactics, Techniques, and Procedures in Spear Phishing Campaign](https://www.fireeye.com/blog/threat-research/2018/03/iranian-threat-group-updates-ttps-in-spear-phishing-campaign.html)

Two simple examples of inline scriptable protocol handler execution via mshta can be seen below:

```
mshta vbscript:Execute("On Error Resume Next:set w=GetObject(,""Word.Application""):execute w.ActiveDocument.Shapes(2).TextFrame.TextRange.Text.close")
```

```
"c:\windows\system32\mshta.exe" javascript:bz0pbzykh="qoethfr1";jo9=new%20activexobject("wscript.shell"); tkk4qffrj="wrqxzpuvp";zv0v5w=jo9.regread("hklm\software\wow6432node\88b21b0b\7f490d53");v9tjbmpoy="nwzv9xiv";eval(zv0v5w);wqfccxdq4="u";
```

This inline technique is a great way to remove the step of creating an HTA file on disk, but may be more susceptible to detection in environments with full command line auditing.

## Abusing Rundll32 to Execute Scriptable Protocol Handlers

In addition to inline execution through mshta, Poweliks introduced the use of the same inline technique through rundll32. Rundll32 is an application that allows for the execution of a specific function from a shared library (DLL). The Poweliks authors found that they could write the commandline for rundll32 in such a way that they could call the RunHTMLApplication function from mshtml.dll AND use that function to execute inline malicious javascript.

An example commandline for leveraging rundll32 to execute malicious inline javascript is shown below:

```
rundll32 javascript:"\..\mshtml,RunHTMLApplication ";document.write("\74script-language=jscript.encode>"+(new%20ActiveXObject("WScript.Shell")).RegRead("HKCU\\software\\microsoft\\windows\\currentversion\\run\\")+"\74/script>")
```

For a more detailed explanation of why this syntax works to execute the javascript scriptable protocol handler, check out BenKow_'s awesome blog post, [Poweliks - Command Line Confusion](https://thisissecurity.stormshield.com/2014/08/20/poweliks-command-line-confusion/), where he digs into how the commandline is parsed to achieve the desired result.

# Blind Spots and Assumptions

This strategy relies on the following assumptions:

* Attackers use inline scriptable protocol handlers as a form of initial access or code execution
* Attackers perform this activity through rundll32.exe or mshta.exe
* Sysmon is installed on the target endpoint
* Sysmon is forwarding all process events to a centralized location
* All Sysmon process events are being indexed into Elasticsearch

A blind spot will occur if any of the assumptions are violated. For instance, the following would not trip the alert:

* The attacker writes a malicious .hta file and executes it via mshta
* The attacker uses rundll32 to executes a function from any other DLL (custom or built in)
* The attacker obfuscates the command line such that the javascript: or vbscript: protocol handlers are not clear

# False Positives

There are currently no known false positives and testing indicates that this activity should rarely if ever occur in an environment.

# Priority

The priority is set to high under all conditions.

# Validation

This detection can be validated by executing benign scripts via the commandline. Below you will find examples of these scripts for both mshta and Rundll32.

## Mshta - Vbscript

```
mshta vbscript:CreateObject("Wscript.Shell").Run("calc.exe",0,true)(window.close)
```

## Mshta - Javascript

```
mshta javascript:alert(‘foo’);
```

## Rundll32 - Javascript

```
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";alert(‘foo’);
```

# Response

Activity of this type should be exceedingly rare. As such, all hits should be analyzed to determine if the activity is malicious or benign. There are a couple steps that can help the analyst gain additional understanding of the activity itself to confirm malicious intent:

## Analyze the Script

As this activity is by nature executing scripts, the first step that should be taken by the analyst should be to understand the intent of the script itself. These scripts are often obfuscated in some way to add additional layers for the analyst to peel through, but the result should ultimately be directly available. The JSDetox project provides some great examples of obfuscated javascript and how the tool can deobfuscate the script in a safe manner.

## Child Processes

In many cases, the initial offending process (mshta or rundll32) is used as a launcher for an additional process. These child processes can often provide more context about the attack than the initial event.

## Network Connections

Network Connections are another great source of context. They can/should be used to identify any lateral movement or command and control activity.

Additionally, the initial offending process is often used as a vehicle to execute a secondary payload, so the network connections of child processes could also prove to be valuable in the same manner.


# Additional Resources

* [Introducing HTML Applications](https://msdn.microsoft.com/en-us/library/ms536496%28v=vs.85%29.aspx?f=255&MSPPError=-2147217396#Compatibility)