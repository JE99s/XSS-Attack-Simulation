# XSS Attack Simulation

<br />


<h2>Environments Used</h2>

- <b>VirtualBox Hypervisor </b>

<h2>Description:</h2>
<p>This demonstration is my attempt to perform some cross-site scripting (XSS) attacks, gradually increasing in sophistication. The increase in difficulty from structured tasks will tie my understanding of the attack to 
practical applications. The following tasks will convey an idea of what methods can be used to exploit 
XSS and why it’s important to practice the proper remediations against these cyber attacks. Regarding 
practical applications, one goal of this lab is to spread an XSS worm among the users, such that whoever 
views an infected user profile will be infected, and whoever is infected will add the attacker to their 
friend list.</p>
<br />
<br />
On my Labtainers VM, much is already provided for the xsite lab including an environment consisting of 
three machines in the lab network: a victim machine, an attacking machine, and a terminal for the 
vulnerable web application, Elgg, itself.

<h3>Preparation</h3>
With the VM installed, I am provided with the topology of the network environment. The vulnerable website, 
xsslabelgg.com, pre-configured to have XSS countermeasures turned off to allow these attacks to take 
place. The victim machine, the entity that will be on the receiving-end of my XSS experiments. The 
attacker machine, where I’ll be capturing the results of the XSS tasks to come (e.g., stealing cookies and 
session hijacking).
<br/>
<img src="https://i.imgur.com/33NVv4O.png" height="70%" width="60%" alt="XSS Network Topology"/>
<br />

<h3>Elgg Web Application</h3>
I will be utilizing an open-source web application called Elgg. Elgg is a web-based social
networking application that is already placed on the vulnerable site. The lab has already provided accounts with their respective credentials shown below:
<br/>
<img src="https://i.imgur.com/ofO0C09.png" height="70%" width="60%" alt="table of accounts and credentials"/>
<br />
The URL configured for this lab is provided below: 
<br/>
<img src="https://i.imgur.com/gheXAbo.png" height="95%" width="85%" alt="DNS CONFIGURED URL TO XSS WEBSITE"/>
<br />

<h3>Posting a Malicious Message to Display an Alert Window</h3>
First, I will attempt to embed a JavaScript program in one of the Elgg server user’s profiles, 
such that when another user views that profile, the JavaScript program will be executed, and an alert 
window will be displayed. I should already have the lab initiated on my Labtainers VM. On the victim 
window, I will type <b><i>firefox</i></b> in the command line to load up the browser. I type the URL provided earlier to access the Elgg web application.
<br/>
<img src="https://i.imgur.com/OpZ5Ttx.png" height="85%" width="85%" alt="SEARCHING UP ELGG URL"/>
<br />
I log in to the social media website application as the user, Alice, on the victim machine.

<br/>
<img src="https://i.imgur.com/DZEGBAK.png" height="85%" width="85%" alt="LOG IN AS ALICE"/>
<br />

I will use the following JavaScript program to display an alert window:
<br/>
<img src="https://i.imgur.com/zjU5K5D.png" height="45%" width="55%" alt="JAVASCRIPT PROGRAM ALERT"/>
<br />

<br/>
<img src="https://i.imgur.com/02lz5Ob.png" height="65%" width="65%" alt="INSERT JS SCRIPT INTO BREIF Description FIELD"/>
<br />

I place this snippet of code in the '<b>Brief description</b>' field of Alice's profile, so that any user who views the profile will be welcomed with the alert window. Once it's entered, I scroll down and click the '<b>Save</b>' button. Once it refreshes, the alert window automatically appears!
<br/>
<img src="https://i.imgur.com/AOtWTGh.png" height="75%" width="75%" alt="ALERT WINDOW APPEARS"/>
<br />
When I log in as another user on the attacker machine. Samy, for example, I see the alert window 
whenever I attempt to view Alice's profile.
<br/>
<img src="https://i.imgur.com/C60Crrk.png" height="75%" width="75%" alt="Login as another user (SAMY)"/>
<br />

<br/>
<img src="https://i.imgur.com/7l2G88z.png" height="75%" width="75%" alt="Alert window appears once Alice's profile is clicked"/>
<br />
<h3>Posting a Malicious Message to Display Cookies</h3>
Now, I will attempt to embed a JavaScript program in Alice’s Elgg profile, such that when another 
user views the profile, the user’s cookies will display in the alert window I’ve just created earlier. This 
can be done by adding some additional code to the JavaScript utilized in the previous task such as:

<br/>
<img src="https://i.imgur.com/alPUPRU.png" height="45%" width="55%" alt="JavaScript program to grab user's cookies"/>
<br />


<br/>
<img src="https://i.imgur.com/ZEb8Y9O.png" height="85%" width="85%" alt="Edit Alice's profile to enter JS script"/>
<br />

Again, I will insert the revised code into the '<b>Brief description</b>' field on Alice's profile page. Once I finish pasting, I scroll down and click the '<b>Save</b>' button. Once it refreshes, the alert window automatically appears. This time with the user's cookies displayed in the alert window.
<br/>
<img src="https://i.imgur.com/orWm8XM.png" height="85%" width="85%" alt="Alert box windows displaying the user's cookies"/>
<br />
When I attempt to view Alice’s profile from another user’s perspective the alert window displays. This 
time with Samy’s cookies displayed.
<br />
<img src="https://i.imgur.com/2gFfl8y.png" height="85%" width="85%" alt="Alert box windows displaying the user's (Samy) cookies"/>
<br />
I'm going to save this cookie value for future purposes.
<br />
<h3>Analyzing DLLs</h3>
Dynamic-Link Libraries (.dll or DLLs) are modules that contain functions (code) and data that can be used 
by either another DLL or a program and have the ability to be used simultaneously by different data 
structures. Inspecting the DLLs of processes can greatly assist in connecting processes and their correlation 
with other programs. I will be using the <b>dlllist</b> plugin command for Volatility to print a list of all running 
DLLs for each process. I will use this plugin command specifically on poisonivy.exe. To print DLLs that are 
respective to a specific process, I use the -p flag and provide the PID of that process after the <b>dlllist</b> command.
Here, <i>poisonivy.exe</i> has quite a few DLLs, one of them being <b>kernel32.dll</b>. This kind of process being in system files is alarming to me.
<br/>
<img src="https://i.imgur.com/jVbr5Fp.png" height="85%" width="85%" alt="DLLLIST FOR POISONIVY.EXE PROCESS"/>
<br />


<h3>Malware Analysis</h3>
<h4>Poisonivy.exe</h4>
To confirm that this process is a malicious program I will be getting the hash of the <i>poisonivy.exe</i> file. Before that, I will need to dump the memory addresses of the executable to the disk of my Kali Linux box. The Volatility Framework tool has a plugin called <b>procdump</b> that allows me to dump the memory of the process to essentially recreate it on my disk for further analysis. I execute the <b>procdump</b> plugin command and it produces a <i>.exe</i> file named <i>executable.480.exe</i> in the current directory I'm in. Next, I get the MD5 hash by executing <b><i>md5sum executable.480.exe</i></b> to get the MD5 hash from the file. I have VirusTotal opened, I enter the hash and commence the scan.
<br />
Here, I see that 66 out of 72 security vendors have flagged this file as malicious from the scan. This most likely some type of malware.
<br/>
<img src="https://i.imgur.com/wDzHOv2.png" height="85%" width="85%" alt="VIRUSTOTAL SCAN OF POISONIVY.EXE"/>
<br />

I look to the <a href="https://attack.mitre.org/" target="_blank">MITRE ATT&CK</a> framework and search for the threat. This is indeed called <i>Poisonivy</i>, a remote administration tool (RAT) that acts as a backdoor to a compromised system. We're able to see this malware because it's memory resident. It's a known threat to Windows 2000, Windows XP, and Windows Server 2003 platforms. This malicious toolkit has been around for a while. There are variants of this malware that can be configured to any or all of the following:

- Capture screen, audio, and webcam 
- List active ports 
- Log keystrokes 
- Manage open windows 
- Manage passwords 
- Manage registry, processes, services, devices, and installed applications 
- Perform multiple simultaneous transfers 
- Perform remote shell 
- Relay server 
- Search files 
- Share servers 
- Update, restart, terminate itself

Most versions of Poisonivy can copy itself into other files, like system files by forking itself into alternate data streams, avoiding detection. I believe the VirusTotal scan seals the deal in identifying that there is or 
was malicious activity happening on this memory image. It says on VirusTotal that one of its imports is 
kernel32.dll to use as an exit process. We know that kernel32.dll is in fact a running DLL for <i>poisonivy.exe</i> from the DLL analysis earlier. I'm going to utilize the <b>malfind</b> Volatility command to find any hidden and injected code associated with <i>poisonivy.exe</i>. Here, there is inject code shown through the memory addresses in the output, "Hacker.Defender" and ".kernel32.dll. I think these files or codes have been injected by <i>poisonivy.exe</i>
<br />
<img src="https://i.imgur.com/KKJzePt.png" height="75%" width="75%" alt="MALFIND VOLATILITY COMMAND ON POISONIVY.EXE PROCESS"/>
<br />

It is common for malware to hide in plain sight. A virus won't be located on the <b>Desktop</b> folder, but malware commonly replaces certain system files located in the <b>system32</b> folder or outside of it. Malware likes to pose as legitimate Windows processes, which enable them to keep hidden and perform actions like keylogging, transferring more malicious files, spreading viruses, and more. I want to check some necessary processes that could possibly be holding malware, enabling the malware, or even the malware itself. The malicious poisonivy.exe has copied itself in to the machine's WINDOWS\system32 folder.

<br />
<img src="https://i.imgur.com/dsVvchI.png" height="90%" width="90%" alt="VOLATILITY FILESCAN & GREP 4 POISONIVY.EXE COMMAND"/>
<br />
I did a similar method in getting the hash of the kernel32.dll file. I used the <b>dlldump</b> plugin command for Volatility to recreate the DLL from the memory image.
<br />
<img src="https://i.imgur.com/6r03Qsv.png" height="95%" width="95%" alt="DLLDUMP CMD"/>
<br />
Once it was generated after executing the <b>dlldump</b> plugin command for Volatility, I got the MD5 hash and copied it to VirusTotal.
<br />
<img src="https://i.imgur.com/4Q4ZmJ4.png" height="85%" width="85%" alt="CMDLINE MD5 HASH OF DLL HASH"/>
<br />
<br />
<img src="https://i.imgur.com/1F3ik4D.png" height="95%" width="95%" alt="VIRUSTOTAL FEED"/>
<br />
<h3>More Findings & Conclusion</h3>
I was curious about <i>services.exe</i> and found that it had an injection as well through the <b>malfind</b> Volatility plugin command.
<br />
<img src="https://i.imgur.com/ymUuGhW.png" height="80%" width="80%" alt="VOLATILITY MALFIND CMD"/>
<br />
I performed a <b>procdump</b> on the process and grabbed its hash. I put the hash in the VirusTotal and the scan showed that there were four flags on it.
<br />
<img src="https://i.imgur.com/wOyRU1H.png" height="85%" width="85%" alt="VIRUSTOTAL SCAN OF SERVICES.EXE HASH"/>
<br />
I looked more into <i>hxdef100.exe</i> which is short for "Hacker Defender". This process is started by <i>services.exe</i> and <i>hxdef100.exe</i> is the PPID of other processes as well.
<br />
<img src="https://i.imgur.com/bE0zvB9.png" height="80%" width="80%" alt="PSTREE CMD TOWARD SERVICES.EXE AND HXDEF100.EXE"/>
<br />
I execute the <b>filescan</b> Volatility command to find any files associated with <i>hxdef100.exe</i>. The executable is in its own created directory labeled as a rootkit.
<br />
<img src="https://i.imgur.com/8ZAy85W.png" height="90%" width="90%" alt="HXDEFROOTKIT"/>
<br />
To confirm that <i>hxdef100.exe</i> is malicious or not, I do the same process of performing a <b>procdump</b> of the process to create an executable from memory, and then get the MD5 hash from the executable file so I can put that in VirusTotal.
<br />
<img src="https://i.imgur.com/sRc6qWH.png" height="90%" width="90%" alt="PROCDUMP ON HXDEF100.EXE"/>
<br />
Here, the VirusTotal scan shows me that 60 security vendors have flagged this file as malicious. This threat is labeled as a backdoor trojan.
<br />
<img src="https://i.imgur.com/zJ13Vpe.png" height="90%" width="90%" alt="VIRUSTOTAL SCAN OF HXDEF100.EXE HASH"/>
<br />
I've come to reveal some major findings throughout the lab. Here is my hypothesis as to how this machine was compromised:
<br />
The Poison Ivy malware (poisonivy.exe) was emitted into the machine via the Windows Explorer browser 
on through an FTP port, maybe port 3460 (from the <b>connscan</b> earlier) most likely through a TCP-enabled transfer file service. Somehow a malicious file containing <i>poisonivy.exe</i> was transferred into the victim's Windows XP instance and then the payload was delivered. Poisonivy could have created a run key Registry pointing to a malicious executable such as <i>hxdef100.exe</i> once it was dropped to disk. Then it executed inside the affected machine, it copies itself as critical files like <i>svchost.exe</i> to stay hidden.
<br />
This enables the download and installation of <i>hxdef100.exe</i> to create a backdoor in the background between different processes in the Windows XP machine or ports (via open ports found in an Nmap scan).
<br />
Hacker Defender or <i>hxdef100.exe</i> is a rootkit that can configure itself to connect to hidden ports on a system via netcat. It can set itself to run when the victim system boots and the file mapping name can be set when it's injected into system files. Utilizing the strings function on Kali, I found the settings section for the <i>hxdef100.exe</i> build and there are some major similarities between that and the <b>malfind</b> Volatility plugin command for PID 480.
<br />
<img src="https://i.imgur.com/dYEHjRv.png" height="90%" width="90%" alt="STRINGS CMD ON KALI FOR HXDEF100"/>
<br />
Here, I found some more configurations possibly done by the hacker showing that <i>hxdef100.exe</i> is 
set as a backdoor shell.
<br />
<img src="https://i.imgur.com/hjzE0KI.png" height="90%" width="90%" alt="STRINGS CMD ON KALI FOR HXDEF100"/>
<br />
<br />
It spread itself to replace or inject itself into essential Windows processes. Then <i>hxdef100.exe</i> can inject 
itself into batch files and other processes via Alternate Data Stream. Once a backdoor is created, the 
hacker was able to connect back to the Windows XP machine via port forwarding through a listed open 
port utilizing netcat or <i>nc.exe</i> to create a bind shell giving the hacker a remote command prompt on the 
Windows XP system.
<br />
<img src="https://i.imgur.com/A7tJZ9D.png" height="95%" width="95%" alt="NETCAT FOUND IN PSTREE COMD"/>
<br />
This provides more malicious activities such as the opportunity to create new passwords for accounts, lock 
users out of their own system, and leave critical damage to a machine.
<br />
<br />
Throughout this demonstration, I utilized a commonly used memory analysis tool to scan, connect, 
identify, and confer on the running processes from this memory image. The compromised machine 
did indeed have malicious activity going on. I found a backdoor with root-like (superuser) privileges that 
took advantage of the machine to gain access to Windows XP.

<h3>References</h3>
Balapure, Aditya. “Memory Forensics and Analysis Using Volatility.” Infosec Resources, 13 May 2021, 
resources.infosecinstitute.com/topic/memory-forensics-and-analysis-using-volatility/.
<br />
<br />
Chaturvedi, A. (2010, December 1). Playing around with HXDEF rootkit. Playing Around with HXDEF Rootkit. 
Retrieved April 2, 2023, from http://anadisays.blogspot.com/2010/11/playing-around-with-hxdef
rootkit.html
<br />
<br />

Corporation, M. (n.d.). Microsoft. threat description - Microsoft Security Intelligence. Retrieved April 2, 
2023, from https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia
description?Name=Backdoor%3AWin32%2FPoisonivy.I&threatId=-2147363597
<br />
<br />

evild3ad. “Home.” evild3ad.Com, 20 Sept. 2011, evild3ad.com/956/volatility-memory-forensics-basic
usage-for-malware-analysis/.
<br />
<br />

eXPlorer, Hack. “How to Use Volatility - Memory Analysis for Beginners.” YouTube, 24 Jan. 2020, 
youtu.be/eluS7_eSm8M.
<br />
<br />

Hat, Black. “Investigating Malware Using Memory Forensics - A Practical Approach.” YouTube, 14 Jan. 2020, 
youtu.be/BMFCdAGxVN4. 
<br />
<br />

Linux, Kali. “Volatolity -- Digial Forensic Testing of RAM on Kali Linux.” Best Kali Linux Tutorials, 11 Dec. 
2021, www.kalilinux.in/2021/03/volatolity-digial-forensic-testing-of.html. 
<br />
<br />

Poisonivy. PoisonIvy, Software S0012 | MITRE ATT&CK®. (n.d.). Retrieved April 1, 2023, from 
https://attack.mitre.org/software/S0012/ 
<br />
<br />

Poisonivy. POISONIVY - Threat Encyclopedia. (n.d.). Retrieved April 1, 2023, from 
https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/poisonivy
<br />
<br />

P4N4Rd1. “First Steps to Volatile Memory Analysis.” Medium, Medium, 13 Jan. 2019, 
medium.com/@zemelusa/first-steps-to-volatile-memory-analysis-dcbd4d2d56a1. 
<br />
<br />

v4L. “Hacker Defender HXDEF Rootkit Tutorial in 10 Steps [Nostalgia].” Ethical Hacking Tutorials, Tips and 
Tricks, 18 Mar. 2014, www.hacking-tutorial.com/hacking-tutorial/hacker-defender-hxdef-rootkit
tutorial-in-10-steps-nostalgia/#sthash.5Bs5vvB2.U7N3Sh54.dpbs.
