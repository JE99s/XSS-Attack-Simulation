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
<h3>Stealing Cookies from the Victim's Machine</h3>
The JavaScript I utilized printed out the user's cookies in the alert window. However, only the user could see those cookies, not the attacker. So, I will attempt to adjust the JavaScript program such that the attacker can have the code send the cookies to them. In doing so, the JavaScript code needs to send an HTTP request to the attacker, with the cookies appended to the request. <br /> <br />

At this point I have switched users on the attacker and victim machine. Now, I have the user, Alice ( the attacker), signed into the Elgg web application on the attacker machine, and I have another user, Samy (victim), signed into the Elgg web application on the victim machine.

I proceed by revising the JavaScript code to insert an <b><img></b> tag with its <b>src</b> attribute set to the attacker's machine. So, when JavaScript inserts the <b><img></b> tag, the browser tries to load the image from the URL in the <b>src</b> field; this results in the an HTTP GET request sent to the attacker's machine. I will update the program in the '<b>brief description</b>' field in Alice's profile page. The revised JavaScript is shown below:
<br/>
<img src="https://i.imgur.com/nKB66Ep.png" height="95%" width="95%" alt="new JS script for attacker to grab victim's cookies"/>
<br />
The code above sends cookies to port 5555 of the attacker's machine, where the attacker has a TCP server listening on that same port. The server will essentially print out whatever it receives. The TCP server program is in the <b>echoserver</b> directory on the attacker machine.
<br/>
<img src="https://i.imgur.com/5MaC4Eu.png" height="75%" width="75%" alt="echoserver location"/>
<br />
Once I've navigated to the <b>echoserver</b> directory of the attacker machine, I type <b><i>./echoserv 5555</i></b> then press <b>Enter</b> to start the port listener.
<br/>
<img src="https://i.imgur.com/mnf7St8.png" height="75%" width="75%" alt="run echoserver on port 5555"/>
<br />
I go back to the Firefox window on the victim machine and travel to the '<b>Members</b>' page under the '<b>More</b>' section on the top menu (blue ribbon) of the Elgg website so I can attempt to view Alice's profile page.
<br/>
<img src="https://i.imgur.com/4qxg76Q.png" height="75%" width="75%" alt="CLICK MEMBERS"/>
<br />
<br/>
<img src="https://i.imgur.com/ycuH7X4.png" height="75%" width="75%" alt="CLICK ALICE"/>
<br />
Once the page loads, I go back to the attacker machine to check the TCP listener and here we have the captured cookies displayed with the HTTP GET request:
<br/>
<img src="https://i.imgur.com/KNyXMPl.png" height="75%" width="75%" alt="RECEIVED VICTIM'S COOKIES ON ECHOSERVER"/>
<br />
Notice how the captured cookies just now are the same as what we've seen captured earlier in the alert window that I save for future reference.
<br/>
<img src="https://i.imgur.com/1nujEAY.png" height="75%" width="75%" alt="Matching cookies under SAMY"/>
<br />
<h3>Session Hijacking Using the Stolen Cookies</h3>
Now that the attacker has stolen the victim's cookies, they can do whatever the victim can do the Elgg web server, including adding and deleting friends. The attacker has essentially hijacked the victim's session. Now, I will launch this session hijacking attack and write a program to add a friend on behalf of the victim. <br /> <br />

A Java program, located in the <b>HTTPSimpleForge</b> directory on the attacker machine, will simplify this task. After navigating to the directory, I execute the command <b><i>nano HTTPSimpleForge.java</i></b> to open the Java program with the nano editor.

<br/>
<img src="https://i.imgur.com/dO4PgFh.png" height="85%" width="85%" alt="Open HTTPSimpleForge with NANO"/>
<br />

The program on the attacker machine should perform the following: 
1) Opens a connection to the web server. 
2) Sets the necessary HTTP header information. 
3) Sends the request to web server. 
4) Gets the response from web server.

<br/>
<img src="https://i.imgur.com/nxTKGis.png" height="85%" width="85%" alt="Editing HTTPSimpleForge with NANO"/>
<br />

At first glance, I pay attention to the string variable, '<b>requestDetails</b>', assigned to two parameters: <b>__elgg_ts</b> and <b>__elgg_token</b>. These values will need to be correctly replaced with the values provided from the victim machine. However, let's examine where these variable parameters located on the Elgg web application itself.

<br />
<img src="https://i.imgur.com/GFhtVkK.png" height="85%" width="85%" alt="Variable param. of Add friend button"/>
<br />

Since the program I want to write will essentially make a victim add the attacker as a friend when viewing the attacker's profile. I should look at the works behind the friend request. We'll look at the example above for adding the user, Samy, as a friend. With the inspector tool, I can see the code of the webpage. Notice the URL selected, those are the same parameters in the Java program. I need to take the values of the parameters contained in the URL link of the '<b>Add friend</b>' button of the user we want to add as a friend (the attacker, Alice) and assign those values to the <b>__elgg_ts</b> and <b>__elgg_token</b> parameters in the Java program. On the victim machine, as the user Samy, I will navigate to Alice's profile as I'm going to add Alice as a friend. I right-click the '<b>Add friend</b>' button and copy the link. I'll keep it for reference as shown below.

<br />
<img src="https://i.imgur.com/dI37sSj.png" height="90%" width="90%" alt="KEEP __ELGG_TS VALUE AS REFERENCE"/>
<br />
I first copy the value of the <b>__elgg_ts</b> parameter from the URL above and assign that value into the <b>__elgg_ts</b> parameter in the <b>HTTPSimpleForge.java</b> program.
<br />
<img src="https://i.imgur.com/cR0gA5u.png" height="95%" width="95%" alt="INSERT ELGG_TS VALUE INTO JAVA PROGRAM (SIMPLEFORGE)"/>
<b>Place: pg 12 of 23 starting at "Same thing goes for..."</b>
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
