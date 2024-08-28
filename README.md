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
<br />
Same thing goes for the '<b>elgg_token</b>' value.
<br />
<img src="https://i.imgur.com/jtZzaad.png" height="85%" width="85%" alt="Grab Elgg_token value"/>
<br />
The last critical component of the program is grabbing the correct cookies to ensure that the code will peform as expected.
<br />
<img src="https://i.imgur.com/hpvYCQo.png" height="85%" width="85%" alt="Ensure program runs with correct cookies"/>
<br />
I will take the cookies I saved from the victim machine and assign them as values to the variables below in the <b>HTTPSimpleForge.java</b> program.
<br />
<img src="https://i.imgur.com/hY59fTQ.png" height="85%" width="85%" alt="Assigned saved cookies into variables in HTTPSimpleForge.java program"/>
<br />
I save the Java program with the new changes and run the code by executing the following commands in sequence:
<br /> <br />
<b><i>javac HTTPSimpleForge.java</i></b>
<br /> <br />
<b><i>java HTTPSimpleForge</i></b> <br />
<br />
<img src="https://i.imgur.com/vHkR5On.png" height="85%" width="85%" alt="HTTP 400 Bad request code"/>
<br />
From execution, I received a HTTP 400 Bad Request response code, which most likely means I missed something while editing the code. I go back to the nano editor, and I notice that URL variable below the '<b>requestDetails</b>' variable holding the <b>__elgg_ts</b> and <b>__elgg_token</b> parameters is essentially the first half of the URL link that will perform the action of adding a friend on the Elgg web application. In the Java program, I replaced the placeholder with the number "39" from the first half of the "add friend" URL saved from earlier. The URL below utilized is Alice's '<b>Add friend</b>' URL.
<br />
<img src="https://i.imgur.com/QOtA3sN.png" height="85%" width="85%" alt="Insert 39 into URL url"/>
<br />
I save the file once the changes are made and run it again. Success, the 200 Response code is what I was 
striving for!
<br />
<img src="https://i.imgur.com/CoUaciX.png" height="85%" width="85%" alt="Successful 200 response from machine"/>
<br />
I navigate back to the Firefox window on the victim machine, logged in as Samy. I was already viewing Alice's profile before executing the <b>HTTPSimpleForge</b> program. I refreshed the page and now I see the option to remove Alice as a friend. I don't remember adding that user in the first place. I go the to the Activity page on the website and lo and behold:
<br />
<img src="https://i.imgur.com/8SWgdIZ.png" height="85%" width="85%" alt="Samy is now a friend with Alice"/>
<br />
<h3>Countermeasures</h3>
Now, I will perform some configurations to see the built-in countermeasures Elgg has to defend against the XSS attacks I've procured throughout this demonstration. The first countermeasure I will activate is a custom-built security plugin, <b>HTMLawed 1.8</b>, which is on the Elgg website application itself. To activate it, I simply log in to the Elgg application as an administrator and activate it from the administrator settings.
<br /> <br />
I will start by logging out of Samy's Elgg account on the victim machine and I will log in as an administrator.
<br />
<img src="https://i.imgur.com/oGxnry7.png" height="75%" width="75%" alt="LOG OUT OF SAMY'S SESSION"/>
<br />

<br />
<img src="https://i.imgur.com/VlB5Zph.png" height="85%" width="85%" alt="LOG IN AS ADMIN"/>
<br />
Once I'm logged in, I click <b>Administration</b> on the top menu (blue ribbon) > locate the right panel and click plugins > select <b>Security and Spam</b> in the dropdown menu > click <b>Filter</b>.
<br />
<img src="https://i.imgur.com/aKmuNfU.png" height="80%" width="80%" alt="CLICK PLUGINS UNDER CONFIGURE"/>
<br />

<br />
<img src="https://i.imgur.com/REnY0N0.png" height="85%" width="85%" alt="ACTIVATE HTMLAWED 1.8"/>
<br />
Now that the plugin is activated. I want to demonstrate its functionality against the first XSS attack I attempted. I will repeat the process for Task 1 to create an alert window with JavaScript. I enter the code into the '<b>Brief description</b>' field and click <b>Save</b>.
<br />
<img src="https://i.imgur.com/7Ffra9v.png" height="60%" width="60%" alt="Attempt alert window XSS attack"/>
<br />

<br />
<img src="https://i.imgur.com/7Ffra9v.png" height="60%" width="60%" alt="Failed XSS attempt with Alert window on brief description"/>
<br />
It seems that input validation countermeasures has kicked in. The input JavaScript code is now output set as regular plaintext and there is no alert window in sight. Now, I will attempt to do the same thing with the process to display the user's cookies in an alert window.
<br />
<img src="https://i.imgur.com/kBSExGz.png" height="50%" width="50%" alt="Cookie display XSS attack attempt"/>
<br />
<br />
<img src="https://i.imgur.com/LBlUeH9.png" height="50%" width="50%" alt="Cookies XSS successful failed attempt"/>
<br />
<br />
Once again, the input validation from the plugin is functioning well against my cross-site scripting efforts. <br /> <br />
There is one more countermeasure, a built-in PHP method called <b>htmlspecialchars()</b>, which is used to encode the special characters in user input, such as encoding "<" to "&lt, ">" to "&gt", etc. The function call, <b>htmlspecialchars</b> can be found in <b>text.php</b>, <b>tagcloud.php</b>, <b>tags.php</b>, <b>access.php</b>, <b>tag.php</b>, <b>friendlytime.php</b>, <b>url.php</b>, <b>dropdown.php</b>, <b>email.php</b>, and <b>confirmlink.php</b> files. I will attempt to activate this countermeasure by uncommenting the <b>htmlspecialchars</b> function call(s) in each file. I can find the path to the <b>/var/www/xsslabelgg.com/elgg</b> directory provided in the '<b>Advanced Settings</b>' page in the <b>Administration</b> page on the Elgg web application.
<br />
<img src="https://i.imgur.com/XEQhOY7.png" height="90%" width="90%" alt="/var/www/xsslabelgg.com/elgg location on Admin page"/>
<br />
On the vuln-site machine, I will navigate to the provided directory and find my way to <b>/var/www/xsslabelgg.com/elgg/views/default/output</b>.
<br />
<img src="https://i.imgur.com/j22ojkz.png" height="90%" width="90%" alt="/var/www/xsslabelgg.com/elgg/view location"/>
<br /
<br />
<img src="https://i.imgur.com/R2ADKOY.png" height="95%" width="95%" alt="/var/www/xsslabelgg.com/elgg/view/output location"/>
<br />
I will attempt to edit the various <b>.php</b> files by uncommenting the <b>htmlspecialchars()</b> function call to activate the second custom-built countermeasure. <br /> <br />

<b>text.php</b>
<br />
<img src="https://i.imgur.com/9c3riPO.png" height="95%" width="95%" alt="text.php uncommenting"/>
<br />
<br />
<img src="https://i.imgur.com/Kopsjmk.png" height="95%" width="95%" alt="text.php uncommenting"/>
<br />
<br />
<img src="https://i.imgur.com/VHBV8BH.png" height="85%" width="85%" alt="text.php uncommenting"/>
<br />
As expected, it may be difficult to edit all of these <b>.php</b> files with varying levels of permission. So, I might not be able to edit any of the previously listed <b>.php</b> files due to permission denial.
<br />
<img src="https://i.imgur.com/9V0GtEL.png" height="85%" width="85%" alt="tagcloud.php uncommenting attempt"/>
<br />
<br />
<br />
<b>confirmlink.php</b>
<br />
<img src="https://i.imgur.com/ihNnkg8.png" height="85%" width="85%" alt="confirmlink.php uncommenting attempt"/>
<br />
<br />
<img src="https://i.imgur.com/1FowfKq.png" height="85%" width="85%" alt="confirmlink.php uncommenting attempt"/>
<br />
<br />
<img src="https://i.imgur.com/r4gOVfx.png" height="85%" width="85%" alt="confirmlink.php uncommenting attempt"/>
<br />
Nonetheless, uncommenting where I was attempting would've enabled encoding countermeasures against XSS attacks. Elgg will look at certain special character input coming into the application and ensure that the output of that is properly encoded to avoid the consequences of poor input validation.

<h3>Conclusion</h3>
This experience has increased my understanding of cross-site 
scripting attacks and gain somewhat of a hands-on experience with methods used to compromise 
victim machines. I find this heavily relevant to real-world security because it’s critical for those 
defending against these attacks to understand the tactics, techniques, and procedures that 
attackers use to undermine web application flaws and vulnerabilities. The effectiveness of XSS 
techniques tools depends on the web application. If the web application has poor input validation 
with a lack of adequate security countermeasures, then a cross-site scripting attack would be very 
effective. 
