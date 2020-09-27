---
title: TryHackMe Relevant Writeup
author: mstreet
layout: post
---
# Introduction
I've been following the Offensive Pentesting training path in TryHackMe while preparing for the eCPPT exam. I finally got to the Advanced Pentesting section and tried the "Relevant" room. This has been awesome and extremely instructive, as it thorougly tests your enumeration skills and also features a typical windows privilege escalation technique, but with a quite new implementation.

# Enumeration and Scanning
We start of with a quick nmap scan on the most used 1000 ports with "nmap -sV -Pn -n IP", before launching a more thorough one.
```bash
80/tcp   open  http          Microsoft IIS httpd 10.0
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds  Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
3389/tcp open  ms-wbt-server Microsoft Terminal Services
```
We find out that we have a Windows machine, nmap suggests some version of window server that is running a website, IIS10, smb shares and rdp enabled.
While the full port scan runs in the background we can take a look at the website. Nothing special, it seems the default Microsoft IIS installation. Also checking with gobuster for commond directories which unfortunately yields nothing interesting.

Time to check the samba shares. Using "smbmap -H IP" we find a folder, nt4wrksv, to which we can connect through anonymous login.  
<img align="center" src="/assets/images/thm_relevant/smb_open_share.png" style="width:80%;">

Inside it we find a username and password list, encoded as base64.  
<img align="center" src="/assets/images/thm_relevant/password.png" style="width:80%;">

We proceed in decoding them, and we get:  
<img align="center" src="/assets/images/thm_relevant/decoded.png" style="width:80%;">

We can now try them, use impacket's psexec.py utility (alternatively you can also use Metasploit's PsExec module).  
Bob:  
<img align="center" src="/assets/images/thm_relevant/bob_fail.png" style="width:80%;">  

Bill:  
<img align="center" src="/assets/images/thm_relevant/bill_fail.png" style="width:80%;">

Both these credentials don't work. Bob seems a legit user, but cannot connect, while Bill does not seem to be an actual user.
Not much left to do as far as I know, luckily the full port scan has finished and we have found something new.
```bash
49663/tcp open  http    Microsoft IIS httpd 10.0
49667/tcp open  msrpc   Microsoft Windows RPC
49668/tcp open  msrpc   Microsoft Windows RPC
```  
There seem to be another webserver running on a high port (49663), using IIS as the other one. When browsing it, it also shows default IIS webpage. Let's directly try with gobuster with the list directory-list-2.3-medium.txt.  
We find a subdirectory with the same name as the one we found open while enumerating smb: nt4wrksv.
<img align="center" src="/assets/images/thm_relevant/gobuster.png" style="width:80%;">

It could be the same directory and with a bit of luck we could have anonymous write permission to it. We can do a simple check, uploading a text file to the smb share:  
<img align="center" src="/assets/images/thm_relevant/test1.png" style="width:80%;">  

Browsing it via the website to display its content:  
<img align="center" src="/assets/images/thm_relevant/test2.png" style="width:80%;">  

# Exploitation
We are lucky and it works! We can exploit this feature by uploading a reverse shell and setting up a listener on our machine. Remember that Microsoft IIS uses asp as language so we should use a aspx shell. I used the one from [borjmz's repo](https://raw.githubusercontent.com/borjmz/aspx-reverse-shell/master/shell.aspx).  
We so set up our netcat listerner, upload the .aspx reverse shell and call it by browsing the website at the uploaded location.   
We got our shell!  
<img align="center" src="/assets/images/thm_relevant/revs-arrived.png" style="width:80%;">  

We can get Bob's flag in his Desktop.  
<img align="center" src="/assets/images/thm_relevant/user_location.png" style="width:80%;">  

Now, time to escalate to root. Looking at the privileges, we find that we have the SeImpersonatePrivilege enabled.  
<img align="center" src="/assets/images/thm_relevant/service_account_privs.png" style="width:80%;">

# Privilege Escalation
A quick googling points at some known privesc exploit under windows, RottenPotato and its variants, like JuicyPotato.
Anyway, looking around better I stumbled upon this [article](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/), which also exploits the SeImpersonatPrivilege, but is more recent (and to me it seems simpler to use). Let's try it out.
Following the article, we compile the source code of PrintSpoofer and upload it to the victim machine by setting up a python webserver on our machine and using certutil.exe to download it.  
<img align="center" src="/assets/images/thm_relevant/webserver.png" style="width:80%;">  

<img align="center" src="/assets/images/thm_relevant/ps-downlaod.png" style="width:80%;">  

After uploading we just need to run PrintSpoofer.exe -i -c powershell to get our powershell ad NT AUTHORITY\SYSTEM.  
<img align="center" src="/assets/images/thm_relevant/privesc.png" style="width:80%;">

Finally we are done and we can just get the Administrator flag!  
<img align="center" src="/assets/images/thm_relevant/root.png" style="width:80%;">

# Conclusion
As they always say, enumeration is key and in this room it is particularly evident. The other lesson this room teaches is that you always have to look for low hanging fruits, they might not work straight out of the box, but be of extreme value later!