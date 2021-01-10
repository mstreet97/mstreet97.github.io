---
title: HackTheBox Tabby Writeup
author: mstreet
layout: post
---
# Introduction
Let's pwn Omni! This HTB machine is listed with "other" as OS so I don't really know what to expect, but I'm curious to find out!.

<img align="center" src="/assets/images/htb_omni/omni_logo.png" style="width:80%;">

# Emuneration
We start off with the usual nmap scan and find open port 135, 5958 and 8080.

```bash
Nmap scan report for 10.10.10.204
Host is up (0.035s latency).

PORT     STATE    SERVICE VERSION
135/tcp  open     msrpc   Microsoft Windows RPC
5958/tcp filtered unknown
8080/tcp open     upnp    Microsoft IIS httpd
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2008|7 (85%)
OS CPE: cpe:/o:microsoft:windows_server_2008::sp1 cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7
Aggressive OS guesses: Microsoft Windows Server 2008 SP1 or Windows Server 2008 R2 (85%), Microsoft Windows 7 (85%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

We see, and nmap gives confirmation, that the OS is for sure Windows, but we don't have a reliable indication.
Port 135 has rpc but when trying to connect to it, it times out. 
Port 5958 results as unassigned and as such nmap is not able to identify it. 
Finally, port 8080 shows a webserver running.

Browsing to the webserver, we are greeted with a basic http authentication for which we don't have credentials. Seems like a dead end... Looking closer at the auth form of the webserver though we see "Windows Device Portal". A quick google search tells us that the "The windows device portal lets you configure and manage you device remotely over a network. It also provides advanced diagnostic tool to help you troubleshoot and view the real-time performance of you Windows device".

<img align="center" src="/assets/images/htb_omni/omni_basic_auth.png" style="width:80%;">

# Exploitation

It seems clear now that we are dealing with an IoT device running some flavour of Windows. Now, knowing that in IoT the S stands for security, there might be some exploit laying around for this specific system. 
Simply googling "windows device portal exploit" points to this github link: https://github.com/SafeBreach-Labs/SirepRAT.
After completing the installation as instructed in the readme, we can use the tool.

After trying out a couple of commands listed in the README of the repo, we can get some system information about the device.

<img align="center" src="/assets/images/htb_omni/omni_sysinfo.png" style="width:80%;">

Since we have RCE we can now upload a netcat executable. So, we setup a python server and run the following command to invoke a webrequest with powershell to download the executable.

<img align="center" src="/assets/images/htb_omni/invoke-webrequest.png" style="width:80%;">

We can see that the uplaoded file works.

<img align="center" src="/assets/images/htb_omni/uploaded.png" style="width:80%;">

Finally, we can call a reverse powershell! (Note: I got stuck here for quite some time because I was trying using the 32bit nc binary, after switching to 64bit everything worked fine).

<img align="center" src="/assets/images/htb_omni/reverse_shell.png" style="width:80%;">

And we can check that we are running our shell as System!

<img align="center" src="/assets/images/htb_omni/privileges.png" style="width:80%;">

We can try to get the user.txt by navigating to C:\Data\Users\App

<img align="center" src="/assets/images/htb_omni/user.png" style="width:80%;">

Unfortunately, when trying to get the user.txt, we get returned an xml document containing the flag under the tag SS. 

<img align="center" src="/assets/images/htb_omni/secure_string.png" style="width:80%;">

Googling a bit around, we find a powershell method that is called ConvertFrom-SecureString, and ConvertTo-SecureString. In particular we would need to import the correct credentials with $creds = Import-CliXml -path C:\\Users\\app\\user.txt. The current credential of our shell don't work as we are in as the user omni. We so need to find a way to get a shell back as the users needed who anctually own the user.txt and root.txt, which, after enumerating the users on the system, are "app" for the user.txt and "administrator" for the root.txt.

# Enumeration (again!)

Moving on with enumeration, inside the PowerShell directory, we find a "PackageManager" which has been installed later than the other modules, and inside it we find a file r.bat containing credentials: administrator:_1nt3rn37ofTh1nGz and app:mesh5143.

<img align="center" src="/assets/images/htb_omni/rbat.png" style="width:80%;">

These credential work for the webpage at port 8080, and we can login into it as one of the found users!

<img align="center" src="/assets/images/htb_omni/windows_device_portal.png" style="width:80%;">

# Exploitation (again!)

After browsing around we can see that there is a way to run commands. Remebering that we have a nc uploaded on the machine, we can create another reverse shell with one of the users we're interested in (app/administrator)!

<img align="center" src="/assets/images/htb_omni/reverse_shell2.png" style="width:80%;">

Now, depending on which credential set we used to login (e.g. app or administrator) we will have a differen environment username, which allows us to view only the password associated to that specific user. So, to recap, we login as app. Note: in this case I had some problem when uploading the netcat executable inside C:\Windows\Temp, as it was working when using the shell as administrator but not for the user. Uploading netcat inside C:\Users\Public instead made it work for both of them.

<img align="center" src="/assets/images/htb_omni/revs_app.png" style="width:80%;">

Once in, using Import-CliXml --path APPROPRIATE_PATH, we load the user.txt as an Xml and then we can retrieve the password calling GetNetworkCredential().Password.
Here is it for the user.txt

<img align="center" src="/assets/images/htb_omni/user-txt.png" style="width:80%;">

Now on to root.txt. Remember, for the root.txt you need to do the same exact process as for the user "app": login to the website with administrator credentials -> call a reverse shell -> load credentials with Import-CliXml and the correct path and finally calling GetNetworkCredential().

<img align="center" src="/assets/images/htb_omni/root-txt.png" style="width:80%;">

# Conclusion

And that's the end! This has been a really fun box! The initial foothold was really straightforward, but I still managed to get stuck especially when trying to upload the netcat executable and then, once I got access to the webapp, in calling the shell as the "app" user (it continously said Access Denied). Anyway it was nice working with something that I had never seen before, both the OS and the SecureString implementation of the flags!
