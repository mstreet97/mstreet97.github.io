---
title: TryHackMe MrRobot Writeup
author: mstreet
layout: post
---
# Introduction
This is my first time putting together a writeup, so I opted for a widely known (and actually really well documented already) TryHackMe room, just to get a feeling and becoming familiar with this. Feel free to shoot me a comment with suggestion or critiques, they will be gratly appreciated!

# Enumeration and Scanning
As usual we start off with a nmap scan. After scanning all the ports with we find ssh, http and https.

```bash
# Nmap 7.80 scan initiated Thu Sep 24 09:32:05 2020 as: nmap -sS -n -Pn -p- -oN tcp_all 10.10.201.145
Nmap scan report for 10.10.201.145
Host is up (0.21s latency).
Not shown: 65532 filtered ports
PORT    STATE  SERVICE
22/tcp  closed ssh
80/tcp  open   http
443/tcp open   https
```

More specifically we can also enumerate the services running on those ports.

```bash
# Nmap 7.80 scan initiated Thu Sep 24 09:46:03 2020 as: nmap -sV -n -Pn -p22,80,443 -oN svc_all 10.10.201.145
Nmap scan report for 10.10.201.145
Host is up (0.081s latency).

PORT    STATE  SERVICE  VERSION
22/tcp  closed ssh
80/tcp  open   http     Apache httpd
443/tcp open   ssl/http Apache httpd
```

So, a couple of websites are there, let's check them out!
After a quick glimpse there seems that the websites are the same, running on the two protocols http and https, so we can concentrated on either of them for now. 
We can see that te website features an interactive shell, with different options which result in different actions, e.g the option "join" lets the user put in an email, to which Elliot will contact him. 
Really awesome content if you are a fan of the show, but unfortunately there doesn't seem to be much to do with those option. We need to investigate deeper into the website. Let's check out the robots.txt.
The robots.txt had two entries:
- fsocity.dic which is a word dictionary (and a big hint on what to do next)
- key-1-of-3.txt, which is out first flag  
Let's get the first flag then!

<img align="center" src="/assets/images/thm_mr_robot/key1.png">

Time to move on. We still need some way to get a shell into the machine. Checking the webpage source, we see something at line 15.

<img align="center" src="/assets/images/thm_mr_robot/js.png" style="height:80%;">

It seems that there is a webpage available (index.html) accessible by a specific IP. Let's run a gobuster then.
We find different folders and also files related to wordpress. 

<img align="center" src="/assets/images/thm_mr_robot/gobuster.png">

# Exploitation

Browsing to IP/wp-login gets us the access page. Now, we can try to bruteforce the login with the wordlist we found before. Knowing that in the show MrRobot is Elliot Alderson, it makes sense to try some common usernames. Let's go with 'Elliot'.
Using wp-scan, with the commands: "--url http://IP --usernames 'Elliot' --passwords fsociety.dic", we are able to bruteforce Elliot's credentials.

<img align="center" src="/assets/images/thm_mr_robot/wp_creds.png">

Aaand we're in!

<img align="center" src="/assets/images/thm_mr_robot/wp-in.png" style="height:80%;">

Since we have an admin account, we can exploit the wp admin dashboard by inserting in a php theme a reverse shell, which gets executed when the webpage associated to it gets loaded.
We copy one of the various php-reverse-shells (I used /usr/share/webshells/php/php-reverse-shell.php) and modify its content setting our own ip and port.
Next we copy the php reverse shell into a page, for instange 404.php set up a listener, load the page and we get the shell!

<img align="center" src="/assets/images/thm_mr_robot/revs_arrived.png">

# Privilege escalation

We are finally in as user daemon. After searching around we get into robot's home dir in which we find the second flag and a md5 of robot's password.
Unfortunately, to see the second flag we need to crack the md5 hash first.

<img align="center" src="/assets/images/thm_mr_robot/robots-home.png">

There are various techniques to crack the hash, hashcat and john will do, but I went for crackstation instead, and we find robot's password! 

<img align="center" src="/assets/images/thm_mr_robot/crackstation.png" style="height:80%;">

Now we just need to switch user to get the second flag.

<img align="center" src="/assets/images/thm_mr_robot/key2.png">

Now, the third flag is probably located in root's home directory. As such we need to escalate our privileges. Giving a sudo -l we se that we cannot run any command as root, we need to look another way.
Looking for suid binaries, we see nmap.

<img align="center" src="/assets/images/thm_mr_robot/suid.png">

Nmap's interactive mode is perfect for privilege escalation.

<img align="center" src="/assets/images/thm_mr_robot/nmap_privesc.png">

Finally, since we are root we can get the third flag!

<img align="center" src="/assets/images/thm_mr_robot/key-3.png">

# Conclusion
That's all for this room, it's been a fun and easy room, and I enjoyed a lot the MrRobot theme!