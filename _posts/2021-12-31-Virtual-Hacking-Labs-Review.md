---
title: Virtual Hacking Labs Review
author: mstreet
layout: post
---
# Introduction
So, I took 6 months of "break" from certification in order to be able to finish my dissertation and graduate from the double masters' degree and UniTn and TUBerlin I was taking. After that I planned on taking the OSCP, that my company very kindly gifted me, but still I wanted to have some more preparation before that. After reading quite a few positive reviews for VHL I decided that going for the three months of VHL subscription would be a good idea, as I could finish it by the end of 2021, have fun and jump start my preparation for OSCP. 
<img align="center" src="/assets/images/vhl/logo.jpg" style="width:60%;">

# Course Content
The course is structured with a ~400 pages pdf that teaches the basic concepts of penetration testing. It covers everything that is needed from information gathering to enumeration, from exploitation to privilege escalation. The content was enough to get started and I found it to be very well made as it introduces every necessary concept in a very clear manner and from a high level perspective, diving deeper into other more critical areas. While I knew already more or less everything that was taught there, I still went back to the material every now and then when stuck on a specific machine. Each time I had to do this, I usually found some very good pointers in there and was able to get unstuck and proceed with exploitation. 
You can find a more broad overview on VHL's website, check it out [here](https://www.virtualhackinglabs.com/?courses=penetration-testing)!

# Labs
The real point of strength of this course is the lab. When I completed it, it contained 50 machines, with varying difficulties from Beginner, to Advanced to Advanced+. Beginner and Advanced machines contained hints to be used when stuck that were giving away just enough information to get unstuck but not to spoon feed the solution, which is something I greatly appreciated because you still get the feeling that you compromised the machine yourself and the hint was just "clearing your mind" a bit. Furthermore, Beginner and Advanced would contain referrers back to the course material which were extremely useful as well to point to the correct direction.
Advanced+ machines were instead plain fun: they did not contain any hint and were more difficult to tackle. There is an unofficial Discord server which contains forums on which fellow learners could still exchange some nudges when stuck, as not to render the whole study process tedious. Furthermore, the email assistance from the owners was on point: I emailed them because I was stuck with the 50th and last machine and they promptly got back to me, giving a very tiny nudge that put me in the correct direction (and after which I was the 7th overall to compromise that difficult machine). The lab environment is shared between students, but I've never encountered issues such as other users attempting the machines I was attempting, which is because VHL have a waiting list to provision the labs for every user, so that they guarantee that they do not become overcrowded. Lab access was provided with a VPN which was very fast and easy to use for me.  
<img align="center" src="/assets/images/vhl/lab-connection.jpg" style="width:80%;">

# Certification
The course offers two completion certificates: one is unlocked after compromising at least 20 machines and the other (advanced+) is obtainable after compromising at least 10 advanced+ machines plus two machines, of whichever difficulty, both in a manual and automated way: e.g. one time automatically with sqlmap, then another time manually with manual SQL Injections.

# Timeline
I got the 3 months access which has been more than enough to complete the 50 available machines. Overall I would say that it was even too much time for me and that 1 month would have been enough (albeit rushing the study process). I would still recommend the 3 months package for someone just getting started as it is a perfect way to learn and do everything without rushing.

# To who is it recommended
This course is fantastic for less technical people that want to get into more technical roles because it provides very hands on training. For more experienced people it might be a bit easy to do: in my case some machines were very straightforward, to the point that they took 15/20 minutes. I definitely feel though that I learned a lot and got more comfortable into doing exploitation manually without relying much on tools, which is basically why asked for this training in the first place, so I would say that the objective was achieved!

# Final thoughts
I can just confirm all the good other reviews that can be found online: the VHL team did a heck of a job for their labs! I would just add my final verdict as follows:
- Course Materials: 4/5. Very good but lacks videos, which someone, like me, might prefer, anyhow not a big deal.
- Labs: 5/5. Excellent machines that allow to build up knowledge in a gradual manner. Definitely real world oriented and not CTFish like some on HackTheBox or TryHackMe.
- Support: 5/5. Prompt and helpful, the associated discord channel was also a big plus.

Again, kudos to the crew at VHL: it was a fun learning experience that I feel definitely made me a better pentester. I will surely go back once new machine come into the picture!