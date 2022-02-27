---
title: Cyberwarfare Labs Red Team Analyst Review
author: mstreet
layout: post
---
# Introduction
After completing the eWPT I was looking for a cert that would give me some foundations on active directory as it had not been touched in the courses I had taken previously. I discovered Cyberwarfare Labs as they were just starting out and enrolled straight away in their Red Team Analyst course which was presented as a beginner red teaming course. It seemed an ideal to learn the basics before moving on to more difficult options such as CRTP from PentesterAcademy or the Red Team Specialist also from Cyberwarfare Labs.
<img align="center" src="/assets/images/ccrta/cwl-logo.jpeg" style="width:30%;">

# Course Content
The course includes a 170 pages pdf along with around 8 hours of videos going through the concepts explained in the slides. They give a broad overview of pentesting and some very quick info about the basics such as port scanning and web hacking as well as the basics of how a red team is conducted. Once exhausted those arguments the material dives directly into the fun part which is Active Directory. It provides an overview of how AD works, how kerberos is used for authentication parent-child and domain trusts. Then it goes through the basic enumeration of AD with PowerView, and its PrivEsc with PowerUp as well as attacks such as kerberoasting, pivoting via powershell remoting and persistence attacks such as golden/silver tickets and dcsyncs. 
You can find a more broad overview on Cyberwarfare's websice, check it out [link](https://www.cyberwarfare.live/courses/certified-red-team-analyst)!

# Labs
Now the labs were the point of strength of the whole course for me. In the material you go through setting up a local lab which is meant to get an idea of setting up an AD environment with a client a DC and an application server. This local lab is then used throughout the course to get familiar with with the TTPs explained and practice the concepts taught in the course. Finally, there is the online lab. For this there is a full video walkthrough which repeats all the course contents in a completely new environment, so that you get an idea on how to adapt the learned tactics to unknown environments. The lab was fun and while it was shared with other students, I never found it to be an issue. Access was through a vpn connection provided via openvpn and I found it to be quite fast which rendered the whole experience very enjoyable.  
<img align="center" src="/assets/images/ccrta/network-layout.png" style="width:80%;">

# Exam
The exam was a practical red teaming assessment to be done in 24 hours plus another 24 hours to write a report, with a structure much like that used by OSCP. I won't say how many machines as not to spoil anything but they were enough to simulate a company infrastructure and its extra and intra net. Cyberwarfare Labs state that you need a grade of at least 70% in order to pass the exam: I don't really know which is the grading metric though in the sense that I did not understand if it was the number of machines compromised vs the total, but I sense this might be the metric.
The exam overall was very fun! It was not too difficult if you study well the materials and practiced in the labs (at least to get to a passing grade) and it required a bit of creativity and thinking outside the box, especially to move between the machines. I got to the passing grade pretty fast, in around 7 hours, after which though I couldn't get to the "final" condition which marked the end of the exam with 100% mark. At that point I emailed the support to ask if that condition was really needed and if I was looking in the right place. The support promptly answered me with a hint that made me backtrack a bit my assessment and find another path that would eventually lead to the final condition. Still, I was not able to conduct the last exploit to get to said condition, but I learnt about a new exploit that was not covered in the course and used the last remaining time to try it. After the 24 hours ended, I put together the report which was basically a walkthrough of the exploitation process and sent it. The support answered that they would get back to me after 7 working days and actually after 5 I got the news that I passed, along with my shiny certificate and badge!

# Final thoughts
I didn't know of Cyberwarfare Labs before this experience, and I signed up basically blindly because they offered a beginner friendly and cheap option to start exploring red team tactics. I overall really enjoyed this course and honestly do not have anything to complain about. I will summarize the pros and cons as follows.
Cons:
- Just one, the slides material would maybe need slightly more polishing as there were a couple of typos here and there. Same reasoning goes for the videos.
Pros:
- I feel that this course provides an option that wasn't there before: a real beginner red teaming course, which gives a very gentle introduction to red teaming and it's perfect to be taken before either Cyberwarfare Labs' Red Team Specialist or PentesterAcademy's CRTP
- The price point is stellar: you get all the materials plus 30 days lab access (which is more than enough for me) for 99$, an offer that's hard to beat
- Cyberwarfare Labs gives the options to get the material straight after purchase but start the lab time at will at a later time. This was awesome as I bought the course in February but only started the lab in May. This provides great flexibility
- The support is very fast to answer and helpful!
- I especially liked that the support gave me a hint to get the last exam condition WHILE still doing the exam. This allowed me to discover another path of exploitation and learn other new techniques. Aside from this, it seemed to me that the crew at Cyberwarfare Labs really cared that their students were actually learning, than just "trying to pass the exam" and this is something I greatly appreciated (which is in contrast to the approach of other vendors for which passing the exam is the only thing that counts).

Overall, kudos to the crew at Cyberwarfare Labs: it was an awesome experience which I will surely repeat with one of their more advanced options on red teaming. They also have other interesting options offered on their website and I recommend to check them out!