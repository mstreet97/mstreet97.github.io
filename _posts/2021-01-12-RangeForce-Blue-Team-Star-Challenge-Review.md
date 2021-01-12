---
title: RangeForce and Blueteam Star Challenge 2020 Review
author: mstreet
layout: post
---
# Introduction
I discovered RangeForce after wandering on LinkedIn and stumbling upon one of my connection posts. It immediately caught my attention as it was something different than the typical InfoSec training. There are a lot of awesome resources on the red side, like HackTheBox, TryHackMe and PentesterLab just to name a few, but such types of environments oriented toward the blue side, are more difficult to find. Since the end of last year and for the next year I will be working on some projects which involve knowledge also of the blue side, which I am almost ignorant of, I decided to look more into RangeForce.

<img align="center" src="/assets/images/blueteam_star_challenge_2020/rangeforce_logo.png" style="width:80%;">

# What is RangeForce?
As stated on their website: "RangeForce is a scalable cloud-based platform providing hands-on measurable simulation training for cybersecurity and IT operations professionals." The description basically says it all: users accessing RangeForce are provided with courses composed by several modules. Each module has an associated learning material, which thoroughly explains and teaches what is needed to know to complete the modules' exercises. Each module has either multiple choice questions or hands on exercises to be completed (most of them are actually hands on).
The cool part about RangeForce modules is that they are accessible from their website. Once you decide for a module to do, you just need to start it and a full virtual environment will be set up, giving access to the Virtual Teaching Assistant (VTA), which guides you through the lab, and full fledged targets and OS to work with directly from your web browser. At first I was skeptical about this approach, as I'd tried some equivalent competitors and was never able to fully use such a RDP like system, especially with my unreliable internet connection. In this matter RangeForce pleasantly surprised me, as everything worked smoothly and without the hassle due to using a VPN and my own system.

# Community Edition
Another cool thing about RangeForce is that they provide 20 modules for free. In fact, by signing up to the community edition, everyone can access various modules about DevOps, Microsoft Security, Tools used in the SOC and Web Application Security. This is an awesome way to get a sneak peek of what is offered and the quality of the materials. I actually completed only those which I had previous experience in: I wanted to see how in depth the materials went. I was extremely happy to see that I still learned something new from the exercises!
If you want to try it out, give it a go for free [link](https://go.rangeforce.com/free-cyber-security-training-community-edition)!

# Blueteam Star Challenge
When I signed up for the free Community Edition (9th December 2020) I received an email shortly after about the Blueteam Star Challenge. Basically the Blueteam Star Challenge is a competition lasting four weeks from the 11th December 2020 to the 10th January 2021 composed of three challenges heavily blue team oriented: 
- Threat Intel Challenge: Determine where potential threats exist and who tampered with a website’s source code.
- Obfuscation Challenge: Investigate and unravel a targeted attack against your company’s infrastructure.
- Multi-Attack Challenge: Work to protect your organization against a complicated series of targeted attacks.

To give a more deep insight on the challenges, in the first a breach to a webserver had to be investigated and traced back to its origin thanks to the log analysis performed with Splunk. The Obfuscation instead had a piece of malware written in powershell that had been obfuscated with various techniques and needed to be un-obfuscated. Finally, in the Multi-Attack you were thrown into a live environment with multiple attacks going on and which you needed to stop: a phishing campaign, some bruteforcing attempts against a ssh server and finally a mass port scan. These three attacks were completed using various tools, but mainly: iptables, Suricata and fail2ban.

The cool part is that signing up for the challenge is free and there were prizes for the participants, in particular:
- Cyber-elite Prize: The first 100 competitors to complete all three challenges will win a $100 Amazon Gift Card.
- Range Rockstar Prize: The first 500 competitors to complete at least two challenges will win a Blue Team Star Challenge T-shirt.
- Participation Prize: All competitors who complete at least one challenge will receive a Blue Team Star Badge and CPE certificate.

So, as I previously said, I didn't have any knowledge about blue teaming, but I decided anyway to give the challenge a go, and see if I could at least get the t-shirt. I quickly gave a look to the free modules about the SOC tools in the community edition and on Saturday 12th December at 10 in the morning I sat down to tackle the challenge. Roughly by 19 in the evening I was done: I had completed all three challenges (compensating my inexperience and lack of knowledge with lots of googling and learning on the fly)! Those challenges were tough but so much fun, with the last one, the Multi-Attack Challenge, taking me almost 7 hours alone to complete. I definitely enjoyed the challenge but even more, I discovered the Blue side of cybersecurity and how much fun it can be!
When the leaderboard came out I was on cloud nine discovering that I was the 11th overall to complete all three challenges!

<img align="center" src="/assets/images/blueteam_star_challenge_2020/blueteam_star_leaderboard.png" style="width:80%;">

# Individual Learner Pathway
The Community Edition was great, the Blueteam Star Challenge was challenging and fun, and I discovered a new possible career pathway on the Blue Team, so what now?
I inquired with RangeForce about how a paid membership works. We scheduled an exploratory call in which the various features of RangeForce were presented to me and also future plans, in particular their Battle Paths. Battle Paths are RangeForce own CREST standard certifications, issued by YouAcclaim. They are awarded to those who can successfully complete the associated battle path, such as: SOC1, SOC2, ThreatHunter, OWASP and (soon) Penetration Testing. These battle paths are valid for two years and are awarded upon completion without additional costs, to renew them after expiration, you just need to complete again the associated challenge at the end of the battle path. Regarding costs RangeForce offers access to their full catalog of modules for 1500$ a year, which is a competitive price, but, and this is the cool feature, at this time they are offering two full battle paths, e.g. SOC 1 and SOC 2, for 250$ year. Even better, if you are a student ( and if you can provide proof of enrollment at a higher education institute) access to all their modules and certifications costs only 150$ a year. To me such an offer was a no-brainer, so I instantly signed up! Now I'm completing the Owasp Battle Path, but once I'm done I'll go for the SOC1/2 and ThreatHunting Battle Paths, as they will be invaluable to start my upcoming projects having already accumulated some experience on the blue side!

# Conclusion
RangeForce is for me an awesome resource to learn and train in cybersecurity. I like that their material is both for red and blue teams, but anyway more leaning on the blue side, which, given how few are blue team training out there compared to red team training, it is definitely a plus. Furthermore, in my opinion, you cannot attack efficiently without knowing first how to defend yourself, so I really find blue knowledge valuable also for a red teamer. Their flexible training platform simulating real-time attacks is something unique and as such I recommend everyone to check them out!
