---
title: A 2024 Review of OffSec's PEN-300 Advanced Evasion Techniques and Breaching Defenses
date: 2024-10-31 17:00:00 +0200
categories: [Ramblings]
tags: [reviews]     # TAG names should always be lowercase


description: My review of the current state of OffSec's PEN300 Course and Exam.
---

# A 2024 Review of OffSec's PEN-300 Advanced Evasion Techniques and Breaching Defenses

<p align="center">
 <img src="/assets/img/osep.logo.svg" alt="OSEP Certification Badge" width="520" height="600" />
</p>

## Introduction

> OffSec’s PEN-300 course explores advanced penetration testing techniques against hardened targets. Learners gain hands-on experience bypassing security defenses and crafting custom exploits in real-world scenarios, enhancing their expertise in ethical hacking and vulnerability assessment.

That's how the introduction goes for the _Advanced Evasion Techniques and Breaching Defenses_ course, which is the successor to the famous _Penetration Testing with Kali Linux_ or maybe better known as the PEN200 OSCP course.

Last year (2023) I attempted and obtained my OSCP certificate, for me it was the logical next step to look at the advanced level certification OSEP. Now after finishing the course and obtaining my OSEP credentials I can look back and let my mind wander a bit on how and what did I think of the course. A good thing to keep in mind is that in between OSCP and OSEP, I have taken Rasta's [Red Team Operator](https://training.zeropointsecurity.co.uk/courses/red-team-ops) Course which also provided me with some interesting perspectives that I took with me in this course.

## The Course Materials

Before we start with the review of the course let's address a concern that is on the mind of a lot of aspiring students. 

Aspiring students often read questions on various forums or discord servers regarding the validity or age of the course materials. While it is true that no major updates have been done to OSEP; that are comparable to the ["Big 2023 OSCP Overhaul"](https://www.offsec.com/blog/pen-200-2023/) or the more recent [introduction of OSCP+](https://www.offsec.com/blog/everything-you-need-to-know-about-the-oscp-plus/), there are smaller iterative updates to the individual learning modules within the course as recent as August 2024. 

Maybe it's also good to address that the _Advanced Evasion Techniques and Breaching Defenses_ is not a copy paste this command or this piece of code course, that you might expect from previous courses. Often you see courses that are learning you a specific technique and a specific way how to perform that specific technique, but what if you are in a situation where that specific way of executing is not possible but the technique itself could still be of value ? That is the space where I think the _Advanced Evasion Techniques and Breaching Defenses_ fits the best. The course will not introduce you to the latest exploits and how to execute them or how to do a modern EDR evasions instead it will teach you the concepts for advanced evasion and bypass techniques and how to execute these technique's successfully in a hardened environment. 

## The Learning Experience

This biggest learning this course will provide you is *Adaptability*, the adaptability to adjust or apply techniques depending on the situation. Let's first start with the [Syllabus](https://www.offsec.com/documentation/PEN300-Syllabus.pdf), which surprisingly doesn't cover all the learning modules in the course, so below you can find the currently (October 2024) active modules in the course:

|||
|--|--|
|Operating System and Programming Theory|Client Side Code Execution With Office|
|Client Side Code Execution With Windows Script Host|*Reflective Powershell*|
|Process Injection and Migration|Introduction to Antivirus Evasion|
|Advanced Antivirus Evasion|Application Whitelisting|
|Bypassing Network Filters|Linux Post-Exploitation|
|Kiosk Breakouts|Windows Credentials|
|Windows Lateral Movement|Linux Lateral Movement|
|Microsoft SQL Attacks|Active Directory Exploitation|
|*Attacking Active Directory*|Combining the Pieces|

The structure of these modules is different and might make some of the new fresh out of OSCP students frown a bit. Only the learning module "Attacking Active Directory" has the same style the OSCP learning modules. This module contains questions you need to answer by submitting a flag or a specific answer that you get while doing the exercise providing you the same experience as the Learning modules in OSCP. All the other modules are also having "Exercises" and "Extra Mile" objectives with the difference that you do not need to verify your answers or actions, which also unfortunately results in a lot of students skipping those. I personally would highly recommend doing the exercises of each module including the extra mile ones, because doing this will leave you at the end of the course with various Loaders and boilerplates to further work on and prepare for the exam.

The course is divided in two parts, the first part which basically focusses on the development of exploits and evasion techniques by leveraging VBA, JS, C# and PowerShell and the second part which focusses on the attacking different environments. Especially the first part was pretty rough for me since I never picked up a programming or scripting language, the course did a fine job guiding me through this part and providing the information needed to understand the concepts.

During the second part of the course I could definitely speed up the pace because I was feeling much more comfortable with that. The course leverages the Metasploit Framework heavily for catching reverse shells and generating payloads but; because of my experiences with the Red Team Operator course, I disliked the workflow in Metasploit, I opted to do this course not with Metasploit but with SliverC2. This also meant I needed to translate the concepts to something else then Metasploit further reinforcing the concepts and applicability, but also reevaluating the code i was writing in various loaders during the course.

I feel this reinforcement enabled me and prepared me more then enough to tackle Challenge Labs, that would follow after you finish the learning modules.

Now we are on the subject of the challenge labs, the course has 6 challenge labs and these are best done in order, with the very temping names of Challenge 1 to 6. These 6 labs are best done in order. While the order is not mandatory, you do see that you are tested in each lab on general knowledge and specific course topics slowly building experience and confidence to tackle the exam. Since I was using SliverC2, this gave me the opportunity to test things in the lab and further hone the techniques before stepping into the exam.

I highly recommend reading and understanding the following article

[How to Tunnel and Pivot Networks using Ligolo-ng](https://software-sinner.medium.com/how-to-tunnel-and-pivot-networks-using-ligolo-ng-cf828e59e740)


## The Exam

So the exam, maybe one of the most interesting things to talk about and also the most restrictive one. The exam objective is to exploit the corporate network and compromise the designated critical asset while providing proof of exploitation. There are a few ways to pass the exam, one way is to compromise that designated critical asset and obtain the `secret.txt` and the other way is to reach a 100 points by submitting `local.txt` or `proof.txt`. 

Without going into too much details I found this exam extremely fun to-do, it simulates a real environment and it also feels as if you are doing an active engagement for a customer. Something that makes it feel much more realistic and "real world" and will definitely be a step up from the OSCP exam. As usual OffSec has strict requirements on how to submit those points and to provide screenshots, failure to adhere to these requirements per submission automatically result in 0 points awarded.

My exam was scheduled to be started at 08:00 in the morning which meant at 07:45 logging in the OffSec exam environment for the pre exam verification checks and getting ready for the 48 hour exam. After all the checks were done, I got the email with the exam VPN details and could start my exam. It was fairly quick that I had initial foothold and could start progressing in the environment, I was able to keep a steady pace and maintain a a good flow avoiding Rabbit holes as much as possible. One of the key aspects that helped me tremendously during this exam but also during my OSCP exam is time management.

I was rigorously following the time table that was proven to be so successful during my OSCP exam, every 90-120 minutes take a break, just grab a cup of coffee, tea, water or a snack. Take a proper lunch/dinner away from your keyboard and go for a walk. This provided some relaxation in a tense exam keeping my mind healthy and sharp and my body from cramping up or long periods of just sitting. I believe this is the number one successfactor for me when taking these type long exams and helping me avoiding the mentioned Rabbit holes.

## Lessons Learned 

So maybe to conclude this post a small overview of what I think are the most valueable during the course and exam.

- Do the course challenges, not only the regular ones but also the extra mile ones. Especially the extra mile ones are going to give you a lot of insights and learnings.

- Programming knowledge helps, but is definitely not mandatory. The course provides you with everything you need to pass the exam.
- Make use of Discord, the student channels for the course are a very welcoming and very valuable. The interaction with students and Alumni challenges you to come up with the solution yourself instead of somebody pasting it to you, actively forcing you to learn and understand the concept instead of copy paste this solution.
- After you finish the course and Challenge labs you should be ready for the exam, however if you want to practice more in a Active Directory environment I can highly suggest using [Game of Active Directory](https://github.com/Orange-Cyberdefense/GOAD) this is a free environment you can run locally.
- Time management, severely helped me during my exam. Best is to come up with a plan before you exam and follow it, ensuring you take regular breaks and time away from keyboard. These breaks can be however long you need them to be also make sure you take breakfast/lunch/dinner away from your desk.
- Notes, maybe the important of all. Take notes, extensive notes. During the course, during your challenge labs, documenting and describing what works, why it works, or it doesn't not. Extensive notes will ultimately help you learn better but also provide you a way to keep track on your task and not fall into those rabbit holes.