---
title: What If I was building an Offensive Security Capability
date: 2025-11-13 07:00:00
categories: [Architecture]
tags: [ramblings]     # TAG names should always be lowercase

description: As organisations mature in their Cyber Security capabilities they quickly notice that structure and overlap are just around the corner. In this blogpost I let my mind wander on how larger organisations can implement and develop a Offensive Security Capability as next step in their Cyber Security strategy.

image:
  path: /assets/img/offseccap/header.png
  alt: What If
---
<br>
<center>

“Simplicity is the ultimate sophistication.”
<br>- Leonardo Da Vinci
</center>

<br>

## Introduction

Every organisation in the world is either having or developing a Cyber Security Capability to protect that organisation. You can outsource by buying managed services, you can do a best of both worlds by combining managed services with inhouse capabilities or you can have everything inhouse. The implementation model can vary however the goal is the same. This blogpost will focus on a inhouse/hybride model, while not being restricted to a specific sector of type of organisation.

> This blog started from a challenge question I received: 
>
>_"What if you had the opportunity to build an Offensive Security capability within a large organization say, 50,000+ employees? How would you design it, and how would you manage it?"_
>
> As a **disclaimer**, this scenario is purely hypothetical. It does not reflect my current employer or the work we do there. This is not a step-by-step guide or a recommendation to implement any specific tool or process. Rather, it is simply my perspective, thoughts and ideas on how I would approach building such a capability in a large organization. Consider it a collection of strategic ramblings from someone passionate about offensive security.

Especially the last part of that challenge question caught me fairly offguard, while I someday have the ambition to actually be a manager of such a team, it's not an easy question to answer. What type of Manager do I want to be ? What type of services would I like to deliver ? How would I build the team or teams around that ? How would those team(s) provide the most value to the organisation etc. So for that reason, I'm going to focus on how I would do that not on how I would manage that.

Let's strart with a bit of background on both sides.

## The Evolution of the "Blue Team".

When I first started in cybersecurity, a Security Operations Center, or SOC, was a very different place. It used to be a room full of screens and tired analysts working in tiers: Tier 1 handled alerts, Tier 2 dug deeper into suspicious activity, and Tier 3 tackled the really complex stuff. It was functional, but it wasn’t efficient. Analysts often drowned in alerts, processes were rigid, and knowledge stayed locked in silos.

Over the years, the cyber threat landscape changed. Attacks became faster, more targeted, and much harder to detect. The old tiered model couldn’t keep up. So, SOCs began to evolve. Instead of just watching and reacting, teams started to specialize. Incident Response professionals took charge when something went wrong, focusing on containing damage and restoring systems quickly. Forensic analysts started digging into digital evidence to understand how an attacker got in and what they did and Detection Engineers emerged, constantly improving the logic and tools that spot suspicious behavior in the first place.

Today, a modern SOC is much more collaborative, were the adoptation of automation is implemented to handle repetitive tasks, allowing analysts to focus on the more complex investigations. Different disciplines work side by side, sharing insights to stay one step ahead of attackers.

This collectively; or dance of disciplines, is reffered to as the "Blue Team", the defenders.

## The Evolution of the "Red Team".

The same goes for penetration testing, it was simple and direct. A client gave a scope, like this website or that subnet, you ran tools and manual checks, then delivered a report with findings and remediation steps. That model still has value, but as organisations got more complex and attacks became more targeted, the role of offensive security grew into a full discipline.

Mature offensive programs now include several specialist roles. Adversary emulation means recreating a specific attacker, with their tools and techniques, so defenders can see how they would fare against a real threat. Adversary simulation is similar but often runs continuously against many parts of the estate to test detection and response. Exploit development is about taking a weak spot and turning it into a reliable attack, which helps defenders understand worst case scenarios. The concept of Red teaming combines many of these skills into long, goal oriented engagements that test people, processes, and technology all at once.

Despite all that specialisation, the traditional penetration tester is still essential. Regular pen testers provide broad coverage, find common misconfigurations and business logic flaws, and validate fixes after remediation. They are specialists focussing on high risk, high impact concerns.

In a mature organisation these functions are coordinated. There is governance, clear rules of engagement, legal oversight, and integration with asset inventories and risk management. Automation and continuous testing feed findings into development pipelines so issues get fixed faster. Teams work with blue team counterparts in purple exercises to improve detection and response.

In short, offensive security was born and has shifted from discrete scoped tests to a layered ecosystem. Specialised experts emulating real attackers and building exploits, while regular penetration testers keep the day to day defenses healthy. Both are needed to reduce risk and improve resilience.

This collectively; or dance of disciplines, is reffered to as the "Red Team", the Attackers.

## What is a mature Offensive Security Capability.

In most organizations looking to build or implement a mature Offensive Security capability, the initiative is usually driven by their Blue Team reaching a certain level of maturity. The Blue Team needs Offensive Security professionals to validate detections, generate telemetry, and test the organization’s defenses.

Where it used to be the Offensive Team pushing the boundaries of the Blue Team, we now see that, at least on an organizational level, the Blue Team is often ahead. The Blue Team today is typically well-structured, with multiple disciplines under the same umbrella, strict procedures, clear expectations, and defined lines of communication when incidents occur.

In contrast, many Offensive Teams still operate with lower maturity, they are less centralized, less structured, and sometimes lack clearly defined processes. It’s clear that Offensive Security, as a practice, is still facing some maturity challenges.

In the same way the Blue Team grew into a structured, multi-disciplinary unit, the Offensive Security team is now following a similar path, developing its own specialized functions and expert roles. The most common ones are:

- Penetration Testers
- Adversary Emulation
- Adversary Simulation
- Exploit or Vulnerability Researchers

But isn’t Vulnerability Management also part of Offensive Security? After all, it deals with exploits and weaknesses too. Or what about specific Assessors roles? While each of these areas has its own value and purpose, I see them as separate disciplines and not part of the core Offensive Security capability.

If you want to focus on building a strong and mature Offensive Security function, you need to understand that it’s mostly about creativity and people. It’s about finding ways to break things, making systems behave in ways they weren’t designed to, and thinking beyond established guidelines, standards, and policies.

Let's dive a bit into the roles: 

- A Penetration Tester identifies vulnerabilities in systems, applications, and/or networks within a defined scope and time frame. Delivering a report to the requester about the tested asset with recommendations on how to address those.

- Adversary emulation tests an organization’s defenses by replicating the exact tactics, techniques, and procedures of a specific threat. Using a narrow, well-defined scope to mirror real attacker behavior, providing a focused assessment that strengthens defenses against that particular adversary.

- Adversary simulation is an approach that has a very broad scope and can act as an hypothetical threat actor. This approach helps organizations understand their capabilities and can also identify lesser-known blind spots.

- Exploit or Vulnerability Researchers are specialists who discover, analyze, and sometimes develop exploits for weaknesses in software, hardware, or systems. Their work involves deeply understanding how technologies function, identifying flaws that could be abused, and responsibly disclosing those issues to vendors or security teams.

## Building the Initial Offensive Security Capability

Building an Offensive Security capability doesn’t necessarily require dozens of teams or people. Often, these capabilities; I preffer calling them disciplines or specialisations, share overlapping knowledge, and it’s difficult to find and recruit those individuals who can do all four. If you try to, you’re essentially looking for unicorns it's like expecting a single Blue Team analyst to cover every discipline on their own.

The best approach starts by treating these disciplines the same way we treat the Blue Team. Place all the related disciplines within a single team so that knowledge can be shared effectively. Spreading them across multiple teams or departments increases overhead and, more importantly, reduces ownership, clarity, and accountability.

If asked what I would do; the question which started this blog, I would begin by combining the four disciplines into one team led by a single manager with clear priorities and deliverables. This structure also helps the organization identify the right people for the work, set priorities efficiently, and streamline the delivery of results but also manage the budget, tooling and licensing centralized. It eliminates also if Team A doesn't have time let's do it with Team B, while time or workload is often perceived as the instagator for this behaviour in an Offensive Security perspective it usually has a deeper reason instead of bypassing that team and finding somebody else to do it, we now can have a conversation why we can or cannot do that specific request.

Within this team, assignments can be organized strategically. One group can focus on Penetration Testing, while another handles the remaining three disciplines, with primary and secondary responsibilities clearly defined. This also creates a natural growth path for team members, allowing them to progress from Penetration Testing to Adversary Emulation or Simulation, and even to Exploit and Vulnerability Research.

Overall, this model builds an internal talent pool to support recruitment, development, and scaling in line with organizational needs.

### Team Growth and Responsibility Model

| Role | Primary Responsibilities | Secondary Responsibilities | Growth Path |
|------|-------------------------|---------------------------|------------|
| **Penetration Tester** | Execute penetration tests, identify vulnerabilities, produce test reports | Support Adversary Emulation exercises, assist in vulnerability research | Move into Adversary Emulation / Simulation or Exploit Research |
| **Adversary Emulation** | Simulate known attacker techniques, conduct red-team exercises | Participate in Penetration Testing engagements, contribute to Exploit Research | Progress to lead Adversary Simulation or specialize in Exploit/Vulnerability Research |
| **Adversary Simulation** | Create advanced attack scenarios, evaluate defenses against sophisticated threats | Support Penetration Tests and Emulation exercises, mentor junior testers | Lead large-scale simulation programs or transition to strategic security roles |
| **Exploit/Vulnerability Researcher** | Discover new vulnerabilities, develop proof-of-concepts, advise on mitigation | Assist Penetration Tests and Emulation exercises, contribute to simulation planning | Become a senior researcher or technical lead influencing multiple teams |

Now that we have a path and idea, we are just left with adding some engineers to the team to help maintain and develop the infrastructure to provide to the team and we should be ready to start out. 

## Scaling to a Offensive Security Team Structure

Following this model and approach also makes it easier to scale up even to a point where you can have multiple teams doing specialised tasks with relative ease. Structuring it in "Operational", "Research" and "Engineering".

#### 1. Operational Teams
Focus: Hands-on security testing, emulation, and simulation of adversary activity.

| Role | Primary Responsibilities | Secondary Responsibilities | Growth Path |
|------|-------------------------|---------------------------|------------|
| **Penetration Tester** | Execute penetration tests, identify vulnerabilities, produce reports | Support Adversary Emulation and Simulation exercises | Move into Senior Penetration Testing, Adversary Emulation, or Team Lead |
| **Adversary Emulation Specialist** | Simulate attacker tactics, techniques, and procedures in real-world scenarios | Assist Penetration Testing and support Simulation planning | Lead Operational Exercises or transition to Adversary Simulation |
| **Adversary Simulation Specialist** | Build advanced attack scenarios, test defenses against complex threats | Mentor Penetration Testers, support Emulation | Lead Simulation Programs or advise on strategic offensive operations |

---

#### 2. Research Teams
Focus: Discovery, analysis, and innovation in offensive techniques and vulnerabilities.

| Role | Primary Responsibilities | Secondary Responsibilities | Growth Path |
|------|-------------------------|---------------------------|------------|
| **Exploit / Vulnerability Researcher** | Discover vulnerabilities, develop proofs-of-concept, advise mitigation | Support Penetration Tests or Emulation exercises | Become Senior Researcher, Technical Lead, or move into Engineering roles |
| **Adversary Research Analyst** | Study attacker techniques, develop threat intelligence, analyze attack trends | Assist Simulation or Emulation exercises | Progress to Senior Threat Research or lead research initiatives |

---

#### 3. Engineering Teams
Focus: Build tools, automation, and platforms to support offensive operations.

| Role | Primary Responsibilities | Secondary Responsibilities | Growth Path |
|------|-------------------------|---------------------------|------------|
| **Offensive Security Engineer** | Build tools for Penetration Testing, Simulation, and Emulation | Assist in vulnerability research or exploit development | Lead Engineering Projects or move into DevSecOps for offensive tooling |
| **Exploit Developer / Automation Specialist** | Automate testing, develop exploit frameworks, integrate offensive tools | Support Research or Operational teams | Become Lead Engineer, Platform Owner, or cross-train into Research |

## Finding the balance

In the end, maturing your Blue Team and your Red Team must stay in balance to create real value. Often, people view this relationship as a game of cat and mouse, the well known “us versus them” battle where one side tries to outsmart the other. But in truth, both teams share the same mission: to protect the organization and make it stronger after every engagement.

The idea of Purple Teaming captures this perfectly. It’s not a buzzword, nor is it a new function wedged between Red and Blue. It’s simply collaboration an exchange of insights, techniques, and lessons learned. Something that should be a natural habit rather than a scheduled exercise, that’s when and where the magic happens. Each side sharpens the other. The Red Team challenges assumptions and uncovers blind spots, while the Blue Team adapts, strengthens detections, and builds resilience.

Balance is critical. When the Red Team runs too far ahead mastering and focusing only on complexity and stealth, the Blue Team struggles to keep up. Likewise, when the Blue Team becomes overly procedural or rigid, creativity and adaptability can fade. Either imbalance leads to the same result: inefficiency, a loss of control, and less overall value.

It’s about fostering curiosity, creativity, and continuous learning and creating an environment that facilitates all three. The most effective organizations don’t treat their Red and Blue teams as opponents, but as two halves of a single, intelligent defense system. These teams should be structured and managed with the same organizational style.

## Closing thoughts.

The only remaining question of the challenge now is, "How would I manage that?" And the truth is, this is not something with a simple answer. It requires time, thoughtful planning, and a willingness to experiment. Having a structure on paper, making it scalable, and writing it down like this is relatively easy. The real challenge lies in implementing it, writing supporting documents, defining processes, setting clear responsibilities, and ensuring alignment with both team and organizational goals.

But this is also where the opportunity lies. By thinking strategically about how to organize Operational, Research, and Engineering teams in offensive security, you’re building a framework that allows your people to grow, learn, and take ownership. You’re creating a team that can adapt, scale, and innovate rather than just following instructions.

Ultimately, building and leading high-performing offensive security teams is less about frameworks on paper and more about empowering people, fostering growth, and creating clear paths for responsibility and innovation. Start small, think strategically, and focus on creating a culture where knowledge flows, ownership is clear, and careers can evolve. Structure is important, but action is what turns ideas into results, so take these concepts, adapt them to your organization, and begin shaping your team for the challenges ahead.

And that's how I would do it.

I hope you enjoyed this blog. It was a bit different from the technical ones I’ve written in the past, but it was fun to approach or crawl back for a bit into my previous strategic role while combining it with my current field of expertise.