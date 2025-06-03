# Alien Recon (a37) - Project Overview and Goals

## What is Alien Recon (a37)?
Alien Recon (`a37`) is an AI-augmented reconnaissance wingman for CTFs, red team runs, and OSINT prowling. It's a modular, CLI-native recon framework designed to automate repetitive tasks, sharpen instincts, and provide AI-driven guidance. It's built for both beginners chasing their first flag and experienced veterans looking to optimize their workflows.

## Overall Goal & Vision
The primary goal is to build an AI-guided ethical hacking assistant focused on CTF reconnaissance for beginners, culminating in a "Zero-to-First-Blood" experience with integrated learning aids. a37 aims to make CTF recon accessible, fast, and educational, blending automation with AI mentorship to teach users the "why" and "how" of recon.

## Target Audience
- Newcomers to CTFs and cybersecurity.
- Experienced practitioners seeking to streamline initial reconnaissance phases.

## Core Philosophy
`a37` is about fostering an operator's mindset. It emphasizes learning, understanding the 'why' behind recon actions, and building momentum through guided, efficient enumeration. The goal is to make users think like hunters, not just script runners.

## Current Development Phase (as of June 2025)
Currently in **Phase 3: Modular, User-Driven Recon**.
The focus is on:
- Ensuring each tool can be run independently with clear CLI options.
- Improving help messages, error handling, and user feedback.
- Allowing users to select and queue tasks manually.
- Storing and organizing results from tool runs.

## Key Upcoming Goals
1.  **Phase 4: Boot Sequence: Zero-to-First-Blood**: Enable a newcomer to achieve an initial foothold on a beginner CTF box with AI support, including `a37 init --ctf`, a `quick-recon` macro, basic exploit suggestion (guiding manual research), and a `debrief` generator.
2.  **Phase 4.5: Enhanced Learning & Context - MITRE ATT&CK Integration**: Map tool findings to MITRE ATT&CK techniques, have the AI explain these techniques, and include them in the debrief report.
