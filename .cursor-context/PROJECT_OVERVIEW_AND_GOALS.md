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

## Current Development Phase (as of January 2025)
Currently in **Phase 4: Boot Sequence: Zero-to-First-Blood** (2/4 features complete).

**Recent Achievements:**
- ✅ All core tools can be run independently with clear CLI options
- ✅ Enhanced help messages, error handling, and user feedback
- ✅ Flexible reconnaissance planning through AI conversation
- ✅ Comprehensive results storage and session state management
- ✅ Fixed tool cancellation issues preventing OpenAI API errors
- ✅ Robust chat history validation and error handling
- ✅ Parallel execution support for compatible tools
- ✅ **`a37 init --ctf` command** - Complete CTF box initialization with metadata and mission organization
- ✅ **`quick-recon` command** - Predefined reconnaissance sequence with guided confirmation

**Current Focus:**
- Completing Phase 4 remaining features: exploit suggestion and debrief generator
- Enhanced educational context and vulnerability explanation
- User experience refinements

## Key Upcoming Goals
1.  **Phase 4 Completion**: Finish remaining Zero-to-First-Blood features including exploit suggestion (guiding manual research) and `debrief` generator to enable newcomers to achieve initial foothold on beginner CTF boxes.
2.  **Phase 4.5: Enhanced Learning & Context - MITRE ATT&CK Integration**: Map tool findings to MITRE ATT&CK techniques, have the AI explain these techniques, and include them in the debrief report.
