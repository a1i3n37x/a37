Okay, this is a smart move. Focusing on a strong, achievable core and then iterating based on feedback is a proven path to success.

---

**Current Status & Next Steps (as of June 2025):**

- ✅ **Doctor command implemented!** Alien Recon now has a beautiful, user-friendly self-test for tools, API, and environment health.
- ✅ **All core tool wrappers (nmap, gobuster, nikto, enum4linux-ng, hydra, http-fetcher) have robust, real parsing logic and are fully tested.**
- ✅ **Parser tests, fixtures, and ToolResult schema are complete and enforced.**
- ✅ **Test coverage is high, including edge and error cases.**
- ✅ **Rich error handling and consistent output schemas.**
- 🟢 **Ready to move into Phase 3: Modular, User-Driven Recon.**

---

**Alien Recon (a37) - Focused Roadmap to v1.0 (Updated June 2025)**

**Overall Goal:** Build an AI-guided ethical hacking assistant focused on CTF reconnaissance for beginners, culminating in a "Zero-to-First-Blood" experience with integrated learning aids like MITRE ATT&CK tagging.

---

**Phase 0: Kick-off & Repo Hygiene (½ week)**
*Goal: Set up src-layout package, CI, linting, pyproject, etc.*
*   ✅ **Project Initialization:** Poetry project (`a37`) with `src` layout (`src/alienrecon`).
*   ✅ **`pyproject.toml` Configuration:** (Metadata, Python version, dependencies, scripts, tool configs).
*   ✅ **Linter/Formatter Setup:** (`ruff`, `pre-commit`).
*   ✅ **Basic CI Setup (GitHub Actions):** (Checkout, Python setup, Poetry install, caching, pre-commit runs).
*   ✅ **Directory Structure & File Migration:** (Organized `src/alienrecon` structure).
*   ✅ **`.gitignore`** configured.

**Status: Phase 0 - COMPLETE** 🎉

---

**Phase 1: Core Refactor + Typer CLI (1 week)**
*Goal: Typer-based alienrecon CLI with sub-commands. SessionController class. Preserve current Nmap→Gobuster→Nikto→enum4linux-ng path. Done = alienrecon recon <target> works; CI green.*

*   ✅ **Typer-based `alienrecon` CLI:** (`src/alienrecon/cli.py`, sub-commands, options).
*   ✅ **`SessionController` class (`src/alienrecon/core/session.py`):** (Initialization, tool management, interactive loop logic, LLM interaction, tool execution & confirmation).
*   ✅ **Preserve current Nmap→Gobuster→Nikto→enum4linux-ng path:** (AI-guided flow implemented).
*   ✅ **Done = `alienrecon recon <target>` works; CI green.**

**Status: Phase 1 - COMPLETE** 🎉

---

**Phase 2: Reliability & Testing (1 week)**
*Goal: Parser unit-tests, standard result schema, rich logging, doctor command. Ensure a robust and trustworthy core.*

*   ✅ **Parser unit-tests + fixtures (> 80 % coverage):**
    *   ✅ All core tools have sample raw outputs and robust tests (success, failure, edge cases).
*   ✅ **Standard Result Schema:**
    *   ✅ Consistent `ToolResult` structure (TypedDict) for all tool outputs.
*   ✅ **Rich Logging & User-Controlled Verbosity:**
    *   ✅ Logging and error handling are robust and user-friendly.
*   ✅ **`alienrecon doctor` self-test command:**
    *   ✅ Checks for tool availability, API connectivity, wordlists, and more.

**Status: Phase 2 - COMPLETE** 🎉

---

**Phase 3: Modular, User-Driven Recon (1 week)**
*Goal: Refocus on a flexible, user-driven workflow. Remove auto-recon and TaskQueue orchestration. Make each tool integration robust, user-friendly, and easy to run individually or in user-defined sequences.*

*   [ ] **Manual Tool Execution:**
    *   [ ] Ensure each tool (nmap, gobuster, nikto, enum4linux-ng, hydra, http-fetcher) can be run independently with clear CLI options and argument validation.
    *   [ ] Improve help messages, error handling, and user feedback for each tool.
*   [ ] **Flexible Task Management:**
    *   [ ] Allow users to select, queue, and reorder tasks manually (if desired), but do not enforce automation.
    *   [ ] Provide CLI flags or interactive prompts for chaining tools, but keep user in control.
*   [ ] **Results Management:**
    *   [ ] Store and organize results from each tool run for easy review and comparison.
    *   [ ] Allow users to re-run or compare results from different tools or runs.
*   [ ] **Documentation & Usability:**
    *   [ ] Update documentation to reflect the new manual-first workflow.
    *   [ ] Add usage examples and best practices for running and combining tools.

**Status: Phase 3 - NEXT UP**

---

**Phase 4: Boot Sequence: Zero-to-First-Blood (2 weeks)**
*Goal: A total newcomer downloads Alien Recon and can realistically achieve an initial foothold (e.g., find a flag) on a beginner CTF box within a short timeframe, supported by helpful outputs and a clear sense of accomplishment.*

*   [ ] **`a37 init --ctf <box_identifier>`:**
    *   [ ] Define a simple metadata format (e.g., YAML/JSON) for beginner CTF boxes (e.g., target IP, VPN info, key services to expect).
    *   [ ] Implement logic to fetch/load this metadata (initially could be local files, later a small shared repo).
    *   [ ] Create a mission folder for the user, potentially pre-populating VPN config files or notes.
*   [ ] **`quick-recon` macro/command:**
    *   [ ] A wrapper command that helps users quickly run a sequence of recon tools with opinionated default settings, but always with user confirmation and control.
*   [ ] **Exploit Suggestion (formerly Auto-Exploit Stub):**
    *   [ ] Based on service versions identified (Nmap, Nikto) and potential vulnerabilities (Nikto):
        *   Integrate `searchsploit` or a similar local exploit database lookup.
        *   The AI will present potential exploits or vulnerability categories found, explaining them.
        *   **Crucially, guide the user on how to *manually* research and attempt these using Metasploit or other tools, rather than auto-firing.** This maintains focus on learning. (e.g., "Nmap identified vsftpd 2.3.4. This version is known to be vulnerable (CVE-XXXX-XXXX). You could try searching for modules in Metasploit using `search vsftpd 2.3.4` and then learn to configure and run the `exploit/unix/ftp/vsftpd_234_backdoor` module.")
*   [ ] **`debrief` generator:**
    *   [ ] After a session, allow the user to generate a templated Markdown report.
    *   [ ] The report should summarize:
        *   Target information.
        *   Key Nmap findings.
        *   Significant results from Gobuster, Nikto, enum4linux-ng.
        *   (Future, from Phase 4.5) MITRE ATT&CK techniques observed/suggested.
        *   Any exploit suggestions made.
        *   A section for the user to add their own notes and flag.
*   [ ] **Flag Capture Feedback & Motivation:**
    *   [ ] Implement a simple command like `a37 flag <flag_string>` or allow the user to tell the AI "I found the flag! It's XYZ".
    *   [ ] Display a fun ASCII art confirmation / "dopamine hit" message.

**Status: Phase 4 - To Be Started**

---

**Phase 4.5: Enhanced Learning & Context - MITRE ATT&CK Integration (1-2 weeks, can overlap with Phase 4)**
*Goal: Deepen the educational value by linking reconnaissance actions and findings to the MITRE ATT&CK framework, helping users understand the broader context of their techniques.*

*   [ ] **MITRE ATT&CK Mapping in Tool Wrappers/Parsers:**
    *   [ ] Research and identify relevant MITRE ATT&CK techniques associated with the information gathered by Nmap, Gobuster, Nikto, and enum4linux-ng.
    *   [ ] Modify the `parse_output` methods in tool classes (or add a subsequent analysis step) to include a list of relevant MITRE ATT&CK technique IDs in their structured results.
*   [ ] **AI Explanation of MITRE Techniques:**
    *   [ ] Update the `AGENT_SYSTEM_PROMPT` to instruct the AI to:
        *   Recognize MITRE technique IDs in tool results.
        *   Briefly explain the identified technique(s) to the user in simple terms when discussing tool findings.
        *   (Optional) Provide a link to the MITRE ATT&CK website for that technique.
*   [ ] **`debrief` Generator Update:**
    *   [ ] Include a section in the Markdown report listing the MITRE ATT&CK techniques identified/used during the session.
*   [ ] **(Stretch Goal for 4.5) Simple `--show-mitre-matrix` for Session:**
    *   [ ] At the end of a session, provide an option to display a very simple, text-based summary of tactics covered (e.g., Reconnaissance: [T1046, T1083], Discovery: [T1087]). Not a full visual matrix yet, but a list.

**Status: Phase 4.5 - To Be Started**

---

**Post v1.0 (After Nailing Phase 4.5 & Gathering Feedback):**

*   **User Feedback Analysis:** Collect and analyze user feedback on the v1.0 experience. What do they love? What's missing? What's confusing?
*   **Next Steps Prioritization:** Based on feedback and your vision, then decide on features from the original "Phase 5+" (e.g., more advanced progressive disclosure, hint systems, specific skill modules, plugin architecture if heavily requested) or entirely new ideas.
*   **Focus on iterative improvements** to the core experience.

---

**AI Assistant Reference & Project Vision**

**What is Alien Recon (a37)?**
- An AI-guided, modular recon framework for CTFs, red team drills, and OSINT.
- Designed for beginners and pros: automates tedious recon, but also teaches and explains.
- CLI-driven, with AI chat guidance and structured, actionable output.

**Current Capabilities:**
- Robust wrappers for nmap, gobuster, nikto, enum4linux-ng, hydra, and http-fetcher.
- All tools have real parsing logic and are fully tested (including edge/error cases).
- Consistent output schema (`ToolResult`) for all tools.
- Interactive and scriptable CLI (Typer-based).
- System health/doctor checks.

**Your Vision & Goals:**
- Make CTF recon accessible, fast, and educational.
- Blend automation with AI mentorship: teach users the "why" and "how" of recon, not just the "what".
- Enable both guided (novice) and power-user (expert) workflows, but always with user control.
- Build a foundation for extensibility: new tools, new task types, new learning modules.

**What You're Working Towards:**
- Phase 3: Modular, user-driven recon with robust, flexible tool execution and results management.
- Phase 4: "Zero-to-First-Blood"—a newcomer can get a flag with AI help, and generate a debrief report.
- Phase 4.5: MITRE ATT&CK tagging and educational context.

**Strategic Recommendations:**
- **Move into Phase 3 now:** Your core is strong and tested. Focus on making each tool easy to use, robust, and flexible for user-driven workflows. Validate your architecture and make it easy to add new tools later.
- **Design for extensibility:** Make each tool wrapper generic and pluggable. Each new tool should be easy to add/test.
- **After Phase 3, add more tools:** ffuf, wpscan, amass, searchsploit, etc. can be added as new modules.
- **Focus on user experience:** Keep the AI guidance clear, actionable, and educational. Make the CLI and reports beautiful and motivating.
- **Gather feedback early:** Once the new workflow is working, get user feedback to guide Phase 4/4.5 priorities.

**Things You Could Add (Future):**
- More tool integrations (ffuf, wpscan, amass, nuclei, etc.)
- Plugin/module registration system for community-contributed modules
- More advanced reporting (Markdown, HTML, PDF)
- Interactive learning/hint modules
- Pro mode with advanced chaining, custom task graphs
- Cloud/remote target support
- Web UI or TUI (text UI) for richer experience

**If you're an AI or developer jumping in:**
- Read the README and this section for project philosophy and priorities.
- Review the CLI, SessionController, and tool wrappers for architecture.
- All new tools should follow the `ToolResult` schema and have robust tests/fixtures.
- Focus on making recon both powerful and educational—automation is great, but teaching is the differentiator.

---

This section is your quick-start for understanding the project, its direction, and how to contribute or extend it successfully.
