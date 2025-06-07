# 👽 a37 - Alien Recon
#
> _"H4ck th3 pl4n3t. D1g b3n34th th3 s1gn4l."_
> _From zero to first blood, guided by ghosts in the shell._

Alien Recon (`a37`) is your AI-augmented recon wingman for CTFs, red team runs, and OSINT prowling.
Built in the shadows between keystrokes and chaos, **a37** automates the grind, sharpens your instincts, and whispers what to try next.

---

## 🧠 What the hell is a37?

**Alien Recon** is a modular, CLI-native recon framework forged for:

- 🔰 New bloods chasing their first flag
- ⚔️ Vets sick of typing out the same stale toolchains

No fluff. No dashboards. No hand-holding.
Just pure, weaponized enumeration with AI in your corner like a rogue sysadmin from another timeline.

---

## 🔍 Current Loadout: Novice Mode

- 🧠 **AI in the loop:** Think of it like having a recon-savvy warlock on comms
- 🛠️ Pre-wired tools:
  `nmap`, `nikto`, `enum4linux-ng`, `hydra`, `http-fetcher`
- 🧪 Structured JSON output + full raw logs (no black boxes)
- 🧙 One-liner flow:
  `alienrecon recon <target>`
- 🧼 Sanity checker:
  `alienrecon doctor` make sure your system isn't dead on arrival

---

## 🚀 Recent Improvements

- ✅ **Stable Tool Cancellation**: Fixed OpenAI API errors when skipping tool suggestions
- ✅ **Parallel Execution**: Run compatible tools simultaneously for faster reconnaissance
- ✅ **Enhanced Session Management**: Robust state tracking and recovery
- ✅ **Improved Error Handling**: Better validation and user feedback
- ✅ **Context-Aware AI**: Maintains awareness of scan results across tools

## ⚠️ Coming Soon...

- 🧬 **MITRE ATT&CK tagging**: Know the technique, not just the tool
- 🕷️ **Pro Mode**: Custom workflows, advanced chaining, no training wheels
- 📜 **Debrief Generator**: Attack paths + summaries that slap

---

## ⚙️ Quick Install

```bash
git clone https://github.com/alien37x/alien-recon.git
cd alien-recon
poetry install
```

> 🧪 Requires Python 3.11+, [Poetry](https://python-poetry.org), and standard recon tools in your `PATH`.

---

## 💾 Usage

### 🤖 Assistant-Driven Workflow (Recommended)

Alien Recon's core strength is its conversational AI assistant that guides you through reconnaissance like an experienced teammate. Start a session and interact naturally:

```sh
# Start an interactive session
alienrecon recon --target 10.10.10.10

# Or start without a target and set it later
alienrecon
> target 192.168.1.100
```

### 🚀 Quick-Recon: Zero-to-Results Fast Track

For beginners or when you need results fast, use the quick-recon command that runs a predefined reconnaissance sequence:

```sh
# Execute standardized recon sequence with guided confirmation
alienrecon quick-recon --target 10.10.10.10
```

**What it does:**
1. **Initial Port Scan** - Fast SYN scan on top 1000 ports with `-Pn` flag
2. **Service Detection** - Detailed version detection on discovered open ports
3. **Web Enumeration** - Automatic directory fuzzing and vulnerability scanning on HTTP/HTTPS services

Each step requires your confirmation and shows educational parameter explanations. Perfect for CTF beginners who want to learn while getting comprehensive results quickly.

#### Example Conversations:

**Basic Reconnaissance:**
```
You: "Start with a basic scan"
AI: "I'll begin with a fast Nmap SYN scan on the top 1000 ports..."
[Proposes nmap_scan with educational parameter explanations]

You: [Confirms scan]
AI: "Found ports 22, 80, 443 open. Let me get detailed service information..."
[Proposes follow-up scan with service detection]
```

**Multi-Step Planning:**
```
You: "After the Nmap scan, if you find web ports, run FFUF directory enumeration and then Nikto"
AI: "I'll create a reconnaissance plan for comprehensive web service enumeration:
     1. Initial Nmap scan to identify open ports
     2. Directory enumeration (only if web ports found)
     3. Vulnerability scanning (only if web ports found)
     Shall I create this plan?"

You: "Yes, create the plan"
AI: [Creates structured plan with conditional execution]
```

**Results Analysis:**
```
You: "What did we find on the web server?"
AI: "From our scans, the web server on port 80 revealed:
     - Apache 2.4.41 with potential vulnerabilities
     - /admin directory (403 Forbidden)
     - /backup directory with directory listing
     Let's investigate the backup directory..."
```

**Learning Mode:**
```
You: "Why did you choose those Nmap parameters?"
AI: "I used -sS (SYN scan) because it's fast and stealthy, -Pn to skip ping
     probes since CTF targets often block ICMP, and --top-ports 1000 to
     check the most common services first..."
```

**Tool Cancellation (Fixed!):**
```
AI: [Proposes Nmap scan with parameters]
You: [Chooses to Skip]
AI: "No problem! What would you like to explore instead? I can suggest
     alternative reconnaissance approaches..."
[No more API errors - smooth continuation]
```

### 🔧 Advanced: Manual Tool Subcommands

For experienced users who want direct tool control:

```sh
# Run tools directly (bypasses AI assistant)
alienrecon manual nmap --ip 10.10.10.10 --scan-type SYN --top-ports 1000
alienrecon manual ffuf --url http://10.10.10.10 --mode dir
```

> **Note**: Manual mode bypasses the assistant's guidance, session management, and educational features. The assistant-driven workflow is recommended for learning and comprehensive reconnaissance.

---

## 🧼 Design Ethos

**a37** isn't just about port scans... it's about mindset.
It's built to teach you how to think like an operator, not just copy-paste one. Every scan is a story. Every banner is a clue.

With AI-guided flows, clean output, and zero bloat, you'll move faster, learn deeper, and stay focused.
Whether you're chasing your first shell or fine-tuning your process, **Alien Recon** keeps you in the fight.

Because recon isn't about information. It's about **momentum**.

---

## 📡 Under the Hood

- 🐍 [Typer](https://typer.tiangolo.com/) — CLI with class
- 🤖 OpenAI API — AI summaries, task flows, and support prompts
- 🧰 POSIX tools — because bash is still king

---

## 💀 Legal Pulse Check

This is an **offensive security** tool.
It's built for **legal, educational, and consensual engagements** only.
Use it wrong, and you're not a hacker... you're a dumbass with a felony.

**Alien37 doesn't pay bail.**

---

## 🌌 Credits + Crew

- From the misfits behind [Alien37.com](https://alien37.com)
- Core design + narrative flow: `@a1i3n37x`
- Purpose-built for that **Novice → Pro** recon evolution

---

## 🛸 Final Transmission

> Power on.
> Dig deep.
> Leave no surface unscanned.

Alien Recon exists to help you think like an operator.
Not a script kiddie. Not a drone. A **hunter**.

**Stay weird. Stay free. H4ck th3 pl4n3t.**
