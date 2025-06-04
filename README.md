# 👽 a37 - Alien Recon

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

### Recommended: Assistant-Driven Workflow

The primary way to use Alien Recon is through the conversational AI assistant. Start a session and interact naturally:

```sh
alienrecon
```

You can then type commands like:
- "Scan 10.10.10.10 with nmap"
- "Run directory enumeration on the web server"
- "What do these results mean?"

The assistant will guide you, run tools, explain results, and manage your recon session.

### Advanced: Manual Tool Subcommands

- You can run tools directly using the `manual` subgroup (e.g., `alienrecon manual nmap ...`), but this bypasses the assistant and session features. Results are managed, but you lose conversational AI guidance. This mode is for advanced/manual use only.

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
