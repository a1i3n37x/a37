# a37 - Alien Recon
# h4ck th3 pl4n3t!


# 👽 a37 - Alien Recon

> "h4ck th3 pl4n3t!"

Alien Recon (`a37`) is your AI-guided recon wingman for CTFs, red team drills, and OSINT operations.
Born in the void between signal and silence, **a37** leads you from **zero to first blood** with a blend of automation, AI insight, and pure hacker grit.

---

## 🧠 What is a37?

Alien Recon is a modular, CLI-driven recon framework built for **beginner ethical hackers** looking to crush their first boxes — and for pros who don’t have time to type out the same 12 commands every time.

No fluff. No filler. Just pure recon, injected with AI guidance and weaponized enumeration.

### 🔍 Current Features (Novice Mode)
- 🧠 AI-assisted walkthrough flow: like having a recon-savvy mentor in your terminal
- 🛠️ Toolchain: `nmap`, `gobuster`, `nikto`, `enum4linux-ng`, `hydra`, `http-fetcher`
- 🧪 Structured output with clean summaries and full raw logs
- 🧙 `alienrecon recon <target>` — start scanning and let the AI steer
- 🧼 `alienrecon doctor` — system checks so your setup doesn’t suck

### 🚀 Upcoming Features
- 🔁 `--auto` mode with smart task-chaining
- 🧬 MITRE ATT&CK technique tagging for each recon step
- 🕷️ Pro Mode: nuclei, ffuf, searchsploit, and advanced exploitation scaffolding
- 📜 `debrief` generator: full recon summary + attack paths

---

## ⚙️ Installation

```bash
git clone https://github.com/alien37x/alien-recon.git
cd alien-recon
poetry install
