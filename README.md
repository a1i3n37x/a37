# 👽 a37 - Alien Recon

> "H4ck th3 pl4n3t. D1g b3n34th th3 sign4l."

Alien Recon (`a37`) is your AI-guided recon wingman for CTFs, red team drills, and OSINT operations.
Born in the void between signal and silence, **a37** leads you from **zero to first blood** with a blend of automation, AI insight, and pure hacker grit.

---

## 🧠 What is a37?!

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
- 🕷️ Pro Mode: ...
- 📜 `debrief` generator: full recon summary + attack paths

---

## ⚙️ Installation

```bash
git clone https://github.com/alien37x/alien-recon.git
cd alien-recon
poetry install
```

> Requires Python 3.11+, `poetry`, and some standard recon tools in `PATH`.

---

## 👾 Usage

### Basic Recon:
```bash
alienrecon recon <target-ip>
```

### Doctor Check:
```bash
alienrecon doctor
```

### With AI Chat Guidance:
```bash
alienrecon recon <target-ip> --novice
```

---

## 🧬 Philosophy

Alien Recon isn’t here to baby you. It’s here to **level you up**.

You’ll learn the right sequence, the right questions, and the right instincts — while the AI keeps your signal clean and your ops tight.

Because recon isn’t just about ports.
It’s about **momentum**.

---

## 📡 Built With

- 🐍 [Typer](https://typer.tiangolo.com/) – for clean CLI vibes
- 🤖 OpenAI API – for AI-guided prompts and summaries
- ⚙️ Good old Unix tools – the bones of every real op

---

## 💀 WARNING

This is an **offensive security** tool built for **legal use only**.
If you aim this at anything without permission, you’re not a hacker — you’re a liability.

Use responsibly.
**Alien37 doesn’t cover court costs.**

---

## 🌌 Credits

- Designed by the misfits behind [Alien37.com](https://Alien37.com)
- Writing, architecture, and narrative: @a1i3n37x
- System tuned for **Novice → Pro** CTF flow

---

## 🛸 Final Transmission

> Plug in.
> Power up.
> Pop shells.

**a37** is here to teach you to think like a red teamer —
one port, one banner, one cracked password at a time.

Stay weird.
Stay sharp.
**h4ck th3 pl4n3t.**
