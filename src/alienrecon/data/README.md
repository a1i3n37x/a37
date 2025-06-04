# CTF Data Directory

This directory contains metadata and templates for CTF box initialization using the `a37 init --ctf` command.

## Directory Structure

```
data/
├── ctf_info/           # CTF box metadata files
│   ├── test_box.yaml
│   ├── thm_basic_pentesting.yaml
│   └── htb_lame.yaml
└── templates/          # Note templates and other files
    └── ctf_notes_template.md
```

## CTF Metadata Format

CTF metadata files are YAML files that describe CTF boxes and provide context for reconnaissance. Here's the expected format:

```yaml
# CTF Box Metadata: Example Box
box_name: "Human-readable box name"
platform: "TryHackMe" | "Hack The Box" | "Local Testing" | etc.
vpn_instructions_url: "https://platform.com/vpn-setup"  # Optional
expected_key_services:
  - "SSH"
  - "HTTP"
  - "SMB"
notes_template_path: "ctf_notes_template.md"  # Optional
description: |
  Longer description of the box, learning objectives, etc.
difficulty: "Easy" | "Medium" | "Hard"
estimated_time: "1-2 hours"
learning_objectives:  # Optional
  - "Basic enumeration"
  - "Web exploitation"
hints:  # Optional
  - "Check for hidden directories"
  - "Look for version information"
```

## Usage

### Initialize a CTF Environment

```bash
# Initialize with a specific CTF box
a37 init --ctf thm_basic_pentesting

# This will:
# 1. Create a mission folder: ./a37_missions/thm_basic_pentesting/
# 2. Copy notes template to the folder
# 3. Display VPN setup instructions (if provided)
# 4. Set CTF context in the session
# 5. Show expected services and guidance
```

### Adding New CTF Boxes

1. Create a new YAML file in `ctf_info/` following the format above
2. Use a descriptive filename (e.g., `platform_boxname.yaml`)
3. Include all relevant metadata for the box

### Notes Templates

The `templates/` directory contains Markdown templates that are copied to mission folders. The default template includes sections for:

- Mission overview
- Reconnaissance findings
- Exploitation attempts
- Post-exploitation activities
- Lessons learned

## Examples

See the existing files in `ctf_info/` for examples:
- `test_box.yaml` - Simple test box for development
- `thm_basic_pentesting.yaml` - TryHackMe Basic Pentesting box
- `htb_lame.yaml` - Hack The Box Lame machine
