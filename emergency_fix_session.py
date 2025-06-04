#!/usr/bin/env python3
"""
Emergency script to clean up corrupted session history.
Run this if you're getting OpenAI API errors about malformed tool messages.
"""

import json
import os


def validate_and_fix_history(history):
    """
    Validate and fix the conversation history to ensure it meets OpenAI API requirements.
    """
    fixed_history = []
    i = 0

    while i < len(history):
        message = history[i]

        # If it's a tool message, check if the previous message has tool_calls
        if message.get("role") == "tool":
            # Find the corresponding assistant message with tool_calls
            tool_call_id = message.get("tool_call_id")

            # Look backward for an assistant message with matching tool_call
            found_matching_assistant = False
            for j in range(len(fixed_history) - 1, -1, -1):
                prev_msg = fixed_history[j]
                if prev_msg.get("role") == "assistant" and prev_msg.get("tool_calls"):
                    # Check if this tool_call_id matches any in the assistant message
                    for tool_call in prev_msg.get("tool_calls", []):
                        if tool_call.get("id") == tool_call_id:
                            found_matching_assistant = True
                            break
                    if found_matching_assistant:
                        break

            # If no matching assistant message found, skip this tool message
            if not found_matching_assistant:
                print(f"❌ Removing orphaned tool message with id: {tool_call_id}")
                i += 1
                continue

        # Add the message to fixed history
        fixed_history.append(message)
        i += 1

    return fixed_history


def fix_session():
    """Fix the corrupted session file."""
    session_file = ".alienrecon_session.json"

    if not os.path.exists(session_file):
        print("❌ No session file found.")
        return

    print("🔧 Loading session file...")
    with open(session_file) as f:
        session_data = json.load(f)

    if "chat_history" not in session_data:
        print("❌ No chat_history in session.")
        return

    original_count = len(session_data["chat_history"])
    print(f"📝 Original message count: {original_count}")

    # Fix the history
    session_data["chat_history"] = validate_and_fix_history(
        session_data["chat_history"]
    )

    fixed_count = len(session_data["chat_history"])
    print(f"✅ Fixed message count: {fixed_count}")
    print(f"🗑️  Removed {original_count - fixed_count} orphaned tool messages")

    # Backup original
    backup_file = f"{session_file}.backup"
    os.rename(session_file, backup_file)
    print(f"💾 Backed up original to: {backup_file}")

    # Save fixed version
    with open(session_file, "w") as f:
        json.dump(session_data, f, indent=2)

    print(f"✅ Fixed session saved to: {session_file}")


if __name__ == "__main__":
    print("🚑 Emergency Session History Fixer")
    print("==================================")
    fix_session()
    print("\n🎉 Session history has been repaired!")
    print("You can now run 'poetry run alienrecon recon --target 10.10.61.3' again.")
