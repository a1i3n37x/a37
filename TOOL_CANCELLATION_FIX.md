# Tool Cancellation Bug Fix

## Issue Summary

Prior to this fix, when users chose to skip/cancel tool suggestions in the interactive reconnaissance session, the application would encounter OpenAI API errors and crash with messages like:

```
ERROR: OpenAI Bad Request Error: Error code: 400 - {'error': {'message': "Invalid parameter: messages with role 'tool' must be a response to a preceeding message with 'tool_calls'.", 'type': 'invalid_request_error', 'param': 'messages.[4].role', 'code': None}}
```

This prevented users from continuing their reconnaissance sessions after skipping tools.

## Root Cause

The issue had two components:

### 1. Invalid Tool Response Messages
When users cancelled tools, the system was adding "tool" role messages to the chat history using `_send_tool_cancellation_to_llm()`. However, OpenAI's API requires that every "tool" role message must correspond to an actual `tool_calls` in the conversation. Since the tools were cancelled, these tool responses became invalid.

### 2. Null Content Fields
Assistant messages with cancelled tools had `content: null`, but OpenAI's API requires content to be a string or omitted entirely, not null.

## Solution

### 1. Proper Tool Cancellation Handling

**Before:**
```python
# When tool was cancelled, this would add invalid tool messages
self._send_tool_cancellation_to_llm(tool_call_id, function_name)
```

**After:**
```python
# When all tools are cancelled, remove tool_calls from assistant message
if not confirmed_tool_calls and cancelled_tool_calls:
    if (self.chat_history and
        self.chat_history[-1].get("role") == "assistant" and
        self.chat_history[-1].get("tool_calls")):
        # Remove tool_calls and ensure content is not null
        self.chat_history[-1]["tool_calls"] = None
        if self.chat_history[-1].get("content") is None:
            self.chat_history[-1]["content"] = "I understand you've cancelled the tool proposals..."
        return  # Don't call LLM again since no tools were executed
```

### 2. Enhanced History Validation

Added robust validation in `validate_and_fix_history()`:

```python
def validate_and_fix_history(history):
    """
    Validate and fix conversation history to ensure OpenAI API compliance.

    Rules:
    1. Messages with role 'tool' must correspond to preceding 'tool_calls'
    2. Content field cannot be null - must be string or omitted
    """
    # Fix null content fields
    if message.get("content") is None:
        if message.get("role") == "tool":
            message["content"] = ""  # Tool messages must have content
        else:
            message["content"] = ""  # Other messages get empty string

    # Validate tool messages have corresponding tool_calls
    # Remove orphaned tool messages that don't match any tool_calls
```

### 3. Removed Invalid Methods

Completely removed `_send_tool_cancellation_to_llm()` method and updated all references to use simple user feedback messages instead of adding invalid tool responses to chat history.

## Testing

### Before Fix:
1. Start reconnaissance session
2. AI proposes a tool (e.g., nmap_scan)
3. User chooses "Skip"
4. **Result**: OpenAI API error, session crashes

### After Fix:
1. Start reconnaissance session
2. AI proposes a tool (e.g., nmap_scan)
3. User chooses "Skip"
4. **Result**: Clean cancellation message, session continues normally

## Key Benefits

1. **Stable Sessions**: Users can skip tool suggestions without breaking their reconnaissance session
2. **Better UX**: Clean cancellation feedback without API errors
3. **Robust History**: Chat history always conforms to OpenAI API requirements
4. **Error Prevention**: Validation prevents similar issues in the future

## Files Modified

- `src/alienrecon/core/session.py`: Enhanced tool cancellation handling, removed invalid method
- `src/alienrecon/core/agent.py`: Improved history validation with null content handling
- `.alienrecon_session.json`: Fixed existing session files with proper content

## Impact

This fix ensures the core user experience remains stable and uninterrupted. Users can confidently skip tool suggestions knowing their session will continue smoothly, which is essential for the exploratory nature of CTF reconnaissance where users often want to try different approaches.

The fix maintains the educational and conversational aspects of the AI assistant while ensuring technical robustness behind the scenes.
