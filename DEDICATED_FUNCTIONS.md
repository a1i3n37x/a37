# 🧰 Dedicated LLM Tool Functions

## ✅ What Was Implemented

I've created the **dedicated, purpose-built tool functions** you requested in `src/alienrecon/tools/llm_functions.py`. These replace generic tool handlers with specific, LLM-aware functions.

## 🔍 FFUF Functions

### `ffuf_vhost_enum(ip, domain, wordlist=None, threads=40, port=80)`
- **Purpose**: Virtual host discovery via Host header fuzzing
- **Returns**: `{"tool": "ffuf", "mode": "vhost_enum", "findings": [...], "scan_summary": "..."}`

### `ffuf_dir_enum(url, wordlist=None, extensions=[], match_codes=[200,301,403])`
- **Purpose**: Directory and file enumeration
- **Returns**: List of discovered paths with status codes and sizes

### `ffuf_param_fuzz(url, param_name, wordlist=None, method="GET")`
- **Purpose**: Parameter value fuzzing
- **Returns**: Interesting parameter values and responses

## 🎯 Gobuster Functions

### `gobuster_dns_enum(domain, wordlist=None, threads=50, dns_server=None)`
- **Purpose**: Subdomain enumeration via DNS queries
- **Returns**: List of discovered subdomains

### `gobuster_dir_enum(url, wordlist=None, extensions=[], threads=50)`
- **Purpose**: Directory brute-forcing
- **Returns**: Discovered directories with status codes

### `gobuster_vhost_enum(ip, domain, wordlist=None, port=80)`
- **Purpose**: Virtual host discovery (alternative to FFUF)
- **Returns**: List of discovered virtual hosts

## 🗺️ Nmap Functions

### `nmap_basic_scan(ip, timeout=300)`
- **Purpose**: Basic port discovery
- **Returns**: Open ports with basic service info

### `nmap_service_version(ip, ports=None)`
- **Purpose**: Detailed service version detection
- **Returns**: Detailed version information for services

### `nmap_os_detect(ip)`
- **Purpose**: Operating system fingerprinting
- **Returns**: OS detection results

### `nmap_script_scan(ip, scripts=[], ports=None)`
- **Purpose**: NSE script execution
- **Returns**: Script scan results

## 🔒 Nikto Functions

### `nikto_scan(ip_or_url, port=None, ssl=None)`
- **Purpose**: Web vulnerability scanning
- **Returns**: Discovered vulnerabilities and misconfigurations

## 📊 Structured Output Format

All functions return consistent structure:

```python
{
    "tool": "ffuf",                    # Tool name
    "mode": "vhost_enum",              # Function mode
    "status": "success",               # success/failure/partial
    "findings": [...],                 # Structured discoveries
    "scan_summary": "Found 3 vhosts",  # Human-readable summary
    "raw_output": "...",               # Optional raw output (truncated)
    "error": None                      # Error message if failed
}
```

## 🧠 LLM Integration Registry

The `LLM_TOOL_FUNCTIONS` registry automatically provides:
- Function metadata for LLM function calling
- Parameter types and descriptions
- Required vs optional parameters
- Intelligent defaults

Example registry entry:
```python
"ffuf_vhost_enum": {
    "function": ffuf_vhost_enum,
    "description": "Enumerate virtual hosts via Host header fuzzing on target IP.",
    "parameters": {
        "ip": {"type": "string", "description": "Target IP address"},
        "domain": {"type": "string", "description": "Base domain to test subdomains against"},
        "threads": {"type": "integer", "description": "Number of concurrent threads", "default": 40}
    },
    "required": ["ip", "domain"]
}
```

## 🎯 Benefits Achieved

### For LLMs:
- **Clear function purposes** - No guessing about tool modes
- **Intelligent defaults** - DNS-optimized wordlists, reasonable timeouts
- **Structured responses** - Easy to parse and reason about
- **Parameter guardrails** - Type validation and helpful error messages

### For Tool Chaining:
LLM can now reason:
> "Found `admin.futurevera.thm` in DNS enum → run `gobuster_dir_enum(url='http://admin.futurevera.thm')` next"

Instead of:
> "Run some generic tool with some mode and hope it works"

## 🔧 Implementation Details

### Smart Wordlist Selection
- **DNS functions**: Auto-select DNS-optimized wordlists (fast, small lists first)
- **Directory functions**: Use appropriate directory wordlists
- **Fallback chains**: Multiple wordlist options with intelligent fallbacks

### Protocol Detection
- Auto-detect HTTP vs HTTPS based on port numbers
- Smart SSL certificate handling for HTTPS targets
- URL parsing for protocol extraction

### Error Handling
- Tool executable validation
- Wordlist existence checking
- Structured error responses with helpful messages

## 🚀 Next Steps

The core dedicated functions are implemented. You can now:

1. **Integrate into existing CLI** - Wire these functions into your current agent system
2. **Test with real targets** - Verify the functions work correctly
3. **Add more specialized functions** - Create additional purpose-built functions as needed
4. **Enhance output parsing** - Improve structured data extraction from tool outputs

The foundation is solid - you now have proper **dedicated, purpose-built functions** instead of generic tool handlers! 🎯
