# SSL Error Probing Guide

## Overview

This guide explains how to use the new SSL error probing functionality in `a37` (Alien Recon) to replicate the behavior you experienced with `gobuster dir` when it revealed hostnames through SSL certificate errors.

## The Problem You Encountered

When you ran:
```bash
gobuster dir --url https://support.futurevera.thm -w /usr/share/wordlists/dirb/common.txt -o gobuster_support
```

`gobuster dir` attempted to connect to `https://support.futurevera.thm` for directory enumeration, but during the SSL handshake, it encountered a certificate error that revealed the correct 2nd level vhost name.

This happens when:
1. You connect to a hostname like `support.futurevera.thm`
2. The server presents an SSL certificate
3. The certificate doesn't match `support.futurevera.thm`
4. The SSL error message reveals what hostname the certificate is actually for

## Solutions in a37

We've implemented **three different approaches** to capture this information:

### 1. Enhanced SSL Inspector (Direct Certificate Inspection)

**Function**: `inspect_ssl_certificate(ip, port=443, hostname_for_sni=None)`

**Use this when**: You want to directly inspect the SSL certificate and see what hostnames it's valid for.

**Example**:
```python
# Connect to the IP with SNI set to the suspected hostname
result = inspect_ssl_certificate(
    ip="10.10.61.3",
    port=443,
    hostname_for_sni="support.futurevera.thm"
)

# Or connect directly to the hostname
result = inspect_ssl_certificate(ip="support.futurevera.thm", port=443)
```

**What it reveals**:
- Certificate Common Name (CN)
- Subject Alternative Names (SANs)
- Certificate verification errors that mention hostnames

### 2. HTTP SSL Error Probe (Gobuster Dir Behavior)

**Function**: `probe_ssl_errors(url)`

**Use this when**: You want to exactly replicate what `gobuster dir` does - make an HTTP request and capture SSL certificate errors.

**Example**:
```python
# This mimics exactly what gobuster dir does
result = probe_ssl_errors(url="https://support.futurevera.thm")

# Check for revealed hostnames
if result['findings'].get('revealed_hostnames'):
    print("Found hostnames:", result['findings']['revealed_hostnames'])

if result['findings'].get('hostname_mismatch'):
    print("Hostname mismatch reveals:", result['findings']['hostname_mismatch'])
```

**What it reveals**:
- Hostnames mentioned in SSL certificate errors
- Hostname mismatch errors
- Certificate verification failures that contain hostname information

### 3. Enhanced FFUF with Stderr Capture

**Function**: `ffuf_vhost_enum()` (with enhanced error reporting)

**Use this when**: You're doing vhost enumeration but want to capture SSL-related errors from stderr.

**Example**:
```python
result = ffuf_vhost_enum(ip="10.10.61.3", domain="futurevera.thm")

# Check stderr for SSL errors (now captured in enhanced version)
if 'stderr_diagnostics' in result:
    print("SSL errors from FFUF:", result['stderr_diagnostics'])
```

## Which Approach Should You Use?

### For Your Specific CTF Scenario:

**Start with**: `probe_ssl_errors(url="https://support.futurevera.thm")`

This is the **closest replication** of what `gobuster dir` does. It will:
1. Attempt an HTTPS connection to `support.futurevera.thm`
2. Capture any SSL certificate errors during the handshake
3. Parse error messages for hostname information
4. Return structured findings

### Testing Scripts Available:

1. **`test_ssl_error_probe.py`** - Tests the HTTP SSL error probe functionality
2. **`test_enhanced_ssl.py`** - Tests the enhanced SSL inspector
3. **`test_gobuster_scenario.py`** - Raw openssl testing to replicate the scenario

## Quick Test Commands

Run these to test the functionality:

```bash
# Test the SSL error probe (closest to gobuster dir)
python3 test_ssl_error_probe.py

# Test the enhanced SSL inspector
python3 test_enhanced_ssl.py

# Raw openssl testing
python3 test_gobuster_scenario.py
```

## How to Use in a37 Session

Once you start an `a37` session, you can call:

```python
# Method 1: HTTP SSL Error Probe (recommended for your case)
result = probe_ssl_errors(url="https://support.futurevera.thm")
print("Revealed hostnames:", result['findings'].get('revealed_hostnames', []))

# Method 2: Direct SSL Certificate Inspection
result = inspect_ssl_certificate(ip="10.10.61.3", hostname_for_sni="support.futurevera.thm")
print("Certificate CN:", result['findings']['certificate'].get('common_name'))
print("SANs:", result['findings']['certificate'].get('subject_alt_names', []))

# Method 3: Enhanced FFUF with stderr capture
result = ffuf_vhost_enum(ip="10.10.61.3", domain="futurevera.thm")
# Check results and stderr_diagnostics
```

## Key Differences from Original Approach

- **`ffuf_vhost_enum`**: Fuzzes Host headers against an IP (different technique)
- **`probe_ssl_errors`**: Connects directly to a hostname like `gobuster dir` does
- **`inspect_ssl_certificate`**: Directly inspects certificates without HTTP

The **`probe_ssl_errors`** function is specifically designed to replicate the `gobuster dir` behavior you experienced.

## Expected Results

If the CTF scenario is set up like you described, one of these approaches should reveal:
- The correct 2nd level vhost name in the certificate CN or SANs
- Hostname mismatch errors that mention the correct hostname
- Certificate verification failures containing the target hostname

## Troubleshooting

If none of the approaches work:
1. Check that `support.futurevera.thm` resolves to `10.10.61.3`
2. Verify the target is still accessible on port 443
3. Try manual testing with the raw scripts (`test_gobuster_scenario.py`)
4. Compare with the actual `gobuster dir` command output

The key insight is that `gobuster dir` was doing **directory enumeration** on a specific hostname, not vhost enumeration, which is why the standard vhost fuzzing approach didn't replicate the behavior.
