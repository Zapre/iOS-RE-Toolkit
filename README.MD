# iOS RE Toolkit – PowerShell Scanner (Advanced v2)

A **PowerShell toolkit for iOS reverse engineering** that scans decrypted `.app` bundles for authentication, license, security, and network patterns, then generates compact reports designed to be pasted into the **AI assistant of your choice** to kick-start your reversing workflow.

> ⚠️ **Legal / ethical notice**  
> This toolkit is for **security research, education, and analysis of software you own or are explicitly authorised to test**.  
> Do **not** use it for piracy, non-consensual account access, or any illegal activity. You are responsible for complying with laws and contracts in your jurisdiction.

---

## Features

- 🔍 Scans decrypted iOS `.app` bundles for:
  - Auth / login related patterns
  - License / activation / subscription logic
  - Security / jailbreak / anti-debug routines
  - Network / API endpoints and hosts
- 🎯 **Goal-aware analysis**
  - Bypassing login / auth
  - Cracking / bypassing activation or license
  - Analyzing security features
  - Finding hosts / URLs / APIs
  - General reconnaissance
- 📑 Generates **compact, structured reports**:
  - Executive summary (binary, size, hash, encryption status)
  - Suspicious dylibs and frameworks
  - Category-based string patterns (Auth, License, Security, Network, Crypto, Storage, UI)
  - URLs, potential keys/tokens, selector-style strings
  - High-priority string lists for Ghidra / IDA
- 🤖 Reports are intentionally shaped to be:
  - Easy to paste into ChatGPT / Claude / Copilot / Grok / etc.
  - Easy for an AI to turn into a **step-by-step reversing plan**
- 📦 Optional **JSON export** for custom tooling / automation

---

## Requirements

- **OS:** Windows 10 / 11  
- **PowerShell:** 5.x or 7.x  
- **Input:** A **decrypted** iOS `.app` directory  
  - e.g. dumped via TrollStore, Frida, or any IPA dumper  
- **Optional:** `strings.exe` or similar in your `PATH`
  - If not available, the toolkit falls back to its own binary string extractor.

---

## Quickstart

1. **Clone the repo:**

   ```powershell
   git clone https://github.com/Zapre/iOS-RE-Toolkit.git
   cd .\iOS-RE-Toolkit
