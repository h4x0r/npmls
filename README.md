# npmls - NPM Security Scanner

[![Crates.io](https://img.shields.io/crates/v/npmls.svg)](https://crates.io/crates/npmls)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/h4x0r/npmls/actions/workflows/ci.yml/badge.svg)](https://github.com/h4x0r/npmls/actions/workflows/ci.yml)
[![Security Audit](https://github.com/h4x0r/npmls/actions/workflows/security-audit.yml/badge.svg)](https://github.com/h4x0r/npmls/actions/workflows/security-audit.yml)
[![Downloads](https://img.shields.io/crates/d/npmls.svg)](https://crates.io/crates/npmls)
[![GitHub Stars](https://img.shields.io/github/stars/h4x0r/npmls.svg?style=social&label=Star)](https://github.com/h4x0r/npmls)

A fast, cross-platform Rust application that scans your entire system for npm modules and detects known malicious packages from recent supply chain attacks.

**Author:** Albert Hui <albert@securityronin.com>

## Features

- **🚀 Lightning Fast**: Uses platform-specific optimizations:
  - **Linux**: `locate` database for instant lookups
  - **macOS**: Spotlight (`mdfind`) for fast filesystem queries  
  - **Windows**: MFT (Master File Table) scanning via PowerShell
  - **Fallback**: Built-in parallel filesystem scanner (implementing `fd` algorithm)
- **🔍 Comprehensive Detection**: Identifies malicious packages from recent attacks:
  - September 2025 Qix attack (chalk, debug, color, etc.)
  - August 2025 Nx packages compromise
  - Historical npm supply chain attacks
- **📊 Multiple Output Formats**: Table, JSON, and CSV reporting
- **⚡ Parallel Processing**: Multi-threaded scanning for maximum performance
- **🎯 Threat Intelligence**: Built-in database of known malicious package versions

## Recent Threats Detected

- **chalk@5.6.1** - Crypto wallet hijacking malware
- **debug@4.4.2** - Transaction manipulation malware  
- **Nx packages@19.6.0** - Credential theft malware
- **color@5.0.1** - Browser injection attacks
- And 15+ other compromised packages from 2025 attacks

## Installation

### From crates.io (Recommended)
```bash
# Install directly from crates.io
cargo install npmls

# The binary will be available in ~/.cargo/bin/npmls
# Make sure ~/.cargo/bin is in your PATH
```

### From Source
```bash
# Clone the repository
git clone https://github.com/yourusername/npmls.git
cd npmls

# Build the application
cargo build --release

# The binary will be available at target/release/npmls
```

### Download Pre-built Binaries

Pre-built binaries are available for Windows on the [GitHub Releases](https://github.com/yourusername/npmls/releases) page.

**For Linux users:** We recommend installing via `cargo install npmls` for the best experience.

## Usage

### Basic Scan (Automatic Updates)
```bash
# Scan entire system - automatically downloads/updates database as needed
npmls

# Show only malicious packages
npmls --threats-only

# Verbose output with progress (shows download progress on first run)
npmls --verbose
```

### Manual Database Control
```bash
# Force database update (optional - normally automatic)
npmls --update-db

# Offline mode - skip all downloads, use built-in database only
npmls --offline
```

### Output Formats
```bash
# JSON output
npmls --format json

# CSV output  
npmls --format csv --output scan_results.csv

# Table output (default)
npmls --format table

# List all known threats
npmls --list-threats
```

### Command Line Options
```
USAGE:
    npmls [OPTIONS]

OPTIONS:
    -o, --output <FILE>       Output results to file (CSV format by default)
        --format <FORMAT>     Output format: table (console), json, csv [default: table]
    -t, --threats-only        Only show packages matching known malicious versions
    -v, --verbose            Verbose output with detailed scan progress
        --offline            Offline mode - only use built-in threat database
        --update-db          Update vulnerability database from online sources and exit
        --list-threats       List all known vulnerable packages and versions, then exit
    -h, --help               Print help
    -V, --version            Print version
```

## Sample Output

```
🔍 NPM Security Scanner v0.1.0
Scanning for npm modules and malicious packages...

🍎 Using macOS Spotlight (mdfind) for fast scanning...
✅ Found 234 node_modules directories
📦 Analyzing 234 node_modules directories...

📦 NPM Package Security Scan Results
────────────────────────────────────────────────────────────────────────────────

Package Name              Version      Status       Threat Level    Location                      
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
chalk                     5.6.1        🚨 MALICIOUS  🔴 Critical     /Users/dev/project/node_modules/chalk
debug                     4.4.2        🚨 MALICIOUS  🔴 Critical     /Users/dev/project/node_modules/debug
express                   4.18.2       ✅ Clean      ─               /Users/dev/project/node_modules/express
react                     18.2.0       ✅ Clean      ─               /Users/dev/project/node_modules/react       

────────────────────────────────────────────────────────────────────────────────
📊 Summary: 1,234 total packages, 2 malicious

🚨 SECURITY ALERT - MALICIOUS PACKAGES DETECTED
═══════════════════════════════════════════════════════════════

📦 Package: chalk@5.6.1
📍 Location: /Users/dev/project/node_modules/chalk
⚡ Threat Type: SupplyChainAttack
🔥 Severity: CRITICAL
📝 Description: Compromised in September 2025 Qix phishing attack. Contains crypto wallet hijacking malware...
```

## How It Works

1. **Smart Database Updates**: Automatically downloads vulnerability data on first run or when cache is >24h old
2. **Fast Discovery**: Uses OS-specific tools for rapid filesystem scanning
3. **Package Analysis**: Parses `package.json` files to extract name/version info  
4. **Threat Matching**: Compares against cached vulnerability database
5. **Intelligent Reporting**: Provides actionable security insights

## Vulnerability Database Sources

The application automatically downloads and maintains vulnerability data from multiple authoritative sources:

### Primary Sources
- **[GitHub Advisory Database](https://github.com/github/advisory-database)**: Official GitHub security advisories for npm packages
  - Comprehensive vulnerability database with CVE mappings
  - Regularly updated by security researchers and maintainers
  - Includes severity scores, affected versions, and remediation guidance
  
- **[npm Security Advisories](https://www.npmjs.com/advisories)**: Official npm security team findings
  - Direct from npm package maintainers and security team
  - Real-time threat intelligence for published packages

### Coverage Includes
- **Recent Supply Chain Attacks**: 
  - September 2025: Qix account compromise affecting chalk, debug, color packages
  - August 2025: Nx build system packages with credential theft malware
- **Historical Threats**: event-stream, eslint-scope, and other documented attacks
- **CVE Database**: Known Common Vulnerabilities and Exposures
- **Malicious Package Detection**: Packages with confirmed malware, backdoors, or cryptocurrency miners

### Database Updates
- **Automatic**: Downloads latest data on first run and when cache is >24 hours old
- **Manual**: Use `--update-db` flag to force immediate update
- **Offline Mode**: Use `--offline` to rely on built-in database only
- **Cache Location**: Stored in system cache directory for optimal performance

## Author & Contact

**Albert Hui**  
Email: albert@securityronin.com  
LinkedIn: https://www.linkedin.com/in/alberthui  
Security Researcher & Developer

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add new threat intelligence or platform optimizations
4. Submit a pull request

## Security Notice

This tool is for defensive security purposes only. It helps identify potentially compromised npm packages on your system. Always verify findings and update to secure package versions.

## License

MIT License - see LICENSE file for details.