# AUVAP - Automated Vulnerability Assessment Pipeline

**AUVAP** is an AI-powered vulnerability assessment and exploit generation pipeline that automates the triage, classification, and proof-of-concept exploit creation from Nessus scan results.

## 🚀 Features

- **Multi-Provider LLM Integration**: OpenAI, Google Gemini, GitHub Models, Local LLMs (Ollama/LM Studio)
- **Intelligent Classification**: Business context-aware vulnerability prioritization
- **Feasibility Filtering**: Automated detection of automation-suitable vulnerabilities
- **Multi-Language Exploit Generation**: Generates Python, Bash, and PowerShell exploits
- **Deterministic Language Selection**: Automatic language choice based on vulnerability characteristics
- **Safety Validation**: Built-in checks for credentials, timeouts, scope validation
- **Organized Output**: Timestamped reports and exploit folders

## 📋 Pipeline Components

### 1. **Parser** (`parser.py`)
Parses Nessus XML reports into structured vulnerability findings.

### 2. **Classifier** (`classifier_v2.py`)
LLM-powered vulnerability classification with:
- Business context awareness
- Multi-provider support (OpenAI, Gemini, GitHub, Local)
- Robust JSON extraction and retry logic
- Environment-based configuration detection

### 3. **Feasibility Filter** (`feasibility_filter.py`)
Identifies vulnerabilities suitable for automation based on:
- CVE availability
- Known exploitability indicators
- Service accessibility
- Automation feasibility heuristics

### 4. **Exploit Generator** (`exploit_generator.py`)
Generates safe, language-appropriate exploit scripts:
- **PowerShell**: Windows services (SMB, RDP, IIS)
- **Bash**: Linux services (SSH, FTP, Shellshock)
- **Python**: Web services, APIs, databases
- Safety wrappers for Python scripts
- Native scripts for Bash/PowerShell

### 5. **Experiment Orchestrator** (`experiment.py`)
End-to-end pipeline execution with timestamped results.

## 🛠️ Installation

### Prerequisites
```bash
# Python 3.8+
python --version

# Required packages
pip install openai google-genai
```

### Local LLM Setup (Optional)
For local model support with Ollama:
```bash
# Install Ollama
# Windows: Download from https://ollama.ai

# Pull models
ollama pull deepseek-r1:14b
ollama pull qwen3:14b
```

## 🔧 Configuration

### Environment Variables

```bash
# OpenAI
export OPENAI_API_KEY="your-openai-api-key"

# Google Gemini
export GEMINI_API_KEY="your-gemini-api-key"

# GitHub Models
export GITHUB_TOKEN="your-github-token"

# Local LLM (Ollama/LM Studio)
export LOCAL_OPENAI_BASE_URL="http://localhost:11434/v1"  # Default
```

## 📖 Usage

### Step 1: Run Classification Pipeline
```bash
python experiment.py
```

**Interactive prompts**:
1. Choose LLM provider (OpenAI/Gemini/GitHub/Local)
2. Select model (if applicable)
3. Add custom business context (optional)

**Output**: `results/experiment_report_YYYYMMDD_HHMMSS.json`

### Step 2: Generate Exploits
```bash
python exploit_generator.py results/experiment_report_YYYYMMDD_HHMMSS.json
```

**Output**: `exploits/exploits_YYYYMMDD_HHMMSS/`

### Example Workflow
```bash
# 1. Classify vulnerabilities
python experiment.py
# Select: 5 (Local), 1 (deepseek-r1:14b)

# 2. Generate exploits
python exploit_generator.py experiment_report_20251030_002605.json
# Select: 5 (Local), 1 (deepseek-r1:14b)

# 3. Review generated exploits
ls exploits/exploits_20251030_002605/
```

## 📁 Project Structure

```
AUVAP/
├── parser.py                    # Nessus XML parser
├── classifier_v2.py             # LLM vulnerability classifier
├── feasibility_filter.py        # Automation feasibility filter
├── exploit_generator.py         # Multi-language exploit generator
├── experiment.py                # Pipeline orchestrator
├── auvap_nessus_25_findings.xml # Sample Nessus report
├── results/                     # Classification reports
│   └── experiment_report_*.json
└── exploits/                    # Generated exploits
    └── exploits_YYYYMMDD_HHMMSS/
        ├── 10_0_1_5/            # Grouped by host
        │   ├── CVE_2020_1938_unknown.py
        │   └── CVE_2021_41773_unknown.py
        ├── 10_0_1_7/
        │   ├── CVE_2017_0144_unknown.ps1  # PowerShell
        │   └── CVE_2017_7269_unknown.ps1
        └── exploits_manifest.json
```

## 🎯 Language Selection Logic

AUVAP automatically chooses the appropriate scripting language:

### PowerShell (`.ps1`)
- Windows OS/Microsoft services
- SMB, RDP, NetBIOS, WinRM
- Known CVEs: MS17-010, BlueKeep, SMBGhost

### Bash (`.sh`)
- Linux/Unix services
- SSH, FTP, Telnet, SMTP
- Known CVEs: Shellshock

### Python (`.py`)
- HTTP/HTTPS services
- Databases (PostgreSQL, MySQL, MongoDB)
- Web servers (Apache, Tomcat, Nginx, Jenkins)
- Complex/unknown exploits

## 🔒 Security & Safety

### Safety Features
- ✅ Timeout constraints (10s default)
- ✅ Max attempts limit (3 attempts)
- ✅ Scope validation requirements
- ✅ No destructive actions
- ✅ Hardcoded credential detection
- ✅ Error handling enforcement

### ⚠️ IMPORTANT SECURITY NOTICE
**All generated scripts are for AUTHORIZED PENETRATION TESTING ONLY.**
- Unauthorized access to computer systems is illegal
- Ensure written permission before executing
- Scripts must be reviewed before execution
- No destructive actions are included
- Proper error handling and logging enforced

**NO UNAUTHORIZED TESTING. ETHICAL USE ONLY.**

## 📊 Output Format

### Classification Report
```json
{
  "total_findings": 25,
  "feasible_count": 12,
  "manual_review_count": 13,
  "feasible_findings_detailed": [
    {
      "host_ip": "10.0.1.5",
      "port": 8009,
      "service": "ajp13",
      "cve": "CVE-2020-1938",
      "title": "Apache Tomcat AJP File Read Vulnerability",
      "severity": "Critical",
      "exploit_notes": "Use AJP protocol to read arbitrary files"
    }
  ]
}
```

### Exploit Manifest
```json
{
  "total": 12,
  "generated": 12,
  "failed": 0,
  "manifests": [
    {
      "vulnerability_id": "CVE_2020_1938_12345",
      "cve": "CVE-2020-1938",
      "title": "Apache Tomcat AJP File Read Vulnerability",
      "target": "10.0.1.5:8009",
      "script_path": "exploits/.../CVE_2020_1938_unknown.py",
      "safety_warnings": []
    }
  ]
}
```

## 🧪 Local Model Support

AUVAP supports local LLMs via Ollama or LM Studio:

### Supported Models
- **deepseek-r1:14b** (default) - Reasoning model
- **qwen3:14b** - Fast inference model
- Custom models via Ollama

### Benefits
- No API costs
- Data privacy (runs locally)
- No rate limits
- Offline capability

### Configuration
```bash
# Start Ollama
ollama serve

# Set base URL (optional, default is http://localhost:11434/v1)
export LOCAL_OPENAI_BASE_URL="http://localhost:11434/v1"
```

## 🐛 Known Issues

### Local Models
- May generate verbose responses requiring higher max_tokens (1200+)
- Less reliable at following complex format instructions
- May default to Python even when other languages requested

### Solutions
- ✅ Deterministic language selection (Option B implementation)
- ✅ Robust JSON extraction with retry logic
- ✅ Increased token limits for local models

## 📝 License

This project is for educational and authorized security testing purposes only.

## 🤝 Contributing

Contributions welcome! Areas for improvement:
- Additional language support (Ruby, Perl, JavaScript)
- Language-specific safety wrappers for Bash/PowerShell
- Enhanced syntax validation for non-Python languages
- Additional CVE mappings
- Cloud provider integration (AWS/Azure/GCP)

## 📧 Contact

For issues or questions, please open an issue on GitHub.

---

**Remember**: Always obtain proper authorization before conducting security assessments. Unauthorized testing is illegal and unethical.
