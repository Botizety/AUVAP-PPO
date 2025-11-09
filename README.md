# AUVAP - Automated Vulnerability Assessment Pipeline

**AUVAP** is an AI-powered vulnerability assessment and exploit generation pipeline that automates the triage, classification, and proof-of-concept exploit creation from Nessus scan results.

## 🚀 Features

### Core Capabilities
- **Multi-Provider LLM Integration**: OpenAI, Google Gemini, GitHub Models, Local LLMs (Ollama/LM Studio)
- **Policy-Based Filtering**: YAML-configured organizational security policies (Phase 2)
- **Few-Shot Learning**: Semantic similarity-based example selection for improved classification (Phase 3)
- **Performance Metrics**: Real-time tracking of latency (P95), label entropy, and classification validity (Phase 3)
- **Risk-Based Task Management**: Automated task prioritization using CVSS and attack surface analysis (Phase 4)
- **Multi-Language Exploit Generation**: Generates Python, Bash, and PowerShell exploits
- **Deterministic Language Selection**: Automatic language choice based on vulnerability characteristics
- **Safety Validation**: Built-in checks for credentials, timeouts, scope validation
- **Organized Output**: Timestamped reports, task manifests, and exploit folders

## 📋 Pipeline Components

### Phase 1: Normalization & Validation
**Parser** (`parser.py`)
- Parses Nessus XML reports into structured vulnerability findings
- Deduplication using content-based hashing
- Missing field imputation
- Metrics: Normalization efficiency (η), Imputation rate (λ)

### Phase 2: Policy Filtering
**Policy Manager** (`policy_config.yaml`)
- YAML-configured organizational security policies
- Rule types: Ignore, Force-manual, Prioritize
- Pattern matching: CVE, CVSS, port, service, severity
- Metrics: Coverage ratio (ρ), ignore breakdown

### Phase 3: LLM Classifier Enhancements
**Classifier** (`classifier_v2.py`) + **Enhancements** (`phase3_enhancements.py`)
- Few-shot learning with semantic example selection (`examples.json`)
- **DynamicFewShotSelector**: Uses sentence-transformers for similarity-based example retrieval
- **ClassificationMetrics**: Tracks latency (P95), label entropy, invalid rate
- **ClassifierCalibrator**: Adjusts thresholds based on false positive rate (FPR)
- Multi-provider support (OpenAI, Gemini, GitHub, Local)
- Business context awareness

### Phase 4: Task Management
**Task Manager** (`task_manager.py`)
- Risk scoring: r(f) = cvss × w_surface × w_auto
  - Attack surface weights: Network=1.0, Adjacent=0.7, Local=0.4, Physical=0.2
  - Automation weights: Automatable=1.0, Manual=0.3
- State machine: PLANNED → EXECUTING → SUCCEEDED/FAILED/ABORTED
- Task grouping by host/service
- Manifest generation with UUID tracking

### Phase 5: Feasibility Filter
**Feasibility Filter** (`feasibility_filter.py`)
- Identifies vulnerabilities suitable for automation
- CVE availability and exploitability indicators
- Risk score calculation and integration
- Service accessibility analysis

### Phase 6: Exploit Generator
**Exploit Generator** (`exploit_generator.py`)
- Generates safe, language-appropriate exploit scripts:
  - **PowerShell**: Windows services (SMB, RDP, IIS)
  - **Bash**: Linux services (SSH, FTP, Shellshock)
  - **Python**: Web services, APIs, databases
- Safety wrappers and validation
- Timestamped exploit folders

### Orchestration
**Experiment Orchestrator** (`experiment.py`)
End-to-end pipeline execution with 6 stages:
1. Parse Nessus XML
2. Apply security policies
3. Classify with LLM (few-shot enabled)
4. Filter by feasibility
5. Initialize exploit tasks
6. Generate assessment report

## 🛠️ Installation

### Prerequisites
```bash
# Python 3.8+
python --version

# Required packages
pip install openai google-genai pyyaml

# Optional: For Phase 3 few-shot learning (semantic similarity)
pip install sentence-transformers tf-keras
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

### Step 1: Run Assessment Pipeline
```bash
python experiment.py
```

**Interactive prompts**:
1. Add custom business context (optional)
2. Choose LLM provider (OpenAI/Gemini/GitHub/Local)
3. Select model (if applicable)

**Pipeline Execution**:
- [1/4] Parse Nessus XML report
- [2/5] Apply organizational security policies
- [3/5] Classify with LLM (few-shot learning enabled)
- [4/6] Filter by automation feasibility
- [5/6] Initialize exploit tasks (risk-based)
- [6/6] Generate assessment report

**Outputs**:
- `results/experiment_report_YYYYMMDD_HHMMSS.json` (human-readable assessment)
- `results/tasks_manifest_YYYYMMDD_HHMMSS.json` (machine-readable task queue)

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
├── parser.py                    # Phase 1: Nessus XML parser
├── policy_config.yaml           # Phase 2: Security policy definitions
├── classifier_v2.py             # Phase 3: LLM vulnerability classifier
├── phase3_enhancements.py       # Phase 3: Few-shot learning, metrics, calibration
├── examples.json                # Phase 3: 30 labeled examples for few-shot
├── task_manager.py              # Phase 4: Risk scoring and task management
├── feasibility_filter.py        # Phase 5: Automation feasibility filter
├── exploit_generator.py         # Phase 6: Multi-language exploit generator
├── experiment.py                # Pipeline orchestrator (6 stages)
├── auvap_nessus_25_findings.xml # Sample Nessus report
├── results/                     # Pipeline outputs
│   ├── experiment_report_*.json       # Human-readable assessment
│   └── tasks_manifest_*.json          # Machine-readable task queue
└── exploits/                    # Generated exploits (Phase 6)
    └── exploits_YYYYMMDD_HHMMSS/
        ├── 10_0_1_5/            # Grouped by host
        │   ├── CVE_2020_1938_unknown.py
        │   └── CVE_2021_41773_unknown.py
        ├── 10_0_1_7/
        │   ├── CVE_2017_0144_unknown.ps1  # PowerShell
        │   └── CVE_2017_7269_unknown.ps1
        └── exploits_manifest.json
```

## 🎯 Advanced Features

### Phase 2: Policy-Based Filtering
Configure organizational security policies in `policy_config.yaml`:

```yaml
rules:
  - name: "Defer low-severity findings"
    pattern: "cvss < 4.0"
    action: "ignore"
    reason: "Low-severity findings deferred per risk acceptance policy"
  
  - name: "Manual review for production DBs"
    pattern: "service == 'postgresql' AND environment == 'production'"
    action: "force_manual"
    priority: "critical"
```

**Rule Types**:
- `ignore`: Exclude from pipeline (with audit trail)
- `force_manual`: Require human review
- `prioritize`: Boost priority level

### Phase 3: Few-Shot Learning & Metrics

**DynamicFewShotSelector**: Automatically selects relevant examples based on semantic similarity
```bash
[*] Few-shot examples enabled
[*] Classifying finding 1/17: Apache Tomcat AJP File Read Vulnerability...
```

**Classification Metrics** (displayed after completion):
```
======================================================================
CLASSIFICATION PERFORMANCE METRICS
======================================================================
Total Processed:      17
Invalid Count:        0 (0.0%)
Avg Latency:          14.837s
P95 Latency:          20.491s
Label Entropy:        1.735 bits

Label Distribution:
  Critical    :   4 ( 23.5%)
  High        :   4 ( 23.5%)
  Medium      :   8 ( 47.1%)
  Low         :   1 (  5.9%)
======================================================================
```

**ClassifierCalibrator**: Adjusts thresholds based on observed false positive rate
```python
θ_adjusted = θ_base + α·(FPR_target - FPR_observed)
```

### Phase 4: Risk-Based Task Management

**Risk Scoring Formula**:
```
r(f) = cvss × w_surface × w_auto

Attack Surface Weights:
  • Network: 1.0
  • Adjacent: 0.7
  • Local: 0.4
  • Physical: 0.2

Automation Weights:
  • Automatable: 1.0
  • Manual: 0.3
```

**Task Summary** (displayed after initialization):
```
======================================================================
EXPLOIT TASK SUMMARY
======================================================================
Total Tasks:     8
State Distribution:
  PLANNED     : 8

Risk Scores:
  Average:  8.18
  Maximum:  9.80
  Minimum:  6.50

Top 5 Highest Risk Tasks:
  1. [ 9.80] 10.0.1.5:8009   - Apache Tomcat AJP File Read Vulnerability
  2. [ 9.80] 10.0.1.11:80    - Shellshock (CVE-2014-6271)
  3. [ 8.10] 10.0.1.5:443    - OpenSSL SM2 Decryption Memory Corruption
======================================================================
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

### Experiment Report (Human-Readable)
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
      "risk_score": 9.8,
      "exploit_notes": "Use AJP protocol to read arbitrary files"
    }
  ]
}
```

### Task Manifest (Machine-Readable)
```json
{
  "metadata": {
    "total_tasks": 12,
    "state_counts": {"PLANNED": 12},
    "avg_risk_score": 8.18,
    "max_risk_score": 9.80
  },
  "tasks": [
    {
      "task_id": "f77ad4e1-edfa-4c54-a794-062fc79efe2d",
      "finding_id": "36e16c1bc8df7a9bc4645e39e7f9babf285b5d61",
      "state": "PLANNED",
      "attempts": 0,
      "target": {"host": "10.0.1.5", "port": 8009, "service": "ajp13"},
      "vulnerability": {
        "cve": "CVE-2020-1938",
        "title": "Apache Tomcat AJP File Read Vulnerability",
        "severity": "Critical"
      },
      "risk_score": 9.8,
      "created_at": "2025-11-09T20:53:50.123456"
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
- **Phase 5**: Exploit execution engine with state management
- **Phase 6**: Result validation and verification
- Additional language support (Ruby, Perl, JavaScript)
- Language-specific safety wrappers for Bash/PowerShell
- Enhanced syntax validation for non-Python languages
- Additional CVE mappings and exploit templates
- Calibrator training on historical data
- Cloud provider integration (AWS/Azure/GCP)

## 📧 Contact

For issues or questions, please open an issue on GitHub.

---

**Remember**: Always obtain proper authorization before conducting security assessments. Unauthorized testing is illegal and unethical.
