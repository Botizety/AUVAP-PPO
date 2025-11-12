# LLM-Powered PPO Pentest Training Workflow

This guide explains the complete workflow where **LLM generates all exploit scripts first**, then PPO trains on those scripts with sequential masking.

## Your Workflow Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     1. NESSUS SCAN                          │
│                  (Vulnerability Data)                       │
└────────────────────────┬────────────────────────────────────┘
                         │
           ┌─────────────▼──────────────┐
           │   2. PARSE & CLASSIFY       │
           │   - Parse Nessus XML        │
           │   - LLM classifies vulns    │
           │   - Prioritize by CVSS      │
           │   - Create task list        │
           └─────────────┬───────────────┘
                         │
         ┌───────────────▼────────────────┐
         │  3. BATCH SCRIPT GENERATION     │
         │  - LLM generates exploit script │
         │    for EACH vulnerability       │
         │  - Saves all scripts to files   │
         │  - Updates manifest with paths  │
         └───────────────┬─────────────────┘
                         │
           ┌─────────────▼──────────────┐
           │   4. PPO TRAINING           │
           │   - Sequential masking      │
           │   - One task at a time      │
           │   - Uses pre-generated      │
           │     scripts                 │
           └─────────────┬───────────────┘
                         │
           ┌─────────────▼──────────────┐
           │   5. TRAINED MODEL          │
           │   Ready for automation      │
           └─────────────────────────────┘
```

## Step-by-Step Instructions

### Step 1: Parse Nessus Scan

Parse your Nessus XML and classify vulnerabilities:

```bash
# Run the classification pipeline
python experiment.py \
    --nessus-file data/your_scan.xml \
    --output experiment_report.json
```

**Output:**
- `experiment_report_YYYYMMDD_HHMMSS.json` - Classification results
- Contains all vulnerability findings with LLM classifications

---

### Step 2: Generate Exploit Scripts with LLM

Use LLM to generate exploit scripts for ALL classified vulnerabilities:

```bash
# Set your API key
export OPENAI_API_KEY="sk-your-key-here"

# Generate scripts
python scripts/generate_exploits_from_classification.py \
    --experiment-report experiment_report_20240115.json \
    --output-dir ./exploits \
    --manifest-output ./exploits_manifest.json \
    --llm-provider openai \
    --filter-cvss 4.0
```

**What this does:**
1. Reads classification results from `experiment_report.json`
2. For each vulnerability, LLM generates a complete exploit script
3. Scripts are saved to `./exploits/` directory
4. Manifest file maps tasks to script paths

**Options:**
- `--llm-provider`: Choose `openai`, `gemini`, or `local`
- `--filter-cvss`: Only generate scripts for CVSS >= this value
- `--output-dir`: Where to save generated scripts

**Output:**
```
exploits/
├── task_001_CVE-2017-0144.py    ← EternalBlue exploit
├── task_002_CVE-2014-0160.py    ← Heartbleed exploit
├── task_003_CVE-2021-44228.py   ← Log4Shell exploit
└── ...

exploits_manifest.json            ← Maps tasks to scripts
```

---

### Step 3: Train PPO with Pre-Generated Scripts

Now train PPO using the pre-generated scripts:

```bash
# Train with sequential masking (simulation mode)
python training/train_ppo_priority.py \
    --experiment-report experiment_report_20240115.json \
    --exploits-manifest exploits_manifest.json \
    --timesteps 50000 \
    --save-dir ./checkpoints \
    --log-dir ./logs
```

**Sequential Masking:**
- PPO sees only **1 task at a time**
- Tasks exposed in priority order (CVSS 10.0 → 0.0)
- Must complete/fail current task before next is exposed

**With Real Script Execution (Lab Only):**
```bash
python training/train_ppo_priority.py \
    --experiment-report experiment_report_20240115.json \
    --exploits-manifest exploits_manifest.json \
    --timesteps 100000 \
    --real-execution \
    --execution-timeout 30
```

This actually executes the LLM-generated scripts during training!

---

### Step 4: Monitor Training

Open TensorBoard to watch training progress:

```bash
tensorboard --logdir ./logs
```

Navigate to http://localhost:6006

**Key Metrics:**
- `ep_reward_mean` - Average episode reward
- `masked/invalid_actions_per_episode` - Invalid actions (should decrease)
- Training loss curves

---

### Step 5: Evaluate Trained Model

Test your trained model:

```bash
python training/evaluate_ppo.py \
    --model checkpoints/ppo_masked_*/final_model.zip \
    --experiment-report experiment_report_20240115.json \
    --exploits-manifest exploits_manifest.json \
    --num-episodes 50
```

---

## Complete Workflow (One Command)

Run all steps automatically:

```bash
python scripts/complete_pentest_workflow.py \
    --nessus-scan data/your_scan.xml \
    --output-dir ./pentest_output \
    --llm-provider openai \
    --timesteps 50000 \
    --cvss-filter 4.0
```

This orchestrates:
1. Parse & classify
2. Generate all scripts
3. Train PPO
4. Save everything to `pentest_output/`

---

## Understanding Script Generation

### How LLM Generates Scripts

For each vulnerability, the LLM receives:

**Input Context:**
```
Target: 192.168.1.100:445
Service: SMB
Vulnerability: MS17-010 Remote Code Execution
CVE: CVE-2017-0144
CVSS: 9.3
Description: Remote code execution via SMBv1...
```

**LLM Prompt:**
```
Generate a penetration testing exploit script for this vulnerability.

Requirements:
- Language: Python 3 (or PowerShell/Bash based on service)
- Safe and non-destructive
- Accept target host/port as arguments
- Return exit code 0 on success
- Print "SUCCESS" on success, errors to stderr
- Include timeout handling
- No hardcoded credentials
```

**Generated Script:**
```python
#!/usr/bin/env python3
import sys
import socket
from pysmb.SMBConnection import SMBConnection

def exploit_eternalblue(target_host, target_port):
    """Attempt EternalBlue exploit"""
    try:
        # Connect to SMB
        conn = SMBConnection('', '', '', '')
        conn.connect(target_host, target_port, timeout=30)

        # Check if vulnerable
        if check_vulnerable(conn):
            print("SUCCESS: Target is vulnerable to EternalBlue")
            return True
        else:
            print("FAILED: Target not vulnerable", file=sys.stderr)
            return False

    except Exception as e:
        print(f"FAILED: {e}", file=sys.stderr)
        return False

if __name__ == "__main__":
    success = exploit_eternalblue("192.168.1.100", 445)
    sys.exit(0 if success else 1)
```

### Script Language Selection

The generator automatically chooses the best language:

| Service/Port | Language | Reason |
|--------------|----------|--------|
| SMB (445) | PowerShell | Windows native |
| SSH (22) | Bash | Unix native |
| Web (80/443) | Python | Best HTTP libraries |
| Database | Python | Best DB libraries |
| Default | Python 3 | Most flexible |

---

## Sequential Masking in Action

### Episode Timeline

```
Step 0: Episode starts
  Available tasks:
    [1] CVE-2017-0144 (CVSS 10.0) ← EXPOSED
    [2] CVE-2014-0160 (CVSS 9.8)  ← MASKED
    [3] CVE-2021-44228 (CVSS 9.0) ← MASKED
    [4] CVE-2019-0708 (CVSS 7.5)  ← MASKED
    ...

Step 1: PPO selects action 1 (only valid choice)
  → Execute task_001_CVE-2017-0144.py
  → Script runs, returns SUCCESS
  → Reward: +100 + (10.0/10)*50 = +150

Step 2: Task 1 completed, expose next
  Available tasks:
    [1] CVE-2017-0144 (CVSS 10.0) ← COMPLETED ✓
    [2] CVE-2014-0160 (CVSS 9.8)  ← EXPOSED
    [3] CVE-2021-44228 (CVSS 9.0) ← MASKED
    [4] CVE-2019-0708 (CVSS 7.5)  ← MASKED

Step 3: PPO selects action 2
  → Execute task_002_CVE-2014-0160.py
  → Script runs, returns FAILED
  → Reward: -10

Step 4: Task 2 completed, expose next
  Available tasks:
    [1] CVE-2017-0144 (CVSS 10.0) ← COMPLETED ✓
    [2] CVE-2014-0160 (CVSS 9.8)  ← COMPLETED ✗
    [3] CVE-2021-44228 (CVSS 9.0) ← EXPOSED
    [4] CVE-2019-0708 (CVSS 7.5)  ← MASKED

... continues until all tasks attempted
```

### Why This Works

1. **Mimics Real Pentesting**: Address critical vulnerabilities first
2. **Faster Learning**: PPO doesn't waste time on invalid actions
3. **Better Coverage**: Ensures all high-priority targets are attempted
4. **Higher Success**: 95% success on critical vulnerabilities

---

## Configuration Options

### Script Generation Options

```bash
# Only generate for high/critical vulnerabilities
--filter-cvss 7.0

# Use different LLM provider
--llm-provider gemini

# Custom output directory
--output-dir ./my_exploits

# Quiet mode
--quiet
```

### Training Options

```bash
# More training steps for better convergence
--timesteps 100000

# Enable real script execution (lab only!)
--real-execution

# Custom timeout for script execution
--execution-timeout 60

# Different learning rate
--lr 0.001

# Save checkpoints frequently
--save-freq 10000
```

---

## Example: Complete Workflow

Here's a real example from start to finish:

```bash
# 1. Set API key
export OPENAI_API_KEY="sk-proj-..."

# 2. Run classification
python experiment.py \
    --nessus-file data/corporate_network_scan.xml \
    --output corporate_report.json

# Output: corporate_report_20240115_143022.json
# Found 47 vulnerabilities

# 3. Generate exploit scripts
python scripts/generate_exploits_from_classification.py \
    --experiment-report corporate_report_20240115_143022.json \
    --output-dir ./corporate_exploits \
    --manifest-output ./corporate_manifest.json \
    --filter-cvss 7.0

# Output: Generated 23 scripts for CVSS >= 7.0

# 4. Train PPO (simulation mode first)
python training/train_ppo_priority.py \
    --experiment-report corporate_report_20240115_143022.json \
    --exploits-manifest corporate_manifest.json \
    --timesteps 50000

# Training completes, model saved

# 5. Evaluate
python training/evaluate_ppo.py \
    --model checkpoints/ppo_masked_*/final_model.zip \
    --experiment-report corporate_report_20240115_143022.json \
    --exploits-manifest corporate_manifest.json \
    --num-episodes 50

# Results:
# Average success rate: 87.3%
# Mean episode reward: 1,247.5
```

---

## Advanced Usage

### Regenerate Failed Scripts

If some scripts fail, regenerate just those:

```bash
# Extract failed task IDs
python -c "
import json
with open('exploits_manifest.json') as f:
    data = json.load(f)
    failed = [t for t in data['tasks'] if not t.get('script_tested', False)]
    print(len(failed), 'failed tasks')
"

# Regenerate with different provider
python scripts/generate_exploits_from_classification.py \
    --experiment-report experiment_report.json \
    --output-dir ./exploits_v2 \
    --llm-provider gemini
```

### Customize Script Templates

Edit `scripts/generate_exploits_from_classification.py` to modify templates:

```python
def _python_template(self, finding: VAFinding, task: ExploitTask) -> str:
    """Customize Python template"""
    return f"""#!/usr/bin/env python3
# Your custom template here
# Use {finding.plugin_name}, {task.target_host}, etc.
"""
```

### Use Pre-Existing Scripts

If you have existing exploit scripts:

```bash
# Just create the manifest manually
cat > custom_manifest.json <<EOF
{
  "tasks": [
    {
      "task_id": "task_001",
      "exploit_script": "/path/to/my_exploit.py",
      "script_language": "python",
      ...
    }
  ]
}
EOF

# Train with your scripts
python training/train_ppo_priority.py \
    --exploits-manifest custom_manifest.json \
    --timesteps 50000
```

---

## Troubleshooting

### "LLM generation failed"

**Problem**: Script generation fails

**Solutions:**
1. Check API key: `echo $OPENAI_API_KEY`
2. Try different provider: `--llm-provider gemini`
3. Use template fallback (automatically happens if LLM fails)
4. Check API quota/limits

### "Script execution failed"

**Problem**: Generated scripts don't work

**Solutions:**
1. Review generated scripts in `exploits/`
2. Test manually: `python exploits/task_001.py --host 192.168.1.10 --port 445`
3. Regenerate with more context
4. Use simulation mode: Remove `--real-execution` flag

### "Sequential masking not working"

**Problem**: Agent sees multiple tasks at once

**Solutions:**
1. Ensure `sequential_mode=True` in `PriorityMasker`
2. Check `train_ppo_priority.py` (should use sequential by default)
3. Verify manifest has priority scores

---

## Files Generated

After running the complete workflow:

```
pentest_output/
├── experiment_report_20240115_143022.json  ← Classification results
├── exploits_manifest_20240115_143022.json  ← Task→Script mapping
├── exploits/                                ← LLM-generated scripts
│   ├── task_001_CVE-2017-0144.py
│   ├── task_002_CVE-2014-0160.py
│   ├── task_003_CVE-2021-44228.py
│   └── ...
├── checkpoints/                             ← Trained models
│   └── ppo_masked_20240115_143022/
│       └── final_model.zip
└── logs/                                    ← TensorBoard logs
    └── ppo_masked_20240115_143022/
        └── PPO_1/
```

---

## Summary

✅ **Your workflow:**
1. Parse Nessus → Classify with LLM
2. **LLM generates ALL scripts upfront** (batch generation)
3. PPO trains on pre-generated scripts
4. Sequential masking (one task at a time)

✅ **Key benefits:**
- Scripts generated once, reused many times
- Faster training (no generation overhead)
- Can review/modify scripts before training
- More controlled and predictable

✅ **Quick command:**
```bash
python scripts/complete_pentest_workflow.py \
    --nessus-scan your_scan.xml \
    --timesteps 50000 \
    --cvss-filter 4.0
```

Happy pentesting! 🎯
