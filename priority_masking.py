#!/usr/bin/env python3
"""
Priority Masking Algorithm for AUVAP-PPO

This module implements a dynamic masking system that:
1. Loads LLM-generated exploits and classification reports
2. Prioritizes vulnerabilities by CVSS, feasibility, and attack chain
3. Creates action masks for PPO based on dependencies and priorities
4. Enables sequential execution of exploits in optimal order
"""

import json
import numpy as np
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class PrioritizedTask:
    """Single exploit task with priority and dependency metadata"""
    task_id: str
    cve: str
    cvss_score: float
    host: str
    port: int
    exploit_script: str
    script_language: str
    dependencies: List[str] = field(default_factory=list)
    priority_score: float = 0.0
    is_completed: bool = False
    is_available: bool = False
    requires_auth: bool = False
    provides_credentials: bool = False
    classification: str = "medium"
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return {
            'task_id': self.task_id,
            'cve': self.cve,
            'cvss_score': self.cvss_score,
            'host': self.host,
            'port': self.port,
            'exploit_script': self.exploit_script,
            'script_language': self.script_language,
            'priority_score': self.priority_score,
            'dependencies': self.dependencies,
            'is_completed': self.is_completed,
            'is_available': self.is_available,
            'classification': self.classification
        }


class PriorityMasker:
    """
    Dynamic action masking based on:
    - Risk priority (CVSS scores)
    - Attack chain dependencies
    - Network topology constraints
    - Completed tasks
    """
    
    def __init__(self, 
                 experiment_report_path: str,
                 exploits_manifest_path: str):
        """
        Initialize priority masker with reports.
        
        Args:
            experiment_report_path: Path to results/experiment_report_*.json
            exploits_manifest_path: Path to exploits/exploits_*/exploits_manifest.json
        """
        print(f"\n[Priority Masker] Initializing...")
        print(f"  - Loading experiment report: {experiment_report_path}")
        print(f"  - Loading exploits manifest: {exploits_manifest_path}")
        
        self.tasks = self._load_and_prioritize(
            experiment_report_path,
            exploits_manifest_path
        )
        
        self.completed_tasks = set()
        # Attacker starting point - can reach all 10.0.1.x hosts (external scanner position)
        self.current_access = set()
        for task in self.tasks:
            self.current_access.add(task.host)  # External scanner can reach all targets
        self.compromised_credentials = {}
        
        print(f"[Priority Masker] Loaded {len(self.tasks)} tasks")
        print(f"[Priority Masker] Initial access: {self.current_access}")
        
    def _load_and_prioritize(self, 
                            report_path: str,
                            manifest_path: str) -> List[PrioritizedTask]:
        """Load reports and create prioritized task list"""
        
        # Load classification report
        with open(report_path, 'r') as f:
            report = json.load(f)
        
        # Load exploit scripts manifest
        with open(manifest_path, 'r') as f:
            manifest = json.load(f)
        
        tasks = []
        
        # Process feasible vulnerabilities from detailed findings (has CVE field)
        feasible = []
        for vuln_data in report.get('feasible_findings_detailed', []):
            # Use data directly from feasible_findings_detailed which has all fields
            vuln = {
                'host': vuln_data.get('host_ip', ''),
                'hostname': vuln_data.get('hostname', ''),
                'os': vuln_data.get('os', ''),
                'cve': vuln_data.get('cve'),  # Use actual CVE field (can be null)
                'title': vuln_data.get('title', ''),
                'cvss_score': vuln_data.get('cvss', 5.0),
                'port': vuln_data.get('port', 0),
                'service': vuln_data.get('service', ''),
                'severity': vuln_data.get('severity_bucket', 'medium'),
                'attack_vector': vuln_data.get('attack_vector', 'Network'),
                'classification': vuln_data.get('severity_bucket', 'medium')
            }
            feasible.append(vuln)
        
        print(f"[Priority Masker] Found {len(feasible)} feasible vulnerabilities")
        
        for idx, vuln in enumerate(feasible):
            # Find corresponding exploit script
            script_info = self._find_exploit_script(vuln, manifest)
            
            # Calculate priority score
            priority = self._calculate_priority(vuln)
            
            # Determine dependencies (attack chain)
            deps = self._extract_dependencies(vuln, feasible)
            
            task = PrioritizedTask(
                task_id=f"task_{idx}",
                cve=vuln.get('cve'),  # Keep None if null, don't convert to string yet
                cvss_score=vuln.get('cvss_score', 5.0),
                host=vuln.get('host', '10.0.1.1'),
                port=vuln.get('port', 0),
                exploit_script=script_info['script_path'],
                script_language=script_info['language'],
                dependencies=deps,
                priority_score=priority,
                requires_auth=vuln.get('requires_authentication', False),
                provides_credentials=vuln.get('provides_credentials', False),
                classification=vuln.get('classification', 'medium')
            )
            tasks.append(task)
        
        # Sort by priority (highest first)
        tasks.sort(key=lambda t: t.priority_score, reverse=True)
        
        print(f"[Priority Masker] Top 3 priorities:")
        for i, task in enumerate(tasks[:3]):
            cve_display = task.cve if task.cve else "NO_CVE"
            print(f"  {i+1}. {cve_display} @ {task.host} (Priority: {task.priority_score:.1f})")
        
        return tasks
    
    def _calculate_priority(self, vulnerability: Dict) -> float:
        """
        Priority scoring formula:
        
        Priority = w1·CVSS + w2·Feasibility + w3·Impact + w4·Chain_Position
        
        Returns:
            float: Priority score (0-100)
        """
        cvss = vulnerability.get('cvss_score', 5.0)
        
        # Parse classification into feasibility score
        classification = vulnerability.get('classification', 'medium').lower()
        feasibility_map = {
            'critical': 1.0,
            'high': 0.75,
            'medium': 0.5,
            'low': 0.25
        }
        feasibility = feasibility_map.get(classification, 0.5)
        
        # Impact based on severity
        impact_map = {
            'critical': 1.0,
            'high': 0.75,
            'medium': 0.5,
            'low': 0.25
        }
        severity = vulnerability.get('severity', 'medium').lower()
        impact = impact_map.get(severity, 0.5)
        
        # Chain position: Entry points get bonus
        is_entry_point = not vulnerability.get('requires_authentication', False)
        chain_bonus = 20 if is_entry_point else 0
        
        # Weighted sum
        priority = (
            0.4 * (cvss * 10) +           # CVSS contribution (0-40)
            0.3 * (feasibility * 100) +    # Feasibility (0-30)
            0.2 * (impact * 100) +         # Impact (0-20)
            0.1 * chain_bonus              # Chain position (0-10)
        )
        
        return priority
    
    def _extract_dependencies(self, 
                             vulnerability: Dict,
                             all_vulnerabilities: List[Dict]) -> List[str]:
        """
        Determine which tasks must complete before this one.
        
        Dependencies based on:
        - Network topology (must compromise gateway first)
        - Credential requirements (must steal creds first)
        """
        deps = []
        
        target_host = vulnerability.get('host', '')
        
        # Check if target requires lateral movement
        for other_idx, other_vuln in enumerate(all_vulnerabilities):
            if other_vuln.get('host') == target_host:
                continue
            
            # If target is internal and other vuln is on gateway
            if (self._is_internal_host(target_host) and 
                self._is_gateway(other_vuln.get('host', ''))):
                deps.append(f"task_{other_idx}")
            
            # If this vuln requires credentials from another
            if (vulnerability.get('requires_authentication', False) and 
                other_vuln.get('provides_credentials', False)):
                deps.append(f"task_{other_idx}")
        
        return deps
    
    def _extract_cve_from_title(self, title: str) -> str:
        """Extract CVE ID from vulnerability title"""
        import re
        match = re.search(r'CVE-\d{4}-\d+', title)
        return match.group(0) if match else 'NO_CVE'
    
    def _is_internal_host(self, host: str) -> bool:
        """Check if host is internal (not gateway)"""
        if not host or len(host.split('.')) < 4:
            return False
        # Simple heuristic: 10.0.1.X are gateways, 10.0.2+ are internal
        third_octet = host.split('.')[2]
        return int(third_octet) > 1
    
    def _is_gateway(self, host: str) -> bool:
        """Check if host is a gateway/DMZ"""
        if not host or len(host.split('.')) < 4:
            return False
        return host.split('.')[2] == '1'
    
    def _find_exploit_script(self, 
                            vulnerability: Dict,
                            manifest: Dict) -> Dict:
        """Find corresponding exploit script in manifest"""
        cve = vulnerability.get('cve')  # Can be None/null
        host = vulnerability.get('host', '')
        port = vulnerability.get('port', 0)
        
        # The manifest structure uses 'manifests' not 'exploits'
        for script in manifest.get('manifests', []):
            script_cve = script.get('cve')  # Can be None/null
            script_target = script.get('target', '')
            
            # Parse target to get host and port
            if ':' in script_target:
                script_host, script_port = script_target.split(':')
                script_port = int(script_port)
            else:
                script_host = script_target
                script_port = 0
            
            # Match by host and port first, then CVE
            # For null CVE, match only on host:port
            host_match = (script_host == host and script_port == port)
            cve_match = (script_cve == cve)  # Works for null==null too
            
            if host_match and cve_match:
                script_path = script.get('script_path', '')
                # Detect language from file extension
                if script_path.endswith('.ps1'):
                    language = 'powershell'
                elif script_path.endswith('.sh'):
                    language = 'bash'
                else:
                    language = 'python'
                
                return {
                    'script_path': script_path,
                    'language': language
                }
        
        # Fallback if not found
        cve_str = cve if cve else 'NO_CVE'
        return {
            'script_path': f"exploits/unknown/{cve_str}.py",
            'language': 'python'
        }
    
    def get_action_mask(self) -> np.ndarray:
        """
        Generate binary mask for current state.
        
        Returns:
            np.ndarray: Shape (num_tasks,) where:
                1 = action available (dependencies met)
                0 = action blocked (dependencies not met or completed)
        """
        mask = np.zeros(len(self.tasks), dtype=np.int8)
        
        for i, task in enumerate(self.tasks):
            # Skip completed tasks
            if task.is_completed:
                mask[i] = 0
                continue
            
            # Check if dependencies are satisfied
            deps_satisfied = all(
                dep_id in self.completed_tasks
                for dep_id in task.dependencies
            )
            
            # Check if we have network access to target
            has_access = task.host in self.current_access
            
            # Check if we have required credentials
            has_creds = not task.requires_auth or \
                       task.host in self.compromised_credentials
            
            # Enable action if all conditions met
            if deps_satisfied and has_access and has_creds:
                mask[i] = 1
                task.is_available = True
            else:
                mask[i] = 0
                task.is_available = False
        
        return mask
    
    def get_prioritized_tasks(self) -> List[PrioritizedTask]:
        """Get tasks sorted by priority with availability status"""
        return [t for t in self.tasks if not t.is_completed]
    
    def mark_completed(self, task_id: str, success: bool = True):
        """
        Mark task as completed and update state.
        
        Args:
            task_id: Task identifier
            success: Whether exploit succeeded
        """
        for task in self.tasks:
            if task.task_id == task_id:
                task.is_completed = True
                self.completed_tasks.add(task_id)
                
                if success:
                    # Add compromised host to accessible network
                    self.current_access.add(task.host)
                    
                    # Add any connected subnets
                    self._expand_access(task.host)
                    
                # Store credentials if provided
                if task.provides_credentials:
                    self.compromised_credentials[task.host] = True
                
                print(f"[Priority Masker] [COMPLETED] Task {task_id} (success={success})")
                print(f"                  Current access: {len(self.current_access)} hosts")
                
                break
    
    def _expand_access(self, compromised_host: str):
        """Add hosts reachable from compromised host"""
        # Simple heuristic: Same /24 subnet
        parts = compromised_host.split('.')
        if len(parts) >= 3:
            subnet = '.'.join(parts[:3])
            
            for task in self.tasks:
                if task.host.startswith(subnet):
                    self.current_access.add(task.host)
    
    def get_next_action(self) -> Tuple[Optional[int], Optional[PrioritizedTask]]:
        """
        Get highest priority available action.
        
        Returns:
            (action_index, task): Next action to execute, or (None, None) if none available
        """
        mask = self.get_action_mask()
        available_indices = np.where(mask == 1)[0]
        
        if len(available_indices) == 0:
            return None, None
        
        # Return first available (already sorted by priority)
        action_idx = int(available_indices[0])
        return action_idx, self.tasks[action_idx]
    
    def get_task_by_index(self, index: int) -> Optional[PrioritizedTask]:
        """Get task by index"""
        if 0 <= index < len(self.tasks):
            return self.tasks[index]
        return None
    
    def print_status(self):
        """Print current task status for debugging"""
        print("\n" + "="*70)
        print("PRIORITY-MASKED TASK LIST")
        print("="*70)
        print(f"Progress: {len(self.completed_tasks)}/{len(self.tasks)} completed")
        print(f"Network Access: {len(self.current_access)} hosts accessible")
        print(f"Credentials: {len(self.compromised_credentials)} hosts compromised")
        print("\nTask Queue (ordered by priority):")
        print("-"*70)
        
        for i, task in enumerate(self.tasks):
            if task.is_completed:
                status = "[DONE]  "
                color = ""
            elif task.is_available:
                status = "[READY] "
                color = ""
            else:
                status = "[BLOCKED]"
                color = ""
            
            cve_display = task.cve if task.cve else "NO_CVE"
            print(f"{i+1:2d}. {status} "
                  f"Priority={task.priority_score:5.1f} | "
                  f"{cve_display:20s} | "
                  f"{task.host}:{task.port} | "
                  f"{task.script_language}")
            
            if task.dependencies and not task.is_completed:
                print(f"     └─ Depends on: {', '.join(task.dependencies)}")
        
        print("="*70 + "\n")
    
    def save_priority_list(self, output_path: str):
        """Save prioritized task list to JSON"""
        output = {
            'total_tasks': len(self.tasks),
            'completed_tasks': len(self.completed_tasks),
            'available_tasks': sum(1 for t in self.tasks if t.is_available),
            'accessible_hosts': list(self.current_access),
            'tasks': [task.to_dict() for task in self.tasks]
        }
        
        with open(output_path, 'w') as f:
            json.dump(output, f, indent=2)
        
        print(f"[Priority Masker] Priority list saved to: {output_path}")


def main():
    """Demo: Load reports and create prioritized task list"""
    import sys
    
    if len(sys.argv) < 3:
        print("Usage: python priority_masking.py <experiment_report.json> <exploits_manifest.json>")
        print("\nExample:")
        print("  python priority_masking.py \\")
        print("    results/experiment_report_20251111_023313.json \\")
        print("    exploits/exploits_20251111_023313/exploits_manifest.json")
        sys.exit(1)
    
    report_path = sys.argv[1]
    manifest_path = sys.argv[2]
    
    # Initialize masker
    masker = PriorityMasker(report_path, manifest_path)
    
    # Show initial status
    masker.print_status()
    
    # Simulate sequential execution
    print("\n" + "="*70)
    print("SIMULATING SEQUENTIAL ATTACK EXECUTION")
    print("="*70)
    
    step = 0
    while True:
        action_idx, task = masker.get_next_action()
        
        if task is None:
            print("\n[Simulation] No more available actions. Attack sequence complete!")
            break
        
        step += 1
        print(f"\nStep {step}: Executing action {action_idx}")
        print(f"  Task: {task.cve}")
        print(f"  Target: {task.host}:{task.port}")
        print(f"  Script: {task.exploit_script}")
        print(f"  Priority: {task.priority_score:.1f}")
        
        # Simulate execution (random success for demo)
        import random
        success = random.random() > 0.2  # 80% success rate
        
        print(f"  Result: {'✅ SUCCESS' if success else '❌ FAILED'}")
        
        # Update state
        masker.mark_completed(task.task_id, success)
        
        # Stop after 10 steps for demo
        if step >= 10:
            print("\n[Simulation] Stopping after 10 steps (demo limit)")
            break
    
    # Show final status
    masker.print_status()
    
    # Save priority list
    output_path = "results/priority_task_list.json"
    masker.save_priority_list(output_path)


if __name__ == "__main__":
    main()
