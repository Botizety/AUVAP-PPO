#!/usr/bin/env python3
"""
feasibility_filter.py - Automated Pentest Feasibility Filter

This module triages classified vulnerability findings to determine which are suitable
candidates for automated penetration testing versus those requiring manual review.

Implements rule-based filtering on LLM-enriched vulnerability data to identify
high-value, remotely accessible, scriptable vulnerabilities.

NO EXPLOITATION IS PERFORMED - This is purely a triage/filtering module.
"""

import json
import sys
from typing import Any


def split_feasible(findings: list[dict]) -> tuple[list[dict], list[dict]]:
    """
    Split findings into feasible automation candidates vs manual review required.
    
    Feasibility criteria (ALL must be true):
    1. automation_candidate == True (LLM suggests scriptable)
    2. attack_vector in ["Network", "Adjacent"] (remotely accessible)
    3. severity_bucket in ["High", "Critical"] (high impact)
    4. llm_confidence >= 0.5 (LLM is reasonably confident)
    
    Args:
        findings: List of enriched finding dictionaries from classifier
        
    Returns:
        Tuple of (feasible_findings, non_feasible_findings)
        Each finding gains "auto_feasibility_reason" key explaining the decision
    """
    feasible: list[dict] = []
    non_feasible: list[dict] = []
    
    for finding in findings:
        # Extract relevant fields with safe defaults
        auto_candidate = finding.get("automation_candidate", False)
        attack_vector = finding.get("attack_vector", "")
        severity = finding.get("severity_bucket", "")
        confidence = finding.get("llm_confidence", 0.0)
        
        # Make a copy to avoid mutating input
        enriched = finding.copy()
        
        # Evaluate feasibility criteria
        reasons = []
        is_feasible = True
        
        # Check criterion 1: automation candidate
        if not auto_candidate:
            reasons.append("not marked as automation candidate")
            is_feasible = False
        
        # Check criterion 2: attack vector
        if attack_vector not in ["Network", "Adjacent"]:
            reasons.append(f"attack vector is '{attack_vector}' (requires Network/Adjacent)")
            is_feasible = False
        
        # Check criterion 3: severity
        if severity not in ["High", "Critical"]:
            reasons.append(f"severity is '{severity}' (requires High/Critical)")
            is_feasible = False
        
        # Check criterion 4: confidence threshold
        if confidence < 0.5:
            reasons.append(f"LLM confidence too low ({confidence:.2f} < 0.5)")
            is_feasible = False
        
        # Build reason string
        if is_feasible:
            enriched["auto_feasibility_reason"] = (
                f"Feasible: automation candidate, {attack_vector} accessible, "
                f"{severity} severity, {confidence:.2f} confidence"
            )
            feasible.append(enriched)
        else:
            enriched["auto_feasibility_reason"] = (
                f"Manual review: {'; '.join(reasons)}"
            )
            non_feasible.append(enriched)
    
    return feasible, non_feasible


def build_host_summary(findings: list[dict]) -> dict[str, dict[str, Any]]:
    """
    Build per-host summary statistics for vulnerability findings.
    
    Aggregates findings by host IP and computes:
    - Total finding count
    - Critical/High severity count
    - Feasible automation candidate count
    - Top 3 critical vulnerability titles
    
    Args:
        findings: List of enriched finding dictionaries (must include feasibility_reason)
        
    Returns:
        Dictionary keyed by host_ip with summary statistics
    """
    host_data: dict[str, dict[str, Any]] = {}
    
    for finding in findings:
        host_ip = finding.get("host_ip", "unknown")
        severity = finding.get("severity_bucket", "")
        title = finding.get("title", "Unknown vulnerability")
        
        # Determine if feasible based on presence of positive feasibility reason
        feasibility_reason = finding.get("auto_feasibility_reason", "")
        is_feasible = feasibility_reason.startswith("Feasible:")
        
        # Initialize host entry if not exists
        if host_ip not in host_data:
            host_data[host_ip] = {
                "total_findings": 0,
                "critical_or_high": 0,
                "feasible_candidates": 0,
                "top_critical_titles": []
            }
        
        # Update counters
        host_data[host_ip]["total_findings"] += 1
        
        if severity in ["High", "Critical"]:
            host_data[host_ip]["critical_or_high"] += 1
        
        if is_feasible:
            host_data[host_ip]["feasible_candidates"] += 1
        
        # Track critical titles (limit to 3)
        if severity == "Critical":
            critical_titles = host_data[host_ip]["top_critical_titles"]
            if len(critical_titles) < 3 and title not in critical_titles:
                critical_titles.append(title)
    
    return host_data
