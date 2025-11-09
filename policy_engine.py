#!/usr/bin/env python3
"""
policy_engine.py - Policy-Aware Filtering for AUVAP

Implements Algorithm 2: POLICY_FILTER from research paper.

Applies organizational security policies BEFORE costly LLM classification.
Supports rule precedence hierarchy to handle conflicting policies.
"""

import sys
from dataclasses import dataclass
from typing import Callable, Literal


@dataclass
class PolicyRule:
    """
    Represents a single policy rule for filtering vulnerability findings.
    
    Attributes:
        rule_id: Unique identifier for the rule (e.g., "RULE-001")
        type: Action type - "ignore" (skip finding), "force_manual" (require human),
              or "prioritize" (must automate)
        predicate: Function that tests if rule applies to a finding
        reason: Human-readable explanation of why rule exists
        precedence: Priority level - 0 (highest), 1 (medium), 2 (lowest)
                   Level 0: User-level overrides (analyst decisions)
                   Level 1: Organizational policy (security team rules)
                   Level 2: Baseline/default rules (framework defaults)
    """
    rule_id: str
    type: Literal["ignore", "force_manual", "prioritize"]
    predicate: Callable[[dict], bool]
    reason: str
    precedence: int
    
    def evaluate(self, finding: dict) -> bool:
        """
        Test if this rule applies to the given finding.
        
        Args:
            finding: Vulnerability finding dictionary
            
        Returns:
            True if rule's predicate matches the finding
        """
        try:
            return self.predicate(finding)
        except Exception as e:
            print(f"[WARNING] Rule {self.rule_id} evaluation failed: {e}", file=sys.stderr)
            return False


class PolicyEngine:
    """
    Manages and evaluates policy rules with precedence handling.
    
    Rules are evaluated in order of precedence (0 = highest priority).
    First matching rule determines the action.
    """
    
    def __init__(self):
        """Initialize empty policy engine."""
        self.rules: list[PolicyRule] = []
    
    def add_rule(self, rule: PolicyRule) -> None:
        """
        Add a policy rule and maintain sorted order by precedence.
        
        Args:
            rule: PolicyRule to add
        """
        self.rules.append(rule)
        # Sort by precedence (ascending) so highest priority (0) comes first
        self.rules.sort(key=lambda r: r.precedence)
    
    def add_rules(self, rules: list[PolicyRule]) -> None:
        """
        Add multiple policy rules at once.
        
        Args:
            rules: List of PolicyRule objects
        """
        for rule in rules:
            self.add_rule(rule)
    
    def evaluate(self, finding: dict) -> tuple[str, str, str]:
        """
        Evaluate finding against all rules, returning first match.
        
        Args:
            finding: Vulnerability finding dictionary
            
        Returns:
            Tuple of (action, reason, rule_id):
                - action: "ignore", "force_manual", "prioritize", or "allow"
                - reason: Human-readable explanation
                - rule_id: ID of matching rule (or "NO_MATCH" if no rules matched)
        """
        for rule in self.rules:
            if rule.evaluate(finding):
                return (rule.type, rule.reason, rule.rule_id)
        
        # No rules matched - allow finding through to next stage
        return ("allow", "No policy rules matched", "NO_MATCH")
    
    def get_rule_count(self) -> int:
        """Return total number of rules in engine."""
        return len(self.rules)
    
    def get_rules_by_type(self) -> dict[str, int]:
        """
        Get breakdown of rules by type.
        
        Returns:
            Dictionary mapping rule type to count
        """
        counts = {"ignore": 0, "force_manual": 0, "prioritize": 0}
        for rule in self.rules:
            counts[rule.type] = counts.get(rule.type, 0) + 1
        return counts


def create_default_policy_rules() -> list[PolicyRule]:
    """
    Create default policy rules for common scenarios.
    
    Returns:
        List of PolicyRule objects with precedence level 2 (baseline)
    """
    rules = []
    
    # Rule: Ignore informational findings (CVSS = 0)
    rules.append(PolicyRule(
        rule_id="DEFAULT-001",
        type="ignore",
        predicate=lambda f: f.get("cvss") == 0.0 or f.get("severity_text", "").lower() == "none",
        reason="Informational finding with no security impact (CVSS = 0)",
        precedence=2
    ))
    
    # Rule: Force manual review for kernel/OS vulnerabilities
    rules.append(PolicyRule(
        rule_id="DEFAULT-002",
        type="force_manual",
        predicate=lambda f: any(kw in f.get("title", "").lower() 
                               for kw in ["kernel", "operating system", "privilege escalation"]),
        reason="Kernel/OS vulnerabilities require expert analysis before automation",
        precedence=2
    ))
    
    # Rule: Prioritize remote code execution
    rules.append(PolicyRule(
        rule_id="DEFAULT-003",
        type="prioritize",
        predicate=lambda f: any(kw in f.get("title", "").lower() 
                               for kw in ["remote code execution", "rce", "command injection"]),
        reason="Remote code execution is high-priority for automated testing",
        precedence=2
    ))
    
    return rules


def emit_policy_metrics(selected: list[dict], ignored: list[dict]) -> dict:
    """
    Calculate and emit policy filter metrics.
    
    Args:
        selected: Findings that passed policy filter
        ignored: Findings that were filtered out
        
    Returns:
        Dictionary with metrics:
            - coverage_ratio (ρ): |selected| / |total_findings|
            - ignore_breakdown: Count by ignore_reason
            - total_findings: Total input findings
            - selected_findings: Findings that passed
            - ignored_findings: Findings that were filtered
    """
    total = len(selected) + len(ignored)
    
    # Calculate coverage ratio
    coverage_ratio = len(selected) / total if total > 0 else 0.0
    
    # Build breakdown by ignore reason
    ignore_breakdown = {}
    for finding in ignored:
        reason = finding.get("policy_reason", "Unknown")
        ignore_breakdown[reason] = ignore_breakdown.get(reason, 0) + 1
    
    metrics = {
        "coverage_ratio": coverage_ratio,
        "ignore_breakdown": ignore_breakdown,
        "total_findings": total,
        "selected_findings": len(selected),
        "ignored_findings": len(ignored)
    }
    
    # Print metrics to stderr
    print(f"[METRICS] Phase 2 Policy Filter:", file=sys.stderr)
    print(f"  Total findings: {metrics['total_findings']}", file=sys.stderr)
    print(f"  Selected: {metrics['selected_findings']}", file=sys.stderr)
    print(f"  Ignored: {metrics['ignored_findings']}", file=sys.stderr)
    print(f"  Coverage ratio (ρ): {metrics['coverage_ratio']:.3f}", file=sys.stderr)
    
    if ignore_breakdown:
        print(f"  Ignore breakdown:", file=sys.stderr)
        for reason, count in sorted(ignore_breakdown.items(), key=lambda x: -x[1]):
            print(f"    - {reason}: {count}", file=sys.stderr)
    
    return metrics


def apply_policy_filter(findings: list[dict], policy_engine: PolicyEngine) -> tuple[list[dict], list[dict]]:
    """
    Apply policy engine to findings, separating selected from ignored.
    
    Adds policy metadata to each finding:
        - policy_action: "allow", "ignore", "force_manual", "prioritize"
        - policy_reason: Explanation of policy decision
        - policy_rule_id: ID of matching rule
        - hints: Dict with force_manual flag and manual_reason if applicable
    
    Args:
        findings: List of vulnerability finding dictionaries
        policy_engine: Configured PolicyEngine with rules
        
    Returns:
        Tuple of (selected_findings, ignored_findings)
    """
    selected = []
    ignored = []
    
    for finding in findings:
        action, reason, rule_id = policy_engine.evaluate(finding)
        
        # Add policy metadata
        finding["policy_action"] = action
        finding["policy_reason"] = reason
        finding["policy_rule_id"] = rule_id
        
        if action == "ignore":
            ignored.append(finding)
        elif action == "force_manual":
            # Add hints for LLM to know this requires manual review
            finding["hints"] = {
                "force_manual": True,
                "manual_reason": reason,
                "rule_id": rule_id
            }
            selected.append(finding)
        elif action == "prioritize":
            # Add hints for high priority
            finding["hints"] = {
                "prioritize": True,
                "priority_reason": reason,
                "rule_id": rule_id
            }
            selected.append(finding)
        else:  # action == "allow"
            selected.append(finding)
    
    return selected, ignored


def main():
    """Test policy engine with sample findings."""
    print("=" * 70)
    print("POLICY ENGINE TEST")
    print("=" * 70)
    print()
    
    # Create policy engine with default rules
    engine = PolicyEngine()
    engine.add_rules(create_default_policy_rules())
    
    # Add custom organizational rule (precedence 1)
    engine.add_rule(PolicyRule(
        rule_id="ORG-001",
        type="ignore",
        predicate=lambda f: f.get("port") in [8080, 33],
        reason="Port 8080 and 33 are company standard dev ports (approved by InfoSec)",
        precedence=1
    ))
    
    print(f"Loaded {engine.get_rule_count()} policy rules")
    print(f"Rule types: {engine.get_rules_by_type()}")
    print()
    
    # Test findings
    test_findings = [
        {
            "host_ip": "10.0.1.5",
            "port": 8009,
            "service": "ajp13",
            "cvss": 9.8,
            "severity_text": "Critical",
            "title": "Apache Tomcat AJP Remote Code Execution",
            "cve": "CVE-2020-1938"
        },
        {
            "host_ip": "10.0.1.10",
            "port": 8080,
            "service": "http",
            "cvss": 7.5,
            "severity_text": "High",
            "title": "Unpatched Web Server",
            "cve": "CVE-2023-1234"
        },
        {
            "host_ip": "10.0.1.15",
            "port": 22,
            "service": "ssh",
            "cvss": 0.0,
            "severity_text": "None",
            "title": "SSH Server Banner Disclosure",
            "cve": None
        },
        {
            "host_ip": "10.0.1.20",
            "port": 445,
            "service": "smb",
            "cvss": 8.8,
            "severity_text": "High",
            "title": "Linux Kernel Privilege Escalation",
            "cve": "CVE-2022-5678"
        }
    ]
    
    # Apply policy filter
    selected, ignored = apply_policy_filter(test_findings, engine)
    
    print(f"Selected: {len(selected)} findings")
    for f in selected:
        print(f"  - {f['title']}")
        print(f"    Action: {f['policy_action']} (Rule: {f['policy_rule_id']})")
        if "hints" in f:
            print(f"    Hints: {f['hints']}")
    print()
    
    print(f"Ignored: {len(ignored)} findings")
    for f in ignored:
        print(f"  - {f['title']}")
        print(f"    Reason: {f['policy_reason']} (Rule: {f['policy_rule_id']})")
    print()
    
    # Emit metrics
    metrics = emit_policy_metrics(selected, ignored)
    
    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()
