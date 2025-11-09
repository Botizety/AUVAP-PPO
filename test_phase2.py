#!/usr/bin/env python3
"""
Test Suite for Phase 2: Policy/Preference Filter

Tests implementation of Algorithm 2: POLICY_FILTER from research paper:
- PolicyRule dataclass
- PolicyEngine with precedence hierarchy
- Rule evaluation and matching
- Policy metrics calculation
- Force-manual hints
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from policy_engine import (
    PolicyRule,
    PolicyEngine,
    create_default_policy_rules,
    apply_policy_filter,
    emit_policy_metrics
)


def test_policy_rule_creation():
    """Test PolicyRule dataclass creation."""
    print("\n=== Test 1: Policy Rule Creation ===")
    
    rule = PolicyRule(
        rule_id="TEST-001",
        type="ignore",
        predicate=lambda f: f.get("port") == 8080,
        reason="Test port exclusion",
        precedence=1
    )
    
    assert rule.rule_id == "TEST-001"
    assert rule.type == "ignore"
    assert rule.precedence == 1
    
    # Test evaluation
    finding_match = {"port": 8080, "title": "Web vuln"}
    finding_nomatch = {"port": 443, "title": "TLS vuln"}
    
    assert rule.evaluate(finding_match) == True
    assert rule.evaluate(finding_nomatch) == False
    
    print("✅ PolicyRule creation and evaluation works")
    return True


def test_precedence_hierarchy():
    """Test that rule precedence is respected (lower number = higher priority)."""
    print("\n=== Test 2: Rule Precedence Hierarchy ===")
    
    engine = PolicyEngine()
    
    # Add rules in random order
    rule_low = PolicyRule(
        rule_id="LOW-PRIORITY",
        type="ignore",
        predicate=lambda f: f.get("port") == 22,
        reason="Low priority rule",
        precedence=2  # Baseline
    )
    
    rule_high = PolicyRule(
        rule_id="HIGH-PRIORITY",
        type="prioritize",
        predicate=lambda f: f.get("port") == 22,
        reason="High priority override",
        precedence=0  # User-level
    )
    
    rule_med = PolicyRule(
        rule_id="MED-PRIORITY",
        type="force_manual",
        predicate=lambda f: f.get("port") == 22,
        reason="Medium priority rule",
        precedence=1  # Organizational
    )
    
    # Add in wrong order intentionally
    engine.add_rule(rule_low)
    engine.add_rule(rule_high)
    engine.add_rule(rule_med)
    
    # Evaluate - should match highest precedence (0) first
    finding = {"port": 22, "service": "ssh"}
    action, reason, rule_id = engine.evaluate(finding)
    
    print(f"Matched rule: {rule_id} (precedence 0)")
    print(f"Action: {action}")
    
    assert rule_id == "HIGH-PRIORITY", "Should match precedence 0 rule first"
    assert action == "prioritize"
    
    print("✅ Rule precedence hierarchy works correctly")
    return True


def test_force_manual_hints():
    """Test that force_manual rules add hints to findings."""
    print("\n=== Test 3: Force Manual Hints ===")
    
    engine = PolicyEngine()
    engine.add_rule(PolicyRule(
        rule_id="MANUAL-001",
        type="force_manual",
        predicate=lambda f: "kernel" in f.get("title", "").lower(),
        reason="Kernel vulnerabilities need expert review",
        precedence=1
    ))
    
    findings = [
        {
            "host_ip": "10.0.1.5",
            "title": "Linux Kernel Privilege Escalation",
            "cvss": 7.8
        }
    ]
    
    selected, ignored = apply_policy_filter(findings, engine)
    
    assert len(selected) == 1, "Finding should be selected (not ignored)"
    assert len(ignored) == 0
    
    finding = selected[0]
    assert "hints" in finding, "Should have hints dict"
    assert finding["hints"]["force_manual"] == True
    assert "manual_reason" in finding["hints"]
    assert finding["hints"]["rule_id"] == "MANUAL-001"
    
    print(f"Hints added: {finding['hints']}")
    print("✅ Force manual hints work correctly")
    return True


def test_ignore_action():
    """Test that ignore rules filter out findings."""
    print("\n=== Test 4: Ignore Action ===")
    
    engine = PolicyEngine()
    engine.add_rule(PolicyRule(
        rule_id="IGNORE-001",
        type="ignore",
        predicate=lambda f: f.get("cvss", 0) == 0.0,
        reason="Informational findings (CVSS 0)",
        precedence=2
    ))
    
    findings = [
        {"host_ip": "10.0.1.5", "title": "Info disclosure", "cvss": 0.0},
        {"host_ip": "10.0.1.10", "title": "RCE vuln", "cvss": 9.8}
    ]
    
    selected, ignored = apply_policy_filter(findings, engine)
    
    assert len(selected) == 1, "One finding should be selected"
    assert len(ignored) == 1, "One finding should be ignored"
    
    assert ignored[0]["title"] == "Info disclosure"
    assert ignored[0]["policy_action"] == "ignore"
    assert ignored[0]["policy_rule_id"] == "IGNORE-001"
    
    print(f"Ignored: {ignored[0]['title']}")
    print(f"Reason: {ignored[0]['policy_reason']}")
    print("✅ Ignore action filters correctly")
    return True


def test_prioritize_hints():
    """Test that prioritize rules add priority hints."""
    print("\n=== Test 5: Prioritize Hints ===")
    
    engine = PolicyEngine()
    engine.add_rule(PolicyRule(
        rule_id="PRIORITY-001",
        type="prioritize",
        predicate=lambda f: "remote code execution" in f.get("title", "").lower(),
        reason="RCE is high priority for testing",
        precedence=1
    ))
    
    findings = [
        {"host_ip": "10.0.1.5", "title": "Remote Code Execution via Apache", "cvss": 9.8}
    ]
    
    selected, ignored = apply_policy_filter(findings, engine)
    
    assert len(selected) == 1
    finding = selected[0]
    
    assert "hints" in finding
    assert finding["hints"]["prioritize"] == True
    assert "priority_reason" in finding["hints"]
    
    print(f"Priority hints: {finding['hints']}")
    print("✅ Prioritize hints work correctly")
    return True


def test_no_match_allow():
    """Test that findings with no matching rules are allowed through."""
    print("\n=== Test 6: No Match = Allow ===")
    
    engine = PolicyEngine()
    engine.add_rule(PolicyRule(
        rule_id="SPECIFIC-001",
        type="ignore",
        predicate=lambda f: f.get("port") == 9999,
        reason="Port 9999 only",
        precedence=2
    ))
    
    findings = [
        {"host_ip": "10.0.1.5", "port": 443, "title": "TLS vuln"}
    ]
    
    selected, ignored = apply_policy_filter(findings, engine)
    
    assert len(selected) == 1
    assert len(ignored) == 0
    
    finding = selected[0]
    assert finding["policy_action"] == "allow"
    assert finding["policy_rule_id"] == "NO_MATCH"
    
    print(f"Finding allowed with action: {finding['policy_action']}")
    print("✅ No-match findings are allowed through")
    return True


def test_coverage_metrics():
    """Test emit_policy_metrics calculation."""
    print("\n=== Test 7: Coverage Metrics ===")
    
    selected = [
        {"title": "Vuln 1"},
        {"title": "Vuln 2"},
        {"title": "Vuln 3"}
    ]
    
    ignored = [
        {"title": "Info 1", "policy_reason": "Informational (CVSS 0)"},
        {"title": "Dev port", "policy_reason": "Development port exclusion"}
    ]
    
    metrics = emit_policy_metrics(selected, ignored)
    
    assert metrics["total_findings"] == 5
    assert metrics["selected_findings"] == 3
    assert metrics["ignored_findings"] == 2
    assert abs(metrics["coverage_ratio"] - 0.6) < 0.01, "ρ = 3/5 = 0.6"
    
    assert "Informational (CVSS 0)" in metrics["ignore_breakdown"]
    assert metrics["ignore_breakdown"]["Informational (CVSS 0)"] == 1
    
    print(f"Coverage ratio: {metrics['coverage_ratio']:.3f}")
    print(f"Ignore breakdown: {metrics['ignore_breakdown']}")
    print("✅ Coverage metrics calculated correctly")
    return True


def test_default_rules():
    """Test create_default_policy_rules."""
    print("\n=== Test 8: Default Policy Rules ===")
    
    rules = create_default_policy_rules()
    
    assert len(rules) > 0, "Should have default rules"
    
    # Check all default rules have precedence 2 (baseline)
    for rule in rules:
        assert rule.precedence == 2, f"Default rule {rule.rule_id} should have precedence 2"
        assert rule.rule_id.startswith("DEFAULT-"), "Default rules should have DEFAULT- prefix"
    
    print(f"Loaded {len(rules)} default rules")
    for rule in rules:
        print(f"  - {rule.rule_id}: {rule.type} ({rule.reason})")
    
    print("✅ Default rules loaded correctly")
    return True


def test_multiple_rules_same_precedence():
    """Test that first matching rule wins when precedence is equal."""
    print("\n=== Test 9: Multiple Rules Same Precedence ===")
    
    engine = PolicyEngine()
    
    # Both rules have same precedence, both match same finding
    rule1 = PolicyRule(
        rule_id="RULE-A",
        type="ignore",
        predicate=lambda f: f.get("service") == "http",
        reason="HTTP services ignored",
        precedence=1
    )
    
    rule2 = PolicyRule(
        rule_id="RULE-B",
        type="force_manual",
        predicate=lambda f: f.get("service") == "http",
        reason="HTTP services need manual review",
        precedence=1
    )
    
    engine.add_rule(rule1)
    engine.add_rule(rule2)
    
    finding = {"service": "http", "title": "HTTP vuln"}
    action, reason, rule_id = engine.evaluate(finding)
    
    # Should match first rule added (RULE-A)
    assert rule_id == "RULE-A", "First rule should win when precedence is equal"
    assert action == "ignore"
    
    print(f"Matched: {rule_id} (first added rule)")
    print("✅ First matching rule wins with equal precedence")
    return True


def run_all_tests():
    """Run all Phase 2 tests."""
    print("=" * 70)
    print("PHASE 2: POLICY/PREFERENCE FILTER - TEST SUITE")
    print("=" * 70)
    
    tests = [
        ("Policy Rule Creation", test_policy_rule_creation),
        ("Rule Precedence Hierarchy", test_precedence_hierarchy),
        ("Force Manual Hints", test_force_manual_hints),
        ("Ignore Action", test_ignore_action),
        ("Prioritize Hints", test_prioritize_hints),
        ("No Match = Allow", test_no_match_allow),
        ("Coverage Metrics", test_coverage_metrics),
        ("Default Policy Rules", test_default_rules),
        ("Multiple Rules Same Precedence", test_multiple_rules_same_precedence),
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        try:
            test_func()
            passed += 1
        except AssertionError as e:
            print(f"❌ Test failed: {e}")
            failed += 1
        except Exception as e:
            print(f"❌ Test error: {e}")
            import traceback
            traceback.print_exc()
            failed += 1
    
    print("\n" + "=" * 70)
    print("PHASE 2 TEST SUMMARY")
    print("=" * 70)
    print(f"Passed: {passed}/{len(tests)}")
    print(f"Failed: {failed}/{len(tests)}")
    
    if failed == 0:
        print("\n🎉 All Phase 2 tests passed!")
        return 0
    else:
        print(f"\n⚠️  {failed} test(s) failed")
        return 1


if __name__ == "__main__":
    exit_code = run_all_tests()
    sys.exit(exit_code)
