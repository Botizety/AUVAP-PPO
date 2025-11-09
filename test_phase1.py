#!/usr/bin/env python3
"""
Test Suite for Phase 1: Normalize & Validate (parser.py)

Tests implementation of Algorithm 1 from research paper:
- Deterministic finding_id generation
- Data quality tracking
- Deduplication logic
- Normalization metrics
"""

import hashlib
import sys
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent))

from parser import (
    VAFinding,
    DataQuality,
    parse_report,
    deduplicate_findings,
    calculate_normalization_metrics
)


def test_finding_id_deterministic():
    """Test that finding_id is deterministic and uses SHA-1 hash."""
    print("\n=== Test 1: Deterministic Finding ID ===")
    
    # Create two identical findings
    finding1 = VAFinding(
        host_ip="10.0.1.5",
        hostname="web-01",
        os="Linux",
        port=8009,
        protocol="tcp",
        service="ajp13",
        severity_text="Critical",
        cvss=9.8,
        cve="CVE-2020-1938",
        title="Ghostcat",
        description="AJP vuln",
        evidence="test",
        remediation="upgrade",
        raw_plugin_id="133798",
        raw_plugin_family="Web"
    )
    
    finding2 = VAFinding(
        host_ip="10.0.1.5",
        hostname="web-01",
        os="Linux",
        port=8009,
        protocol="tcp",
        service="ajp13",
        severity_text="Critical",
        cvss=9.8,
        cve="CVE-2020-1938",
        title="Ghostcat",
        description="Different description",  # Different field
        evidence="different evidence",  # Different field
        remediation="upgrade",
        raw_plugin_id="133798",
        raw_plugin_family="Web"
    )
    
    print(f"Finding 1 ID: {finding1.finding_id}")
    print(f"Finding 2 ID: {finding2.finding_id}")
    
    # IDs should be identical (based on host_ip, service, port, cve)
    assert finding1.finding_id == finding2.finding_id, \
        "Identical key fields should produce same finding_id"
    
    # Verify it's a SHA-1 hash (40 hex characters)
    assert len(finding1.finding_id) == 40, "finding_id should be SHA-1 (40 chars)"
    assert all(c in '0123456789abcdef' for c in finding1.finding_id), \
        "finding_id should be hexadecimal"
    
    # Verify manual calculation
    id_string = f"10.0.1.5|ajp13|8009|CVE-2020-1938"
    expected_id = hashlib.sha1(id_string.encode('utf-8')).hexdigest()
    assert finding1.finding_id == expected_id, \
        f"Expected {expected_id}, got {finding1.finding_id}"
    
    print("✅ Finding ID is deterministic and uses correct hash")
    return True


def test_finding_id_nocve():
    """Test finding_id generation when CVE is None."""
    print("\n=== Test 2: Finding ID without CVE ===")
    
    finding = VAFinding(
        host_ip="10.0.1.10",
        hostname="db-01",
        os="Windows",
        port=3306,
        protocol="tcp",
        service="mysql",
        severity_text="Medium",
        cvss=5.0,
        cve=None,  # No CVE
        title="Weak Password",
        description="test",
        evidence="test",
        remediation="test",
        raw_plugin_id="12345",
        raw_plugin_family="Database"
    )
    
    # Should use "NOCVE" as placeholder
    id_string = "10.0.1.10|mysql|3306|NOCVE"
    expected_id = hashlib.sha1(id_string.encode('utf-8')).hexdigest()
    
    print(f"Finding ID: {finding.finding_id}")
    print(f"Expected: {expected_id}")
    
    assert finding.finding_id == expected_id, \
        "Missing CVE should use NOCVE placeholder"
    
    print("✅ Finding ID handles missing CVE correctly")
    return True


def test_data_quality_tracking():
    """Test DataQuality dataclass tracks provenance."""
    print("\n=== Test 3: Data Quality Tracking ===")
    
    dq = DataQuality(
        missing_fields=["cve", "cvss"],
        imputed_fields=["cvss_computed"],
        source="nvd_api"
    )
    
    print(f"Missing: {dq.missing_fields}")
    print(f"Imputed: {dq.imputed_fields}")
    print(f"Source: {dq.source}")
    
    assert "cve" in dq.missing_fields, "Should track missing fields"
    assert "cvss_computed" in dq.imputed_fields, "Should track imputed fields"
    assert dq.source == "nvd_api", "Should track authoritative source"
    
    # Test default values
    dq_default = DataQuality()
    assert dq_default.missing_fields == [], "Default missing_fields should be empty"
    assert dq_default.source == "scanner", "Default source should be 'scanner'"
    
    print("✅ Data quality tracking works correctly")
    return True


def test_deduplication_by_timestamp():
    """Test deduplication selects most recent finding."""
    print("\n=== Test 4: Deduplication by Timestamp ===")
    
    from datetime import datetime, timedelta
    
    now = datetime.utcnow()
    earlier = now - timedelta(hours=1)
    
    # Same key fields, different timestamps
    finding_old = VAFinding(
        host_ip="10.0.1.5",
        hostname="web-01",
        os="Linux",
        port=22,
        protocol="tcp",
        service="ssh",
        severity_text="Medium",
        cvss=5.0,
        cve="CVE-2023-1234",
        title="SSH Vuln",
        description="old scan",
        evidence="old",
        remediation="test",
        raw_plugin_id="111",
        raw_plugin_family="SSH"
    )
    finding_old.timestamp = earlier.isoformat()
    
    finding_new = VAFinding(
        host_ip="10.0.1.5",
        hostname="web-01",
        os="Linux",
        port=22,
        protocol="tcp",
        service="ssh",
        severity_text="Medium",
        cvss=5.0,
        cve="CVE-2023-1234",
        title="SSH Vuln",
        description="new scan",
        evidence="new",
        remediation="test",
        raw_plugin_id="111",
        raw_plugin_family="SSH"
    )
    finding_new.timestamp = now.isoformat()
    
    # Should have same finding_id
    assert finding_old.finding_id == finding_new.finding_id, \
        "Findings should have same ID"
    
    # Deduplicate
    findings = [finding_old, finding_new]
    deduplicated = deduplicate_findings(findings)
    
    print(f"Input: {len(findings)} findings")
    print(f"Output: {len(deduplicated)} findings")
    print(f"Selected description: {deduplicated[0].description}")
    
    assert len(deduplicated) == 1, "Should have 1 finding after dedup"
    assert deduplicated[0].description == "new scan", \
        "Should select finding with most recent timestamp"
    
    print("✅ Deduplication by timestamp works")
    return True


def test_deduplication_by_cvss():
    """Test deduplication selects highest CVSS when timestamps equal."""
    print("\n=== Test 5: Deduplication by CVSS Score ===")
    
    timestamp = "2025-11-09T12:00:00"
    
    finding_low = VAFinding(
        host_ip="10.0.1.5",
        hostname="web-01",
        os="Linux",
        port=80,
        protocol="tcp",
        service="http",
        severity_text="Medium",
        cvss=5.0,
        cve="CVE-2023-5678",
        title="HTTP Vuln",
        description="lower score",
        evidence="test",
        remediation="test",
        raw_plugin_id="222",
        raw_plugin_family="Web"
    )
    finding_low.timestamp = timestamp
    
    finding_high = VAFinding(
        host_ip="10.0.1.5",
        hostname="web-01",
        os="Linux",
        port=80,
        protocol="tcp",
        service="http",
        severity_text="High",
        cvss=8.5,
        cve="CVE-2023-5678",
        title="HTTP Vuln",
        description="higher score",
        evidence="test",
        remediation="test",
        raw_plugin_id="222",
        raw_plugin_family="Web"
    )
    finding_high.timestamp = timestamp
    
    findings = [finding_low, finding_high]
    deduplicated = deduplicate_findings(findings)
    
    print(f"Low CVSS: {finding_low.cvss}, High CVSS: {finding_high.cvss}")
    print(f"Selected: {deduplicated[0].description} (CVSS: {deduplicated[0].cvss})")
    
    assert len(deduplicated) == 1, "Should have 1 finding after dedup"
    assert deduplicated[0].cvss == 8.5, "Should select finding with highest CVSS"
    
    print("✅ Deduplication by CVSS works")
    return True


def test_deduplication_by_provenance():
    """Test deduplication selects richest data quality when CVSS equal."""
    print("\n=== Test 6: Deduplication by Data Quality ===")
    
    timestamp = "2025-11-09T12:00:00"
    
    finding_poor = VAFinding(
        host_ip="10.0.1.5",
        hostname="web-01",
        os="Linux",
        port=443,
        protocol="tcp",
        service="https",
        severity_text="High",
        cvss=7.5,
        cve="CVE-2023-9999",
        title="TLS Vuln",
        description="poor provenance",
        evidence="test",
        remediation="test",
        raw_plugin_id="333",
        raw_plugin_family="SSL"
    )
    finding_poor.timestamp = timestamp
    finding_poor.data_quality = DataQuality(
        missing_fields=[],
        imputed_fields=[],
        source="scanner"
    )
    
    finding_rich = VAFinding(
        host_ip="10.0.1.5",
        hostname="web-01",
        os="Linux",
        port=443,
        protocol="tcp",
        service="https",
        severity_text="High",
        cvss=7.5,
        cve="CVE-2023-9999",
        title="TLS Vuln",
        description="rich provenance",
        evidence="test",
        remediation="test",
        raw_plugin_id="333",
        raw_plugin_family="SSL"
    )
    finding_rich.timestamp = timestamp
    finding_rich.data_quality = DataQuality(
        missing_fields=[],
        imputed_fields=["cvss_computed", "cvss_vector", "cvss_confidence"],
        source="nvd_api"
    )
    
    findings = [finding_poor, finding_rich]
    deduplicated = deduplicate_findings(findings)
    
    print(f"Poor provenance: {len(finding_poor.data_quality.imputed_fields)} fields")
    print(f"Rich provenance: {len(finding_rich.data_quality.imputed_fields)} fields")
    print(f"Selected: {deduplicated[0].description}")
    
    assert len(deduplicated) == 1, "Should have 1 finding after dedup"
    assert len(deduplicated[0].data_quality.imputed_fields) == 3, \
        "Should select finding with richest provenance"
    
    print("✅ Deduplication by data quality works")
    return True


def test_normalization_metrics():
    """Test calculation of normalization efficiency and imputation rate."""
    print("\n=== Test 7: Normalization Metrics ===")
    
    metrics = calculate_normalization_metrics(
        raw_count=100,
        normalized_count=85,
        imputed_count=20
    )
    
    print(f"Metrics: {metrics}")
    
    assert metrics["raw_findings"] == 100
    assert metrics["normalized_findings"] == 85
    assert metrics["imputed_findings"] == 20
    assert metrics["deduplication_count"] == 15, "Should be 100 - 85 = 15"
    assert abs(metrics["normalization_efficiency"] - 0.85) < 0.01, \
        "η_norm should be 85/100 = 0.85"
    assert abs(metrics["imputation_rate"] - (20/85)) < 0.01, \
        "λ_impute should be 20/85 ≈ 0.235"
    
    print("✅ Normalization metrics calculated correctly")
    return True


def test_parse_report_integration():
    """Test full parse_report with deduplication and metrics."""
    print("\n=== Test 8: Full Parse Report Integration ===")
    
    xml_file = "auvap_nessus_25_findings.xml"
    
    if not Path(xml_file).exists():
        print(f"⚠️  Test file {xml_file} not found, skipping")
        return True
    
    findings = parse_report(xml_file, deduplicate=True)
    
    print(f"Parsed {len(findings)} findings")
    
    # Verify all findings have finding_id
    for f in findings:
        assert f.finding_id, "All findings should have finding_id"
        assert len(f.finding_id) == 40, "finding_id should be SHA-1"
        assert f.timestamp, "All findings should have timestamp"
        assert f.data_quality, "All findings should have data_quality"
    
    # Verify no duplicates by finding_id
    finding_ids = [f.finding_id for f in findings]
    assert len(finding_ids) == len(set(finding_ids)), \
        "No duplicate finding_ids should exist after deduplication"
    
    print("✅ Full parse report integration works")
    return True


def run_all_tests():
    """Run all Phase 1 tests."""
    print("=" * 70)
    print("PHASE 1: NORMALIZE & VALIDATE - TEST SUITE")
    print("=" * 70)
    
    tests = [
        ("Deterministic Finding ID", test_finding_id_deterministic),
        ("Finding ID without CVE", test_finding_id_nocve),
        ("Data Quality Tracking", test_data_quality_tracking),
        ("Deduplication by Timestamp", test_deduplication_by_timestamp),
        ("Deduplication by CVSS", test_deduplication_by_cvss),
        ("Deduplication by Provenance", test_deduplication_by_provenance),
        ("Normalization Metrics", test_normalization_metrics),
        ("Parse Report Integration", test_parse_report_integration),
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
    print("PHASE 1 TEST SUMMARY")
    print("=" * 70)
    print(f"Passed: {passed}/{len(tests)}")
    print(f"Failed: {failed}/{len(tests)}")
    
    if failed == 0:
        print("\n🎉 All Phase 1 tests passed!")
        return 0
    else:
        print(f"\n⚠️  {failed} test(s) failed")
        return 1


if __name__ == "__main__":
    exit_code = run_all_tests()
    sys.exit(exit_code)
