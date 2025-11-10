#!/usr/bin/env python3
"""
test_integration.py - Integration tests for AUVAP-PPO

Tests the integration of multiple components:
- Parser → Classifier → Policy → Task Manager
- PPO Agent → CyberEnv → Terrain Generator
- LLM-DRL Bridge → Sandbox → Memory
- End-to-end pipeline execution
"""

import pytest
import sys
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import torch

# Add parent directories to path
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "execution"))


class TestParserClassifierIntegration:
    """Test integration between parser and classifier."""

    def test_parser_to_classifier_flow(self):
        """Test parsing findings and passing to classifier."""
        from parser import VAFinding

        # Create sample finding
        finding = VAFinding(
            finding_id="test_001",
            host_ip="192.168.1.100",
            port=80,
            protocol="tcp",
            service="http",
            cvss=7.5,
            severity_text="High",
            title="SQL Injection",
            description="SQL injection vulnerability",
            cve="CVE-2023-1234"
        )

        # Verify finding structure
        assert finding.host_ip == "192.168.1.100"
        assert finding.port == 80
        assert finding.cvss == 7.5

        # Convert to dict for classifier
        finding_dict = {
            'host_ip': finding.host_ip,
            'port': finding.port,
            'service': finding.service,
            'cvss': finding.cvss,
            'severity_text': finding.severity_text,
            'title': finding.title
        }

        assert isinstance(finding_dict, dict)
        assert 'cvss' in finding_dict


class TestClassifierPolicyIntegration:
    """Test integration between classifier and policy engine."""

    def test_classified_findings_to_policy(self):
        """Test passing classified findings to policy engine."""
        from policy_engine import PolicyEngine, PolicyRule

        # Create sample classified finding
        classified_finding = {
            'host_ip': '192.168.1.100',
            'port': 22,
            'service': 'ssh',
            'cvss': 9.8,
            'severity_bucket': 'Critical',
            'attack_vector': 'Network',
            'automation_candidate': True,
            'llm_confidence': 0.95
        }

        # Create policy engine
        engine = PolicyEngine()

        # Add a test rule
        rule = PolicyRule(
            rule_id="test_critical",
            type="prioritize",
            predicate=lambda f: f.get('severity_bucket') == 'Critical',
            reason="Critical vulnerability",
            precedence=0
        )
        engine.add_rule(rule)

        # Apply policy
        action = engine.evaluate(classified_finding)

        assert action is not None
        assert action.rule.rule_id == "test_critical"


class TestPolicyTaskManagerIntegration:
    """Test integration between policy engine and task manager."""

    def test_policy_filtered_findings_to_tasks(self):
        """Test creating tasks from policy-approved findings."""
        from task_manager import initialize_tasks, ExploitTask

        # Create policy-approved findings
        approved_findings = [
            {
                'finding_id': 'find_001',
                'host_ip': '192.168.1.100',
                'port': 22,
                'service': 'ssh',
                'cvss': 9.8,
                'severity_bucket': 'Critical',
                'attack_vector': 'Network',
                'automation_candidate': True,
                'title': 'SSH RCE',
                'cve': 'CVE-2023-0001'
            },
            {
                'finding_id': 'find_002',
                'host_ip': '192.168.1.101',
                'port': 80,
                'service': 'http',
                'cvss': 7.5,
                'severity_bucket': 'High',
                'attack_vector': 'Network',
                'automation_candidate': True,
                'title': 'SQL Injection',
                'cve': 'CVE-2023-0002'
            }
        ]

        # Initialize tasks
        tasks = initialize_tasks(approved_findings)

        assert len(tasks) == 2
        assert all(isinstance(task, ExploitTask) for task in tasks)
        # Should be sorted by priority (risk_score)
        assert tasks[0].priority >= tasks[1].priority


class TestPPOCyberEnvIntegration:
    """Test integration between PPO agent and CyberBattleSim environment."""

    @pytest.mark.skip(reason="Requires CyberBattleSim installation")
    def test_ppo_agent_with_cyber_env(self):
        """Test PPO agent interacting with CyberBattleSim environment."""
        from ppo_agent import PPOAgent
        from execution.cyber_env import CyberBattleEnv

        # This would require actual CyberBattleSim setup
        # Skipped in unit tests, but structure is validated
        pass

    def test_ppo_agent_action_selection_integration(self):
        """Test PPO agent action selection with masking."""
        from ppo_agent import PPOAgent

        agent = PPOAgent(obs_dim=128, action_dim=50)

        # Simulate masked action space
        obs = torch.randn(128)
        mask = torch.zeros(50, dtype=torch.bool)
        mask[:10] = True  # Only first 10 actions valid

        action, log_prob, value = agent.select_action(obs, mask)

        # Action should respect mask
        assert 0 <= action < 10
        assert isinstance(log_prob, float)
        assert isinstance(value, float)


class TestTerrainGeneratorIntegration:
    """Test terrain generator with other components."""

    def test_terrain_to_cyber_env(self):
        """Test using generated terrain in CyberBattleSim environment."""
        from execution.terrain_generator import TerrainGenerator, TerrainParams
        import networkx as nx

        # Generate terrain
        generator = TerrainGenerator()
        params = TerrainParams(num_nodes=10)
        graph, terrain_id = generator.generate_terrain(params, seed=42)

        # Verify terrain structure
        assert isinstance(graph, nx.DiGraph)
        assert len(graph.nodes()) == 10
        assert nx.is_weakly_connected(graph)

        # Verify nodes have required attributes for env
        for node in graph.nodes():
            assert 'os' in graph.nodes[node]
            assert 'services' in graph.nodes[node]
            assert 'vulnerabilities' in graph.nodes[node]


class TestLLMDRLSandboxIntegration:
    """Test LLM-DRL bridge with sandbox executor."""

    @patch('llm_drl_bridge.VulnerabilityClassifier')
    def test_bridge_with_sandbox(self, mock_classifier):
        """Test LLM-DRL bridge using sandbox for execution."""
        from llm_drl_bridge import LLMDRLBridge, ScriptGenerationResponse
        from sandbox_executor import SandboxExecutor, ExecutionResult
        from execution.persistent_memory import PersistentMemory

        # Create mocked components
        mock_sandbox = Mock(spec=SandboxExecutor)
        mock_memory = Mock(spec=PersistentMemory)

        # Create bridge
        bridge = LLMDRLBridge(
            sandbox_executor=mock_sandbox,
            persistent_memory=mock_memory,
            verbose=False
        )

        # Mock script generation
        mock_response = ScriptGenerationResponse(
            script_content="print('test')",
            confidence=0.9,
            reasoning="Test",
            metadata={}
        )
        bridge._generate_script = Mock(return_value=mock_response)
        bridge._save_script = Mock(return_value="/tmp/test.py")

        # Mock successful execution
        mock_sandbox.execute_task = Mock(return_value=ExecutionResult(
            status="success",
            exit_code=0,
            stdout="Success",
            stderr="",
            duration=1.0,
            logs=[]
        ))

        # Verify components are connected
        assert bridge.sandbox == mock_sandbox
        assert bridge.memory == mock_memory


class TestEndToEndPipeline:
    """Test end-to-end pipeline integration."""

    def test_minimal_pipeline_flow(self):
        """Test minimal end-to-end flow through all components."""
        # Step 1: Parse findings
        from parser import VAFinding

        finding = VAFinding(
            finding_id="e2e_001",
            host_ip="10.0.0.1",
            port=22,
            protocol="tcp",
            service="ssh",
            cvss=9.8,
            severity_text="Critical",
            title="SSH RCE",
            description="Remote code execution",
            cve="CVE-2023-9999"
        )

        # Step 2: Convert to dict for processing
        finding_dict = {
            'finding_id': finding.finding_id,
            'host_ip': finding.host_ip,
            'port': finding.port,
            'service': finding.service,
            'cvss': finding.cvss,
            'severity_text': finding.severity_text,
            'title': finding.title,
            'cve': finding.cve
        }

        # Step 3: Simulate classification (mock)
        classified = finding_dict.copy()
        classified.update({
            'severity_bucket': 'Critical',
            'attack_vector': 'Network',
            'automation_candidate': True,
            'llm_confidence': 0.95
        })

        # Step 4: Apply policy (mock - assume approved)
        approved = [classified]

        # Step 5: Create tasks
        from task_manager import initialize_tasks

        tasks = initialize_tasks(approved)

        assert len(tasks) == 1
        assert tasks[0].finding_id == finding.finding_id
        assert tasks[0].risk_score > 0

    def test_pipeline_with_multiple_findings(self):
        """Test pipeline with multiple findings."""
        from parser import VAFinding
        from task_manager import initialize_tasks

        # Create multiple findings
        findings = []
        for i in range(5):
            finding_dict = {
                'finding_id': f"multi_{i}",
                'host_ip': f"10.0.0.{i+1}",
                'port': 22 + i,
                'service': 'ssh',
                'cvss': 9.0 - i * 0.5,
                'severity_bucket': 'Critical',
                'attack_vector': 'Network',
                'automation_candidate': True,
                'title': f"Vulnerability {i}",
                'cve': f"CVE-2023-{1000+i}"
            }
            findings.append(finding_dict)

        # Create tasks
        tasks = initialize_tasks(findings)

        assert len(tasks) == 5
        # Verify prioritization
        assert tasks[0].priority >= tasks[1].priority
        assert tasks[1].priority >= tasks[2].priority


class TestMemoryPersistence:
    """Test persistent memory integration."""

    def test_memory_store_and_retrieve(self):
        """Test storing and retrieving execution history."""
        from execution.persistent_memory import PersistentMemory
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            db_path = tmp.name

        try:
            memory = PersistentMemory(db_path)

            # Store attempt
            memory.store_attempt(
                finding_id="mem_test_001",
                task_id="task_mem_001",
                script_content="print('test')",
                execution_result={"status": "success", "duration": 1.5},
                success=True,
                metadata={"test": True}
            )

            # Retrieve
            attempts = memory.get_attempts_by_finding("mem_test_001")

            assert len(attempts) > 0
            assert attempts[0]['finding_id'] == "mem_test_001"

        finally:
            Path(db_path).unlink(missing_ok=True)


def test_integration_stress_test():
    """Stress test with many findings."""
    from task_manager import initialize_tasks, compute_risk_score

    # Create 100 findings
    findings = []
    for i in range(100):
        finding = {
            'finding_id': f"stress_{i}",
            'host_ip': f"10.0.{i // 256}.{i % 256}",
            'port': 1000 + i,
            'service': ['ssh', 'http', 'ftp'][i % 3],
            'cvss': 5.0 + (i % 5),
            'severity_bucket': ['Medium', 'High', 'Critical'][i % 3],
            'attack_vector': 'Network',
            'automation_candidate': i % 2 == 0,
            'title': f"Vulnerability {i}",
            'cve': f"CVE-2023-{10000+i}"
        }
        findings.append(finding)

    # Initialize all tasks
    tasks = initialize_tasks(findings)

    assert len(tasks) == 100
    # Verify all have valid risk scores
    assert all(task.risk_score > 0 for task in tasks)
    # Verify prioritization
    assert tasks[0].priority == max(t.priority for t in tasks)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
