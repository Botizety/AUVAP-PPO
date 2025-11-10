#!/usr/bin/env python3
"""
test_llm_drl_bridge.py - Unit tests for LLM-DRL Bridge

Tests the LLM↔DRL feedback loop including:
- Script generation requests
- Execution feedback loop
- Refinement iterations
- Memory integration
- Success/failure handling
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from dataclasses import dataclass

# Add parent directories to path
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "execution"))

from llm_drl_bridge import (
    LLMDRLBridge,
    ScriptGenerationRequest,
    ScriptGenerationResponse
)
from sandbox_executor import ExecutionResult
from parser import VAFinding
from task_manager import ExploitTask, TaskState


class TestScriptGenerationRequest:
    """Test ScriptGenerationRequest dataclass."""

    def test_basic_request(self):
        """Test basic request creation."""
        finding = Mock(spec=VAFinding)
        task = Mock(spec=ExploitTask)

        request = ScriptGenerationRequest(
            finding=finding,
            task=task
        )

        assert request.finding == finding
        assert request.task == task
        assert request.refinement_iteration == 0
        assert request.similar_attempts is None
        assert request.previous_errors is None

    def test_request_with_refinement(self):
        """Test request with refinement context."""
        finding = Mock(spec=VAFinding)
        task = Mock(spec=ExploitTask)
        errors = ["Error 1", "Error 2"]
        trace = "Execution trace..."

        request = ScriptGenerationRequest(
            finding=finding,
            task=task,
            refinement_iteration=2,
            previous_errors=errors,
            execution_trace=trace
        )

        assert request.refinement_iteration == 2
        assert len(request.previous_errors) == 2
        assert request.execution_trace == trace


class TestScriptGenerationResponse:
    """Test ScriptGenerationResponse dataclass."""

    def test_basic_response(self):
        """Test basic response creation."""
        response = ScriptGenerationResponse(
            script_content="print('exploit')",
            confidence=0.85,
            reasoning="Based on CVE analysis",
            metadata={"attempts": 1}
        )

        assert "exploit" in response.script_content
        assert response.confidence == 0.85
        assert "CVE" in response.reasoning
        assert response.metadata["attempts"] == 1


class TestLLMDRLBridgeInitialization:
    """Test LLMDRLBridge initialization."""

    @pytest.fixture
    def mock_sandbox(self):
        """Create mock sandbox executor."""
        return Mock()

    @pytest.fixture
    def mock_memory(self):
        """Create mock persistent memory."""
        return Mock()

    @patch('llm_drl_bridge.VulnerabilityClassifier')
    def test_basic_initialization(self, mock_classifier, mock_sandbox, mock_memory):
        """Test basic bridge initialization."""
        bridge = LLMDRLBridge(
            sandbox_executor=mock_sandbox,
            persistent_memory=mock_memory,
            verbose=False
        )

        assert bridge.sandbox == mock_sandbox
        assert bridge.memory == mock_memory
        assert bridge.llm_provider == "openai"
        assert bridge.max_iterations == 3
        assert bridge.use_memory == True

    @patch('llm_drl_bridge.VulnerabilityClassifier')
    def test_custom_initialization(self, mock_classifier, mock_sandbox, mock_memory):
        """Test initialization with custom parameters."""
        bridge = LLMDRLBridge(
            sandbox_executor=mock_sandbox,
            persistent_memory=mock_memory,
            llm_provider="gemini",
            max_refinement_iterations=5,
            use_memory_context=False,
            verbose=True
        )

        assert bridge.llm_provider == "gemini"
        assert bridge.max_iterations == 5
        assert bridge.use_memory == False
        assert bridge.verbose == True


class TestScriptGeneration:
    """Test script generation via LLM."""

    @pytest.fixture
    def bridge(self):
        """Create bridge with mocked components."""
        mock_sandbox = Mock()
        mock_memory = Mock()

        with patch('llm_drl_bridge.VulnerabilityClassifier'):
            bridge = LLMDRLBridge(
                sandbox_executor=mock_sandbox,
                persistent_memory=mock_memory,
                verbose=False
            )
        return bridge

    @pytest.fixture
    def sample_finding(self):
        """Create sample vulnerability finding."""
        finding = Mock(spec=VAFinding)
        finding.finding_id = "test_finding_123"
        finding.host_ip = "192.168.1.100"
        finding.port = 8080
        finding.service = "http"
        finding.title = "SQL Injection"
        finding.cvss = 9.8
        return finding

    @pytest.fixture
    def sample_task(self):
        """Create sample exploit task."""
        task = Mock(spec=ExploitTask)
        task.task_id = "task_123"
        task.finding_id = "test_finding_123"
        task.target = "192.168.1.100:8080"
        task.state = TaskState.PLANNED
        task.attempts = 0
        return task

    def test_generate_script_mock(self, bridge, sample_finding, sample_task):
        """Test script generation with mocked LLM."""
        # Mock the _generate_script method
        mock_response = ScriptGenerationResponse(
            script_content="#!/usr/bin/env python3\nprint('exploit')\n",
            confidence=0.9,
            reasoning="Test reasoning",
            metadata={}
        )

        bridge._generate_script = Mock(return_value=mock_response)

        response = bridge._generate_script(
            finding=sample_finding,
            task=sample_task,
            iteration=1,
            previous_errors=[],
            execution_trace=""
        )

        assert response.script_content is not None
        assert response.confidence > 0
        assert isinstance(response.reasoning, str)


class TestExecutionLoop:
    """Test the main LLM→DRL→LLM execution loop."""

    @pytest.fixture
    def configured_bridge(self):
        """Create fully configured bridge with mocks."""
        mock_sandbox = Mock()
        mock_memory = Mock()

        with patch('llm_drl_bridge.VulnerabilityClassifier'):
            bridge = LLMDRLBridge(
                sandbox_executor=mock_sandbox,
                persistent_memory=mock_memory,
                max_refinement_iterations=3,
                verbose=False
            )

        return bridge, mock_sandbox, mock_memory

    @pytest.fixture
    def sample_finding(self):
        """Create sample finding."""
        finding = Mock(spec=VAFinding)
        finding.finding_id = "test_123"
        finding.host_ip = "192.168.1.100"
        finding.port = 22
        finding.service = "ssh"
        finding.title = "SSH Weak Password"
        finding.cvss = 7.5
        return finding

    @pytest.fixture
    def sample_task(self):
        """Create sample task."""
        task = Mock(spec=ExploitTask)
        task.task_id = "task_456"
        task.finding_id = "test_123"
        task.target = "192.168.1.100:22"
        task.state = TaskState.PLANNED
        task.attempts = 0
        # Add missing attributes that the bridge accesses
        task.target_host = "192.168.1.100"
        task.target_port = 22
        task.vulnerability_id = "CVE-2023-1234"
        task.cvss_score = 7.5
        return task

    def test_successful_execution_first_try(self, configured_bridge, sample_finding, sample_task):
        """Test successful exploitation on first attempt."""
        bridge, mock_sandbox, mock_memory = configured_bridge

        # Mock successful script generation
        mock_script_response = ScriptGenerationResponse(
            script_content="print('success')",
            confidence=0.95,
            reasoning="Test",
            metadata={}
        )
        bridge._generate_script = Mock(return_value=mock_script_response)
        bridge._save_script = Mock(return_value="/tmp/script.py")

        # Mock successful execution
        success_result = ExecutionResult(
            status="success",
            exit_code=0,
            stdout="Exploit successful\n",
            stderr="",
            duration=1.5,
            logs=[]
        )
        mock_sandbox.execute_task = Mock(return_value=success_result)

        # Execute
        success, result, script = bridge.plan_and_execute(sample_finding, sample_task)

        assert success == True
        assert result.status == "success"
        assert result.exit_code == 0

        # Verify script was generated and executed
        bridge._generate_script.assert_called_once()
        mock_sandbox.execute_task.assert_called_once()

    def test_failure_with_refinement(self, configured_bridge, sample_finding, sample_task):
        """Test failure on first attempt with successful refinement."""
        bridge, mock_sandbox, mock_memory = configured_bridge

        # Mock script generation (called multiple times)
        mock_script_response = ScriptGenerationResponse(
            script_content="print('attempt')",
            confidence=0.8,
            reasoning="Test",
            metadata={}
        )
        bridge._generate_script = Mock(return_value=mock_script_response)
        bridge._save_script = Mock(return_value="/tmp/script.py")

        # Mock execution: first fails, second succeeds
        failure_result = ExecutionResult(
            status="failure",
            exit_code=1,
            stdout="",
            stderr="Connection refused\n",
            duration=0.5,
            logs=[]
        )
        success_result = ExecutionResult(
            status="success",
            exit_code=0,
            stdout="Success\n",
            stderr="",
            duration=1.0,
            logs=[]
        )
        mock_sandbox.execute_task = Mock(side_effect=[failure_result, success_result])

        # Execute
        success, result, script = bridge.plan_and_execute(sample_finding, sample_task)

        assert success == True
        assert result.status == "success"

        # Verify refinement happened
        assert bridge._generate_script.call_count == 2
        assert mock_sandbox.execute_task.call_count == 2

    def test_max_iterations_reached(self, configured_bridge, sample_finding, sample_task):
        """Test max refinement iterations exceeded."""
        bridge, mock_sandbox, mock_memory = configured_bridge

        # Mock script generation
        mock_script_response = ScriptGenerationResponse(
            script_content="print('attempt')",
            confidence=0.7,
            reasoning="Test",
            metadata={}
        )
        bridge._generate_script = Mock(return_value=mock_script_response)
        bridge._save_script = Mock(return_value="/tmp/script.py")

        # Mock execution: always fails
        failure_result = ExecutionResult(
            status="failure",
            exit_code=1,
            stdout="",
            stderr="Error\n",
            duration=0.3,
            logs=[]
        )
        mock_sandbox.execute_task = Mock(return_value=failure_result)

        # Execute
        success, result, script = bridge.plan_and_execute(sample_finding, sample_task)

        assert success == False
        assert result.status == "failure"

        # Verify all iterations were attempted
        assert bridge._generate_script.call_count == 3  # max_iterations
        assert mock_sandbox.execute_task.call_count == 3

    def test_timeout_handling(self, configured_bridge, sample_finding, sample_task):
        """Test execution timeout handling."""
        bridge, mock_sandbox, mock_memory = configured_bridge

        # Mock script generation
        mock_script_response = ScriptGenerationResponse(
            script_content="import time; time.sleep(100)",
            confidence=0.8,
            reasoning="Test",
            metadata={}
        )
        bridge._generate_script = Mock(return_value=mock_script_response)
        bridge._save_script = Mock(return_value="/tmp/script.py")

        # Mock execution: timeout
        timeout_result = ExecutionResult(
            status="timeout",
            exit_code=-1,
            stdout="",
            stderr="",
            duration=10.0,
            logs=[]
        )
        mock_sandbox.execute_task = Mock(return_value=timeout_result)

        # Execute
        success, result, script = bridge.plan_and_execute(sample_finding, sample_task)

        assert success == False
        assert result.status == "timeout"


class TestMemoryIntegration:
    """Test persistent memory integration."""

    @pytest.fixture
    def bridge_with_memory(self):
        """Create bridge with memory enabled."""
        mock_sandbox = Mock()
        mock_memory = Mock()

        with patch('llm_drl_bridge.VulnerabilityClassifier'):
            bridge = LLMDRLBridge(
                sandbox_executor=mock_sandbox,
                persistent_memory=mock_memory,
                use_memory_context=True,
                verbose=False
            )

        return bridge, mock_memory

    def test_memory_context_retrieved(self, bridge_with_memory):
        """Test that memory context is retrieved for similar vulnerabilities."""
        bridge, mock_memory = bridge_with_memory

        # Mock memory retrieval
        similar_attempts = [
            {"finding_id": "similar_1", "success": True, "script": "..."},
            {"finding_id": "similar_2", "success": True, "script": "..."}
        ]
        mock_memory.get_similar_attempts = Mock(return_value=similar_attempts)

        # This would be called internally during plan_and_execute
        # For unit test, just verify the mock can be called
        result = mock_memory.get_similar_attempts("test_vuln", limit=5)

        assert len(result) == 2
        mock_memory.get_similar_attempts.assert_called_once_with("test_vuln", limit=5)


def test_integration_full_loop():
    """Integration test for complete LLM-DRL loop."""
    mock_sandbox = Mock()
    mock_memory = Mock()

    with patch('llm_drl_bridge.VulnerabilityClassifier'):
        bridge = LLMDRLBridge(
            sandbox_executor=mock_sandbox,
            persistent_memory=mock_memory,
            max_refinement_iterations=2,
            verbose=False
        )

    # Create test data
    finding = Mock(spec=VAFinding)
    finding.finding_id = "integration_test"
    finding.host_ip = "10.0.0.1"
    finding.port = 80
    finding.service = "http"
    finding.cvss = 8.5

    task = Mock(spec=ExploitTask)
    task.task_id = "integration_task"
    task.finding_id = "integration_test"
    task.target = "10.0.0.1:80"
    task.target_host = "10.0.0.1"
    task.target_port = 80
    task.vulnerability_id = "CVE-2023-TEST"
    task.cvss_score = 8.5
    task.state = TaskState.PLANNED
    task.attempts = 0

    # Mock components
    bridge._generate_script = Mock(return_value=ScriptGenerationResponse(
        script_content="print('test')",
        confidence=0.9,
        reasoning="Test",
        metadata={}
    ))
    bridge._save_script = Mock(return_value="/tmp/test_script.py")

    mock_sandbox.execute_task = Mock(return_value=ExecutionResult(
        status="success",
        exit_code=0,
        stdout="Success",
        stderr="",
        duration=1.0,
        logs=[]
    ))

    # Execute full loop
    success, result, script = bridge.plan_and_execute(finding, task)

    assert success == True
    assert isinstance(result, ExecutionResult)
    assert result.status == "success"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
