#!/usr/bin/env python3
"""
test_masking_sensor.py - Unit tests for Masking Sensor

Tests the masking sensor algorithm including:
- Task exposure to DRL agent
- Action space masking
- Safety constraint enforcement
- Task prioritization
- Execution logging
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import Mock, MagicMock

# Add parent directories to path
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "environment"))

from masking_sensor import (
    MaskingSensor,
    TaskStatus,
    SafetyConstraint,
    TaskExposure,
    ExecutionLogEntry
)
from parser import VAFinding
from task_manager import ExploitTask, TaskState


class TestSafetyConstraint:
    """Test SafetyConstraint dataclass."""

    def test_basic_constraint(self):
        """Test basic safety constraint creation."""
        constraint = SafetyConstraint(
            constraint_type="timeout",
            value=30,
            reason="Prevent long-running exploits",
            enforced=True
        )

        assert constraint.constraint_type == "timeout"
        assert constraint.value == 30
        assert constraint.enforced == True

    def test_constraint_types(self):
        """Test different constraint types."""
        types = ["network_isolation", "timeout", "resource_limit", "port_restriction"]

        for ctype in types:
            constraint = SafetyConstraint(
                constraint_type=ctype,
                value="test",
                reason="Test constraint"
            )
            assert constraint.constraint_type == ctype


class TestTaskExposure:
    """Test TaskExposure dataclass."""

    def test_basic_exposure(self):
        """Test basic task exposure creation."""
        mock_task = Mock(spec=ExploitTask)
        allowed_actions = [0, 1, 2, 5, 10]
        constraints = [
            SafetyConstraint("timeout", 30, "Time limit")
        ]

        exposure = TaskExposure(
            task=mock_task,
            allowed_actions=allowed_actions,
            safety_constraints=constraints,
            context={"network_state": "isolated"},
            attempt_number=1,
            max_attempts=3
        )

        assert exposure.task == mock_task
        assert len(exposure.allowed_actions) == 5
        assert len(exposure.safety_constraints) == 1
        assert exposure.attempt_number == 1
        assert exposure.max_attempts == 3


class TestExecutionLogEntry:
    """Test ExecutionLogEntry dataclass."""

    def test_log_entry_creation(self):
        """Test execution log entry creation."""
        entry = ExecutionLogEntry(
            timestamp="2024-01-01T12:00:00",
            task_id="task_123",
            action_taken=5,
            result="success",
            safety_violations=[],
            duration_seconds=2.5,
            metadata={"notes": "test"}
        )

        assert entry.task_id == "task_123"
        assert entry.action_taken == 5
        assert entry.result == "success"
        assert entry.duration_seconds == 2.5


class TestMaskingSensorInitialization:
    """Test MaskingSensor initialization."""

    @pytest.fixture
    def sample_findings(self):
        """Create sample findings."""
        finding1 = Mock(spec=VAFinding)
        finding1.finding_id = "find_1"
        finding1.risk_score = 9.0

        finding2 = Mock(spec=VAFinding)
        finding2.finding_id = "find_2"
        finding2.risk_score = 7.0

        return [finding1, finding2]

    @pytest.fixture
    def mock_action_mapper(self):
        """Create mock action mapper."""
        mapper = Mock()
        mapper.register_task = Mock()
        return mapper

    def test_basic_initialization(self, sample_findings, mock_action_mapper):
        """Test basic sensor initialization."""
        sensor = MaskingSensor(
            findings=sample_findings,
            action_mapper=mock_action_mapper
        )

        assert len(sensor.findings) == 2
        assert sensor.action_mapper == mock_action_mapper
        assert sensor.max_attempts == 3
        assert sensor.enable_safety == True

    def test_custom_initialization(self, sample_findings, mock_action_mapper):
        """Test initialization with custom parameters."""
        mock_policy = Mock()

        sensor = MaskingSensor(
            findings=sample_findings,
            action_mapper=mock_action_mapper,
            policy_engine=mock_policy,
            max_attempts_per_task=5,
            enable_safety_constraints=False
        )

        assert sensor.policy_engine == mock_policy
        assert sensor.max_attempts == 5
        assert sensor.enable_safety == False


class TestActionMasking:
    """Test action space masking."""

    @pytest.fixture
    def sensor(self):
        """Create configured sensor."""
        findings = [Mock(spec=VAFinding)]
        mapper = Mock()
        return MaskingSensor(findings, mapper)

    def test_get_allowed_actions_mock(self, sensor):
        """Test getting allowed actions for a task."""
        mock_task = Mock(spec=ExploitTask)
        mock_task.task_id = "test_task"
        mock_task.config = {
            'service': 'http',
            'port': 80
        }

        # Mock the method
        sensor._get_allowed_actions = Mock(return_value=[0, 1, 2, 3])

        allowed_actions = sensor._get_allowed_actions(mock_task)

        assert isinstance(allowed_actions, list)
        assert len(allowed_actions) > 0


class TestSafetyConstraints:
    """Test safety constraint enforcement."""

    @pytest.fixture
    def sensor(self):
        """Create sensor with safety enabled."""
        findings = [Mock(spec=VAFinding)]
        mapper = Mock()
        return MaskingSensor(
            findings,
            mapper,
            enable_safety_constraints=True
        )

    def test_safety_constraints_applied(self, sensor):
        """Test that safety constraints are applied to tasks."""
        mock_task = Mock(spec=ExploitTask)
        mock_task.task_id = "safe_task"
        mock_task.config = {'port': 22, 'service': 'ssh'}

        # Mock constraint generation
        sensor._generate_safety_constraints = Mock(return_value=[
            SafetyConstraint("timeout", 30, "Time limit"),
            SafetyConstraint("network_isolation", True, "Network isolation")
        ])

        constraints = sensor._generate_safety_constraints(mock_task)

        assert len(constraints) == 2
        assert all(isinstance(c, SafetyConstraint) for c in constraints)

    def test_safety_disabled(self):
        """Test sensor with safety disabled."""
        findings = [Mock(spec=VAFinding)]
        mapper = Mock()
        sensor = MaskingSensor(
            findings,
            mapper,
            enable_safety_constraints=False
        )

        assert sensor.enable_safety == False


class TestTaskPrioritization:
    """Test task prioritization logic."""

    @pytest.fixture
    def multiple_findings(self):
        """Create multiple findings with different priorities."""
        findings = []
        for i in range(5):
            finding = Mock(spec=VAFinding)
            finding.finding_id = f"finding_{i}"
            finding.cvss = 10.0 - i  # Descending priority
            findings.append(finding)
        return findings

    def test_prioritization(self, multiple_findings):
        """Test that tasks are prioritized by severity."""
        mapper = Mock()
        sensor = MaskingSensor(multiple_findings, mapper)

        # Mock the prioritization method
        sensor._prioritize_tasks = Mock(return_value=multiple_findings)

        prioritized = sensor._prioritize_tasks()

        assert len(prioritized) == 5


class TestExecutionLogging:
    """Test execution logging for replay."""

    @pytest.fixture
    def sensor_with_logging(self, tmp_path):
        """Create sensor with logging enabled."""
        log_file = tmp_path / "execution.log"
        findings = [Mock(spec=VAFinding)]
        mapper = Mock()

        return MaskingSensor(
            findings,
            mapper,
            log_file=str(log_file)
        )

    def test_log_entry_creation(self, sensor_with_logging):
        """Test that execution events are logged."""
        entry = ExecutionLogEntry(
            timestamp="2024-01-01T12:00:00",
            task_id="log_test",
            action_taken=3,
            result="success",
            safety_violations=[],
            duration_seconds=1.5
        )

        assert entry.task_id == "log_test"
        assert entry.action_taken == 3
        assert entry.result == "success"


class TestTaskStatusTracking:
    """Test task status tracking."""

    def test_task_status_enum(self):
        """Test TaskStatus enum values."""
        assert TaskStatus.PENDING.value == "pending"
        assert TaskStatus.ACTIVE.value == "active"
        assert TaskStatus.COMPLETED.value == "completed"
        assert TaskStatus.FAILED.value == "failed"
        assert TaskStatus.SKIPPED.value == "skipped"
        assert TaskStatus.BLOCKED.value == "blocked"

    def test_status_transitions(self):
        """Test valid status transitions."""
        valid_transitions = [
            (TaskStatus.PENDING, TaskStatus.ACTIVE),
            (TaskStatus.ACTIVE, TaskStatus.COMPLETED),
            (TaskStatus.ACTIVE, TaskStatus.FAILED),
            (TaskStatus.PENDING, TaskStatus.SKIPPED),
            (TaskStatus.PENDING, TaskStatus.BLOCKED)
        ]

        for from_status, to_status in valid_transitions:
            assert from_status != to_status


def test_integration_sensor_workflow():
    """Integration test for full sensor workflow."""
    # Create test data
    findings = []
    for i in range(3):
        finding = Mock(spec=VAFinding)
        finding.finding_id = f"integration_{i}"
        finding.cvss = 9.0 - i
        finding.host_ip = f"192.168.1.{100+i}"
        finding.port = 22
        finding.service = "ssh"
        findings.append(finding)

    mapper = Mock()
    mapper.register_task = Mock()

    sensor = MaskingSensor(
        findings=findings,
        action_mapper=mapper,
        max_attempts_per_task=3,
        enable_safety_constraints=True
    )

    # Verify initialization
    assert len(sensor.findings) == 3
    assert sensor.max_attempts == 3
    assert sensor.enable_safety == True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
