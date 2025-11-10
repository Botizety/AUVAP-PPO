"""
Docker-Based Sandbox Executor (Priority 1, Item 3)

Implements isolated, safe execution of exploit scripts with:
- Docker containerization for isolation
- Network isolation by default
- Resource limits (CPU, memory, timeout)
- Execution result tracking
"""

import docker
import os
import tempfile
import shutil
from dataclasses import dataclass
from typing import Optional, Dict, List
from pathlib import Path
import time
import subprocess


@dataclass
class ExecutionResult:
    """Result of sandbox execution"""
    status: str  # "success", "failure", "timeout", "error"
    exit_code: int
    stdout: str
    stderr: str
    duration: float
    logs: List[str]
    artifacts: Dict = None
    safety_violations: List[str] = None

    def __post_init__(self):
        if self.artifacts is None:
            self.artifacts = {}
        if self.safety_violations is None:
            self.safety_violations = []


class SandboxExecutor:
    """
    Docker-based sandbox for safe exploit execution.

    Features:
    - Network isolation (no external access)
    - Resource limits (512MB RAM, 1 CPU)
    - Execution timeout (10s default)
    - Clean teardown after execution
    """

    def __init__(self,
                 docker_image: str = "python:3.10-slim",
                 default_timeout: int = 10,
                 memory_limit: str = "512m",
                 cpu_count: float = 1.0,
                 enable_network: bool = False,
                 work_dir: str = "/tmp/sandbox_workdir"):
        """
        Initialize sandbox executor.

        Args:
            docker_image: Docker image to use
            default_timeout: Default execution timeout in seconds
            memory_limit: Memory limit (e.g., "512m")
            cpu_count: CPU count limit
            enable_network: Enable network access (default: False for safety)
            work_dir: Working directory for temporary files
        """
        self.docker_image = docker_image
        self.default_timeout = default_timeout
        self.memory_limit = memory_limit
        self.cpu_count = cpu_count
        self.enable_network = enable_network
        self.work_dir = Path(work_dir)
        self.work_dir.mkdir(parents=True, exist_ok=True)

        # Initialize Docker client
        try:
            self.client = docker.from_env()
            # Test connection
            self.client.ping()
        except Exception as e:
            print(f"Warning: Docker not available: {e}")
            self.client = None

    def execute_task(self,
                    task_id: str,
                    script_path: str,
                    timeout: Optional[int] = None,
                    env_vars: Optional[Dict] = None) -> ExecutionResult:
        """
        Execute a task in isolated Docker container.

        Args:
            task_id: Unique task identifier
            script_path: Path to script to execute
            timeout: Execution timeout (uses default if None)
            env_vars: Environment variables for execution

        Returns:
            ExecutionResult with execution details
        """
        if self.client is None:
            # Fallback to local execution (not safe, for testing only)
            return self._execute_local(script_path, timeout or self.default_timeout)

        timeout = timeout or self.default_timeout
        start_time = time.time()

        # Create temporary directory for this execution
        exec_dir = self.work_dir / task_id
        exec_dir.mkdir(parents=True, exist_ok=True)

        try:
            # Copy script to execution directory
            script_name = Path(script_path).name
            target_script = exec_dir / script_name
            shutil.copy(script_path, target_script)

            # Create container configuration
            container_config = {
                'image': self.docker_image,
                'command': ['python', f'/workspace/{script_name}'],
                'volumes': {
                    str(exec_dir): {'bind': '/workspace', 'mode': 'rw'}
                },
                'working_dir': '/workspace',
                'mem_limit': self.memory_limit,
                'nano_cpus': int(self.cpu_count * 1e9),
                'network_disabled': not self.enable_network,
                'detach': True,
                'remove': False,  # Don't auto-remove so we can inspect logs
                'environment': env_vars or {}
            }

            # Run container
            container = self.client.containers.run(**container_config)

            # Wait for completion with timeout
            try:
                result = container.wait(timeout=timeout)
                exit_code = result['StatusCode']
                status = "success" if exit_code == 0 else "failure"
            except docker.errors.ReadTimeout:
                container.kill()
                status = "timeout"
                exit_code = -1

            # Get logs
            stdout = container.logs(stdout=True, stderr=False).decode('utf-8', errors='ignore')
            stderr = container.logs(stdout=False, stderr=True).decode('utf-8', errors='ignore')

            # Check for safety violations
            safety_violations = self._check_safety_violations(stdout + stderr)

            # Cleanup container
            container.remove(force=True)

            duration = time.time() - start_time

            return ExecutionResult(
                status=status,
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                duration=duration,
                logs=[stdout, stderr],
                safety_violations=safety_violations
            )

        except Exception as e:
            duration = time.time() - start_time
            return ExecutionResult(
                status="error",
                exit_code=-1,
                stdout="",
                stderr=str(e),
                duration=duration,
                logs=[str(e)],
                safety_violations=[]
            )

        finally:
            # Cleanup execution directory
            try:
                shutil.rmtree(exec_dir)
            except:
                pass

    def _execute_local(self, script_path: str, timeout: int) -> ExecutionResult:
        """
        Fallback: Execute locally (NOT SAFE, for testing only).

        Args:
            script_path: Path to script
            timeout: Execution timeout

        Returns:
            ExecutionResult
        """
        start_time = time.time()

        try:
            result = subprocess.run(
                ['python', script_path],
                capture_output=True,
                text=True,
                timeout=timeout
            )

            status = "success" if result.returncode == 0 else "failure"
            duration = time.time() - start_time

            return ExecutionResult(
                status=status,
                exit_code=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr,
                duration=duration,
                logs=[result.stdout, result.stderr],
                safety_violations=[]
            )

        except subprocess.TimeoutExpired:
            return ExecutionResult(
                status="timeout",
                exit_code=-1,
                stdout="",
                stderr="Execution timed out",
                duration=timeout,
                logs=["Timeout"],
                safety_violations=[]
            )

        except Exception as e:
            return ExecutionResult(
                status="error",
                exit_code=-1,
                stdout="",
                stderr=str(e),
                duration=time.time() - start_time,
                logs=[str(e)],
                safety_violations=[]
            )

    def _check_safety_violations(self, output: str) -> List[str]:
        """
        Check execution output for safety violations.

        Args:
            output: Combined stdout/stderr

        Returns:
            List of detected violations
        """
        violations = []

        # Dangerous patterns
        patterns = {
            'rm -rf /': 'Attempted to delete root filesystem',
            'DROP DATABASE': 'Attempted database destruction',
            '> /dev/sda': 'Attempted disk write',
            'format': 'Attempted disk format',
            'dd if=/dev/zero': 'Attempted disk zeroing',
            'curl http://': 'Attempted external network access',
            'wget http://': 'Attempted external download',
            ':(){ :|:& };:': 'Fork bomb detected'
        }

        for pattern, description in patterns.items():
            if pattern in output:
                violations.append(description)

        return violations

    def cleanup(self):
        """Cleanup sandbox resources"""
        try:
            if self.work_dir.exists():
                shutil.rmtree(self.work_dir)
        except:
            pass

    def pull_image(self, image: Optional[str] = None):
        """Pull Docker image if not available"""
        if self.client is None:
            return

        image = image or self.docker_image

        try:
            self.client.images.pull(image)
            print(f"✓ Pulled Docker image: {image}")
        except Exception as e:
            print(f"✗ Failed to pull image {image}: {e}")

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.cleanup()
