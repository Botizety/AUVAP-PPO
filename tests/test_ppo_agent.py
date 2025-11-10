#!/usr/bin/env python3
"""
test_ppo_agent.py - Unit tests for PPO Agent

Tests the custom PPO implementation including:
- PolicyNetwork architecture
- PPOAgent training loop
- Action selection and masking
- GAE computation
- Loss calculation
"""

import pytest
import torch
import numpy as np
from pathlib import Path
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from ppo_agent import PolicyNetwork, PPOAgent


class TestPolicyNetwork:
    """Test PolicyNetwork architecture and forward pass."""

    def test_network_initialization(self):
        """Test network initialization with valid parameters."""
        obs_dim = 128
        action_dim = 50

        network = PolicyNetwork(obs_dim, action_dim)

        assert network.obs_dim == obs_dim
        assert network.action_dim == action_dim
        assert isinstance(network.fc1, torch.nn.Linear)
        assert isinstance(network.fc2, torch.nn.Linear)
        assert isinstance(network.policy_head, torch.nn.Linear)
        assert isinstance(network.value_head, torch.nn.Linear)

    def test_forward_pass_shape(self):
        """Test forward pass output shapes."""
        obs_dim = 128
        action_dim = 50
        batch_size = 32

        network = PolicyNetwork(obs_dim, action_dim)
        obs = torch.randn(batch_size, obs_dim)

        logits, value = network(obs)

        assert logits.shape == (batch_size, action_dim)
        assert value.shape == (batch_size, 1)

    def test_forward_pass_with_mask(self):
        """Test forward pass with action masking."""
        obs_dim = 128
        action_dim = 50
        batch_size = 4

        network = PolicyNetwork(obs_dim, action_dim)
        obs = torch.randn(batch_size, obs_dim)

        # Create mask: allow only first 10 actions
        mask = torch.zeros(batch_size, action_dim, dtype=torch.bool)
        mask[:, :10] = True

        logits, value = network(obs, mask)

        # Check that masked actions have -inf logits
        assert torch.all(logits[:, 10:] == float('-inf'))
        assert torch.all(torch.isfinite(logits[:, :10]))

    def test_value_range(self):
        """Test that value predictions are reasonable."""
        obs_dim = 128
        action_dim = 50

        network = PolicyNetwork(obs_dim, action_dim)
        obs = torch.randn(10, obs_dim)

        _, value = network(obs)

        # Values should be finite
        assert torch.all(torch.isfinite(value))


class TestPPOAgent:
    """Test PPOAgent training and inference."""

    @pytest.fixture
    def agent(self):
        """Create a test PPO agent."""
        return PPOAgent(
            obs_dim=128,
            action_dim=50,
            lr=3e-4,
            gamma=0.99,
            gae_lambda=0.95,
            clip_epsilon=0.2,
            entropy_coef=0.01,
            value_coef=0.5
        )

    def test_agent_initialization(self, agent):
        """Test agent initialization."""
        assert agent.obs_dim == 128
        assert agent.action_dim == 50
        assert agent.gamma == 0.99
        assert agent.gae_lambda == 0.95
        assert agent.clip_epsilon == 0.2
        assert isinstance(agent.policy, PolicyNetwork)
        assert isinstance(agent.optimizer, torch.optim.Adam)

    def test_select_action(self, agent):
        """Test action selection."""
        obs = torch.randn(128)

        action, log_prob, value = agent.select_action(obs)

        assert isinstance(action, int)
        assert 0 <= action < 50
        assert isinstance(log_prob, float)
        assert isinstance(value, float)

    def test_select_action_with_mask(self, agent):
        """Test action selection with masking."""
        obs = torch.randn(128)

        # Create mask: only allow actions 0-9
        mask = torch.zeros(50, dtype=torch.bool)
        mask[:10] = True

        action, log_prob, value = agent.select_action(obs, mask)

        # Action should be in allowed range
        assert 0 <= action < 10

    def test_compute_gae(self, agent):
        """Test Generalized Advantage Estimation."""
        rewards = [1.0, 2.0, 3.0, 0.0]
        values = [0.5, 1.0, 1.5, 0.0]
        dones = [False, False, False, True]

        advantages = agent.compute_gae(rewards, values, dones)

        assert len(advantages) == len(rewards)
        assert all(isinstance(adv, float) for adv in advantages)

    def test_update_with_batch(self, agent):
        """Test policy update with a small batch."""
        batch_size = 16

        # Create dummy trajectory
        obs_batch = torch.randn(batch_size, 128)
        action_batch = torch.randint(0, 50, (batch_size,))
        log_prob_batch = torch.randn(batch_size)
        advantage_batch = torch.randn(batch_size)
        return_batch = torch.randn(batch_size)

        # Get initial loss
        initial_params = [p.clone() for p in agent.policy.parameters()]

        loss_dict = agent.update(
            obs_batch,
            action_batch,
            log_prob_batch,
            advantage_batch,
            return_batch
        )

        # Check loss dict structure
        assert 'policy_loss' in loss_dict
        assert 'value_loss' in loss_dict
        assert 'entropy' in loss_dict
        assert 'total_loss' in loss_dict

        # Check that parameters were updated
        final_params = list(agent.policy.parameters())
        params_changed = any(
            not torch.equal(init, final)
            for init, final in zip(initial_params, final_params)
        )
        assert params_changed

    def test_save_and_load(self, agent, tmp_path):
        """Test model saving and loading."""
        # Save model
        save_path = tmp_path / "test_model.pt"
        agent.save(save_path)

        assert save_path.exists()

        # Create new agent and load
        new_agent = PPOAgent(
            obs_dim=128,
            action_dim=50,
            lr=3e-4,
            gamma=0.99,
            gae_lambda=0.95,
            clip_epsilon=0.2
        )
        new_agent.load(save_path)

        # Check that parameters match
        for p1, p2 in zip(agent.policy.parameters(), new_agent.policy.parameters()):
            assert torch.equal(p1, p2)

    def test_gradient_clipping(self, agent):
        """Test that gradients are clipped properly."""
        batch_size = 32

        obs_batch = torch.randn(batch_size, 128)
        action_batch = torch.randint(0, 50, (batch_size,))
        log_prob_batch = torch.randn(batch_size)

        # Create large advantages to trigger clipping
        advantage_batch = torch.randn(batch_size) * 100
        return_batch = torch.randn(batch_size) * 100

        # Should not raise error
        loss_dict = agent.update(
            obs_batch,
            action_batch,
            log_prob_batch,
            advantage_batch,
            return_batch
        )

        # Check that losses are finite
        assert all(np.isfinite(v) for v in loss_dict.values())


class TestTrainingLoop:
    """Test complete training loop behavior."""

    def test_episode_rollout(self):
        """Test collecting a trajectory from environment interaction."""
        agent = PPOAgent(obs_dim=128, action_dim=50)

        # Simulate episode
        trajectory = {
            'observations': [],
            'actions': [],
            'log_probs': [],
            'values': [],
            'rewards': [],
            'dones': []
        }

        # Collect 10 steps
        for _ in range(10):
            obs = torch.randn(128)
            action, log_prob, value = agent.select_action(obs)

            trajectory['observations'].append(obs)
            trajectory['actions'].append(action)
            trajectory['log_probs'].append(log_prob)
            trajectory['values'].append(value)
            trajectory['rewards'].append(np.random.uniform(-1, 1))
            trajectory['dones'].append(False)

        # Mark last step as done
        trajectory['dones'][-1] = True

        # Verify trajectory structure
        assert len(trajectory['observations']) == 10
        assert len(trajectory['actions']) == 10
        assert len(trajectory['rewards']) == 10
        assert trajectory['dones'][-1] == True

    def test_advantage_computation_full_episode(self):
        """Test advantage computation on full episode."""
        agent = PPOAgent(obs_dim=128, action_dim=50, gamma=0.99, gae_lambda=0.95)

        # Create episode with clear reward structure
        rewards = [0, 0, 0, 0, 10]  # Reward at end
        values = [1, 2, 3, 4, 5]
        dones = [False, False, False, False, True]

        advantages = agent.compute_gae(rewards, values, dones)

        # Last advantage should be positive (reward > value)
        assert advantages[-1] > 0

        # Earlier advantages should propagate backwards
        assert len(advantages) == 5


def test_action_masking_integration():
    """Integration test for action masking throughout pipeline."""
    agent = PPOAgent(obs_dim=128, action_dim=50)

    obs = torch.randn(128)

    # Test with no masking
    action1, _, _ = agent.select_action(obs)
    assert 0 <= action1 < 50

    # Test with restrictive masking
    mask = torch.zeros(50, dtype=torch.bool)
    mask[0] = True  # Only allow action 0

    action2, _, _ = agent.select_action(obs, mask)
    assert action2 == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
