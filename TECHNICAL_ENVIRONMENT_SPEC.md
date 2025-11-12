# Technical Specification: PriorityMaskedEnv for PPO Pentest Training

## 1. Markov Decision Process (MDP) Formulation

The environment implements a **finite-horizon, episodic, partially observable Markov Decision Process (POMDP)** with action masking:

**Formal Definition:**
```
MDP = (S, A, P, R, γ, ρ₀, T, M)
```

Where:
- **S**: State space (continuous, high-dimensional)
- **A**: Action space (discrete, finite)
- **P**: Transition probability function `P(s'|s,a)`
- **R**: Reward function `R(s,a,s')`
- **γ**: Discount factor (typically 0.99)
- **ρ₀**: Initial state distribution
- **T**: Episode horizon (variable length)
- **M**: Action mask function `M(s) → {0,1}^|A|`

---

## 2. State Space (S)

### 2.1 Mathematical Definition

The state space is a continuous vector space:

```
S ⊆ ℝ^d where d = 4N + 3
```

Where:
- **N**: Number of exploit tasks (cardinality of task set)
- **d**: Observation dimensionality

### 2.2 State Vector Composition

The state vector `s_t ∈ S` at timestep `t` is constructed as:

```
s_t = [φ₁(τ₁), φ₂(τ₂), ..., φ_N(τ_N), g(Γ_t)]
```

Where:
- **τᵢ**: Task i from task set T = {τ₁, τ₂, ..., τ_N}
- **φᵢ(τᵢ)**: Feature extraction function for task i
- **g(Γ_t)**: Global state features at time t
- **Γ_t**: Environment global state

### 2.3 Per-Task Feature Representation

For each task τᵢ ∈ T, the feature vector φᵢ(τᵢ) ∈ ℝ⁴ is:

```
φᵢ(τᵢ) = [
    π(τᵢ) / 100.0,           # Normalized priority score
    CVSS(τᵢ) / 10.0,          # Normalized CVSS score
    𝟙(τᵢ ∈ C_t),              # Completion indicator
    𝟙(τᵢ ∈ A_t)               # Availability indicator (mask)
]
```

Where:
- **π(τᵢ)**: Priority score function (range: [0, 100])
- **CVSS(τᵢ)**: Common Vulnerability Scoring System score (range: [0, 10])
- **C_t**: Set of completed tasks at time t
- **A_t**: Set of available (unmasked) tasks at time t
- **𝟙(·)**: Indicator function (1 if true, 0 if false)

### 2.4 Global State Features

The global feature vector g(Γ_t) ∈ ℝ³ is:

```
g(Γ_t) = [
    |C_t| / N,                    # Task completion ratio
    |H_accessible(t)| / N,        # Network access ratio
    t / T_max                     # Temporal progress
]
```

Where:
- **|C_t|**: Cardinality of completed task set
- **H_accessible(t)**: Set of accessible network hosts at time t
- **T_max**: Maximum episode length (horizon)

### 2.5 State Space Properties

- **Dimensionality**: d = 4N + 3 (scales linearly with task count)
- **Bounds**: s_t ∈ [0, 1]^d (all features normalized to unit interval)
- **Type**: Continuous, bounded, fully observable within episode
- **Example**: For N=10 tasks, d = 43 dimensions

---

## 3. Action Space (A)

### 3.1 Mathematical Definition

The action space is a **discrete, finite set**:

```
A = {0, 1, 2, ..., N-1}
```

Where each action `a ∈ A` corresponds to selecting task τ_{a+1} for exploitation.

### 3.2 Action Semantics

Action `a_t` at timestep t represents:

```
a_t: A → T
a_t(i) = τ_{i+1}   (select and execute exploit for task i+1)
```

### 3.3 Action Space Properties

- **Type**: Discrete (gym.spaces.Discrete)
- **Cardinality**: |A| = N (fixed per environment instance)
- **Structure**: Flat (non-hierarchical)
- **Constraints**: Subject to action masking M(s_t)

---

## 4. Action Masking Function (M)

### 4.1 Formal Definition

The action mask function M: S → {0,1}^|A| determines valid actions:

```
M(s_t) = [m₀(s_t), m₁(s_t), ..., m_{N-1}(s_t)]

Where mᵢ(s_t) = {
    0,  if τᵢ ∈ C_t ∨ τᵢ ∉ A_t     (masked)
    1,  if τᵢ ∉ C_t ∧ τᵢ ∈ A_t     (valid)
}
```

### 4.2 Sequential Masking Policy

In **sequential mode** (default), the availability set A_t is restricted:

```
A_t = {τ_k} where k = argmax_{i: τᵢ ∉ C_t} π(τᵢ)
```

This enforces **single-task exposure**: only the highest-priority uncompleted task is unmasked.

### 4.3 Parallel Masking Policy

In **parallel mode**, the availability set is unrestricted:

```
A_t = T \ C_t
```

All uncompleted tasks are simultaneously available.

### 4.4 Masking Integration with PPO

The masked action space A'_t ⊆ A at time t is:

```
A'_t = {a ∈ A : M(s_t)[a] = 1}
```

Policy sampling is restricted to A'_t:

```
π(a|s_t) = {
    softmax(logits[a])/Z,  if a ∈ A'_t
    0,                      if a ∉ A'_t
}

Where Z = Σ_{a' ∈ A'_t} softmax(logits[a'])
```

---

## 5. Transition Dynamics (P)

### 5.1 Deterministic Components

The environment exhibits **deterministic transitions** for most state components:

```
P(s_{t+1} | s_t, a_t) = δ(s_{t+1} - f(s_t, a_t))
```

Where f is the deterministic transition function:

```
f(s_t, a_t) updates:
- C_{t+1} = C_t ∪ {τ_{a_t}} if execution attempted
- H_accessible(t+1) = H_accessible(t) ∪ H_compromised(a_t) if success
- Step counter: t → t+1
```

### 5.2 Stochastic Components

**Exploit execution outcome** introduces stochasticity:

#### Mode A: Probabilistic Simulation

```
P(success | τᵢ) = {
    0.90,  if CVSS(τᵢ) ≥ 9.0
    0.75,  if 7.0 ≤ CVSS(τᵢ) < 9.0
    0.60,  if 4.0 ≤ CVSS(τᵢ) < 7.0
    0.40,  if CVSS(τᵢ) < 4.0
}
```

Stochastic transition:

```
success_t ~ Bernoulli(P(success | τ_{a_t}))
```

#### Mode B: Real Script Execution

```
success_t = Execute(script(τ_{a_t}), target(τ_{a_t}), timeout)
```

Outcome depends on:
- Script correctness
- Target vulnerability state
- Network conditions
- Timeout constraints

### 5.3 Transition Function Properties

- **Markovian**: P(s_{t+1}|s_t, a_t) (no memory beyond current state)
- **Partially stochastic**: Deterministic state updates + stochastic execution
- **Episodic**: Terminates at fixed conditions

---

## 6. Reward Function (R)

### 6.1 Mathematical Definition

The reward function R: S × A × S → ℝ is defined as:

```
R(s_t, a_t, s_{t+1}) = R_validity(a_t, s_t) + R_execution(a_t, s_t, s_{t+1}) + R_step
```

### 6.2 Reward Components

#### 6.2.1 Validity Reward

```
R_validity(a_t, s_t) = {
    0,              if M(s_t)[a_t] = 1  (valid action)
    -2 × r_fail,    if M(s_t)[a_t] = 0  (invalid action)
}

Where r_fail = 10.0 (base failure penalty)
```

#### 6.2.2 Execution Reward

```
R_execution(a_t, s_t, s_{t+1}) = {
    r_success + β × CVSS(τ_{a_t})/10.0,  if success_t = 1
    -r_fail,                              if success_t = 0
}

Where:
- r_success = 100.0 (base success reward)
- r_fail = 10.0 (base failure penalty)
- β = 50.0 (risk bonus weight)
```

**Risk-adjusted reward** for successful exploitation:

```
R_success(τᵢ) = 100 + 50 × (CVSS(τᵢ)/10) ∈ [100, 150]
```

#### 6.2.3 Step Penalty

```
R_step = -1.0  (constant per timestep)
```

Encourages episode efficiency.

### 6.3 Total Reward Examples

**Example 1: Successful high-risk exploit**
```
Task: CVE-2017-0144 (EternalBlue), CVSS = 10.0
R = 0 + (100 + 50×1.0) + (-1) = 149
```

**Example 2: Failed medium-risk exploit**
```
Task: CVE-2019-0708 (BlueKeep), CVSS = 7.5
R = 0 + (-10) + (-1) = -11
```

**Example 3: Invalid action (masked task)**
```
Task: Already completed
R = -20 + 0 + (-1) = -21
```

### 6.4 Expected Episode Return

For episode with length T and k successes:

```
G = Σ_{t=0}^{T-1} γ^t R_t

Expected: E[G] ≈ k × 125 - (T-k) × 11 - T
```

Where:
- k successes at avg CVSS 7.5: ~125 reward each
- (T-k) failures: -11 reward each
- T step penalties: -1 each

---

## 7. Episode Structure

### 7.1 Initialization

Episode begins with:

```
s_0 ~ ρ₀, where ρ₀(s) = δ(s - s_init)

s_init = [
    [π(τ₁)/100, CVSS(τ₁)/10, 0, 𝟙(τ₁ ∈ A_0)],
    [π(τ₂)/100, CVSS(τ₂)/10, 0, 𝟙(τ₂ ∈ A_0)],
    ...,
    [π(τ_N)/100, CVSS(τ_N)/10, 0, 𝟙(τ_N ∈ A_0)],
    [0, 1, 0]  # Global: 0% progress, full access, step 0
]
```

### 7.2 Termination Conditions

Episode terminates when:

```
done_t = (|C_t| ≥ N) ∨ (t ≥ T_max)
```

Where:
- **|C_t| ≥ N**: All tasks attempted (normal termination)
- **t ≥ T_max**: Maximum steps reached (truncation)

### 7.3 Episode Trajectory

Complete trajectory τ:

```
τ = (s_0, a_0, r_0, s_1, a_1, r_1, ..., s_T, a_T, r_T)
```

### 7.4 Episode Length Statistics

- **Minimum length**: T_min = N (one action per task, all valid)
- **Maximum length**: T_max = 2N (default) or configured
- **Expected length**: E[T] ≈ N × 1.2 (accounting for invalid actions during learning)

---

## 8. Environment Properties

### 8.1 Observability

- **Type**: Fully observable (within episode scope)
- **Justification**: Agent sees complete task state, network state, and progress
- **Caveat**: Attack chain dependencies create partial observability across episodes

### 8.2 Determinism

- **Classification**: Stochastic
- **Sources of Stochasticity**:
  - Exploit execution outcomes (probabilistic or real-world variability)
  - Initial state distribution ρ₀ (if randomized)

### 8.3 Episodic vs Continuing

- **Type**: Episodic
- **Episode boundary**: Clear start (reset) and termination conditions
- **No discount across episodes**: Each episode is independent

### 8.4 Action Space Structure

- **Type**: Discrete, finite
- **Cardinality**: O(N) where N = number of tasks
- **Masking**: Dynamic, state-dependent
- **Constraint complexity**: O(1) per state (sequential mode)

### 8.5 Reward Structure

- **Type**: Sparse + Dense
- **Sparse component**: Large rewards on success/failure
- **Dense component**: Per-step penalty
- **Horizon sensitivity**: Unbounded (no explicit discount in rewards)

### 8.6 State Space Complexity

- **Dimensionality**: Linear in N: O(4N + 3)
- **Scalability**: Handles 10-100 tasks effectively
- **Bottleneck**: Policy network capacity, not observation size

---

## 9. Gymnasium API Implementation

### 9.1 Interface Specification

The environment implements the **Gymnasium** (formerly OpenAI Gym) API:

```python
class PriorityMaskedEnv(gym.Env):
    """Gymnasium-compliant pentest environment"""

    # Required attributes
    action_space: gym.spaces.Discrete
    observation_space: gym.spaces.Box
    metadata: Dict[str, Any] = {'render.modes': ['human']}
```

### 9.2 Core Methods

#### 9.2.1 Reset

```python
def reset(
    self,
    seed: Optional[int] = None,
    options: Optional[Dict] = None
) -> Tuple[np.ndarray, Dict]:
    """
    Reset environment to initial state.

    Returns:
        observation: s_0 ∈ S (initial state)
        info: Auxiliary diagnostic information
    """
```

**Postconditions:**
- C_0 = ∅ (no completed tasks)
- t = 0 (timestep reset)
- A_0 determined by masking policy

#### 9.2.2 Step

```python
def step(
    self,
    action: int
) -> Tuple[np.ndarray, float, bool, bool, Dict]:
    """
    Execute action and transition environment.

    Args:
        action: a_t ∈ A (discrete action index)

    Returns:
        observation: s_{t+1} ∈ S (next state)
        reward: R(s_t, a_t, s_{t+1}) ∈ ℝ
        terminated: Whether episode naturally ended
        truncated: Whether episode was cut off
        info: Auxiliary diagnostic information
    """
```

**State transition:**
```
(s_t, a_t) → (s_{t+1}, r_t)
```

#### 9.2.3 Action Masking

```python
def action_masks(self) -> np.ndarray:
    """
    Return valid action mask for current state.

    Returns:
        mask: M(s_t) ∈ {0,1}^N (binary mask)
    """
```

Used by **Stable-Baselines3 MaskablePPO**.

### 9.3 Vectorization Support

Compatible with `VecEnv` wrappers:

```python
from stable_baselines3.common.vec_env import DummyVecEnv, SubprocVecEnv

# Single-process vectorization
env = DummyVecEnv([lambda: PriorityMaskedEnv(...) for _ in range(4)])

# Multi-process vectorization
env = SubprocVecEnv([lambda: PriorityMaskedEnv(...) for _ in range(4)])
```

**Parallelization**: 4-16 environments typical for PPO training

---

## 10. PPO Integration Specifics

### 10.1 Policy Architecture

**Input Layer:**
```
Observation: s_t ∈ ℝ^{4N+3}
```

**Hidden Layers (MLP):**
```
h_1 = ReLU(W_1 × s_t + b_1),  W_1 ∈ ℝ^{64 × d}
h_2 = ReLU(W_2 × h_1 + b_2),  W_2 ∈ ℝ^{64 × 64}
```

**Policy Head (Actor):**
```
logits = W_π × h_2 + b_π,  W_π ∈ ℝ^{N × 64}

π(a|s) = softmax(logits)[a] × M(s)[a] / Z
```

**Value Head (Critic):**
```
V(s) = W_V × h_2 + b_V,  W_V ∈ ℝ^{1 × 64}
```

### 10.2 Training Hyperparameters

```python
PPO(
    policy="MlpPolicy",
    env=env,
    learning_rate=3e-4,         # α (Adam optimizer)
    n_steps=2048,               # Rollout length per env
    batch_size=64,              # Minibatch size
    n_epochs=10,                # Epochs per update
    gamma=0.99,                 # Discount factor γ
    gae_lambda=0.95,            # GAE λ
    clip_range=0.2,             # PPO clip ε
    ent_coef=0.01,              # Entropy bonus β_H
    vf_coef=0.5,                # Value loss weight
    max_grad_norm=0.5           # Gradient clipping
)
```

### 10.3 Advantage Estimation

**Generalized Advantage Estimation (GAE):**

```
A_t^GAE(γ,λ) = Σ_{l=0}^{∞} (γλ)^l δ_{t+l}

Where:
δ_t = r_t + γV(s_{t+1}) - V(s_t)  (TD residual)
```

### 10.4 Policy Update Objective

**Clipped Surrogate Objective:**

```
L_CLIP(θ) = E_t[min(
    r_t(θ) Â_t,
    clip(r_t(θ), 1-ε, 1+ε) Â_t
)]

Where:
r_t(θ) = π_θ(a_t|s_t) / π_θ_old(a_t|s_t)  (probability ratio)
ε = 0.2  (clip range)
```

**Value Function Loss:**

```
L_VF(θ) = E_t[(V_θ(s_t) - V_target(s_t))²]
```

**Entropy Bonus:**

```
L_ENT(θ) = -E_t[H(π_θ(·|s_t))]
         = -E_t[Σ_a π_θ(a|s_t) log π_θ(a|s_t)]
```

**Total Loss:**

```
L(θ) = -L_CLIP(θ) + c_1 L_VF(θ) - c_2 L_ENT(θ)

Where:
c_1 = 0.5  (value loss coefficient)
c_2 = 0.01 (entropy coefficient)
```

---

## 11. Computational Complexity

### 11.1 Time Complexity

**Per Step:**
- Observation construction: O(N)
- Action masking: O(N)
- Reward calculation: O(1)
- State transition: O(1)

**Total per step**: O(N)

**Per Episode:**
- Expected steps: E[T] ≈ N
- Episode complexity: O(N²)

### 11.2 Space Complexity

**State representation**: O(N)
**Action mask storage**: O(N)
**Episode trajectory**: O(NT) where T ≈ N

**Total**: O(N²) per episode

### 11.3 Training Scalability

**Forward pass (policy):**
```
O(batch_size × d × hidden_dim + hidden_dim × N)
≈ O(B × N × H + H × N)
≈ O(BNH) where B=64, H=64
```

**Backward pass (PPO update):**
```
O(n_steps × n_epochs × batch_size)
≈ O(2048 × 10 × 64) = O(1.3M operations per update)
```

---

## 12. Environment Variants

### 12.1 Sequential Mode (Default)

```
sequential_mode = True
|A'_t| = 1  (single task exposed)
```

**Properties:**
- Faster convergence (4× empirically)
- Deterministic task ordering
- Mimics real pentesting workflow

### 12.2 Parallel Mode

```
sequential_mode = False
|A'_t| = |T \ C_t|  (all uncompleted tasks)
```

**Properties:**
- More exploration
- Flexible task ordering
- Slower convergence

### 12.3 Execution Modes

**Simulation Mode:**
```
use_real_execution = False
P(success|τ) = f(CVSS(τ))  (probabilistic)
```

**Real Execution Mode:**
```
use_real_execution = True
success ~ Execute(script(τ), target(τ))  (actual scripts)
```

---

## 13. Formal Environment Verification

### 13.1 Gym Compliance Check

```python
from stable_baselines3.common.env_checker import check_env

env = PriorityMaskedEnv(...)
check_env(env)  # Validates Gym API compliance
```

### 13.2 Key Invariants

1. **Action mask consistency**: ∀t: M(s_t)[a] = 1 ⟹ a is executable
2. **State bounds**: ∀t: s_t ∈ [0,1]^d
3. **Episode termination**: |C_T| = N ∨ T = T_max
4. **Reward boundedness**: R ∈ [-21, 150]
5. **Markov property**: P(s_{t+1}|s_0,...,s_t, a_t) = P(s_{t+1}|s_t, a_t)

---

## 14. Performance Metrics

### 14.1 Environment Metrics

- **Episode length**: E[T]
- **Task completion rate**: |C_T| / N
- **Success rate**: (# successes) / |C_T|
- **Invalid action rate**: (# invalid actions) / T

### 14.2 Learning Metrics

- **Average return**: E[G] = E[Σ_t γ^t R_t]
- **Success rate on critical vulns**: P(success | CVSS ≥ 9.0)
- **Policy entropy**: H(π(·|s))
- **Value function error**: E[(V(s) - V_target(s))²]

### 14.3 Convergence Criteria

Training converges when:

```
E[G] > threshold (e.g., 0.8 × N × 125)  AND
σ[G] < variance_threshold  AND
Invalid_rate < 0.05
```

---

## 15. Mathematical Properties

### 15.1 State Space Geometry

- **Manifold**: Hypercube [0,1]^d
- **Reachable states**: Dense subset of S (not all corners reachable)
- **State trajectory**: Piecewise linear path through S

### 15.2 Reward Distribution

**Empirical distribution** from simulation:

```
R ~ Mixture(
    p₁ × Uniform(100, 150),    # Success outcomes
    p₂ × δ(-11),                # Failure outcomes
    p₃ × δ(-21)                 # Invalid actions
)

Where: p₁ ≈ 0.7, p₂ ≈ 0.25, p₃ ≈ 0.05 (after learning)
```

### 15.3 Policy Convergence

**Optimal policy** π* in sequential mode:

```
π*(a|s) = {
    1, if a = argmax_{i: M(s)[i]=1} CVSS(τᵢ)
    0, otherwise
}
```

This is a **deterministic, greedy policy** w.r.t. CVSS score.

---

## 16. Implementation Details

### 16.1 Dependencies

```
gymnasium >= 0.28.0
numpy >= 1.21.0
stable-baselines3 >= 2.0.0
torch >= 1.12.0
```

### 16.2 Numerical Stability

- All observations normalized to [0, 1]
- Rewards scaled to [-21, 150] range
- No exponential terms (prevents overflow)
- Integer counters for completion tracking

### 16.3 Reproducibility

```python
env = PriorityMaskedEnv(...)
env.reset(seed=42)  # Sets environment RNG seed
```

PPO training seed:
```python
set_random_seed(42)  # Sets global seeds (NumPy, PyTorch, Python random)
```

---

## Summary Table

| Property | Value | Type |
|----------|-------|------|
| **State Space** | ℝ^{4N+3} | Continuous, bounded |
| **Action Space** | {0,...,N-1} | Discrete, finite |
| **Masking** | M: S → {0,1}^N | State-dependent |
| **Transition** | P(s'|s,a) | Partially stochastic |
| **Reward** | R: S×A×S → ℝ | Bounded, sparse+dense |
| **Episode Length** | T ∈ [N, 2N] | Variable |
| **Discount** | γ = 0.99 | Standard |
| **Observability** | Full (episodic) | Complete state |
| **Stochasticity** | Execution outcomes | Bernoulli(p_CVSS) |
| **Complexity** | O(N) per step | Linear in tasks |

---

This specification provides the complete formal mathematical and technical foundation for the PPO pentest training environment.
