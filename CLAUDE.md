# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

---

## Project Overview

### Storyline: Bob vs SecureEncrypCompany

**The Setup**:
Bob is evaluating SecureEncrypCompany's "state-of-the-art" RSA-as-a-service for his SaaS application. The vendor makes bold claims:

1. ⚡ **Lightning-fast prime generation** (100% verified with Miller-Rabin test)
2. 🚀 **Blazing decryption speeds** (optimized for performance)
3. 🔒 **Super secure encryption** with extremely large public keys
4. ✅ **Cryptographically sound** (uses standard algorithms)

**Bob's Suspicions**:
Having studied SC4010 Applied Cryptography, Bob's alarm bells ring:
- Fast prime generation → suggests p and q might be related/close
- Fast decryption + huge public key → indicates small d (private exponent) and correspondingly large e (public exponent)

**Bob's Investigation**:
Bob invokes **Kerckhoff's principle** (security should not depend on algorithm secrecy) and requests the source code. Upon deep analysis, he discovers fatal flaws despite the "verified primes":

1. **Close Primes Vulnerability**:
   - p and q generated using incremental ±2 search from the same random seed
   - Results in `|p-q| ≈ 60` (only ~6 bits of separation!)
   - Functions: `generate_prime_factors_up()` and `generate_prime_factors_down()`
   - Susceptible to Fermat factorization

2. **Small Private Exponent Vulnerability**:
   - d chosen as only 256 bits first (for "blazing decryption")
   - e computed as modular inverse of d, resulting in huge e (≈2048 bits)
   - Violates Wiener security threshold: `d ≥ (1/3)·N^(1/4)`
   - Enables continued fraction attack to recover d

**Bob's Response**:
Bob implements a comprehensive attack suite to demonstrate these vulnerabilities and present evidence to the company.

**IMPORTANT**: This codebase contains **intentionally vulnerable** cryptographic implementations for educational purposes. The weak implementation is designed to be broken.

### Work Division

**Randy's Contributions** (Exploiting Close Primes):
- Fermat factorization attack
- Quadratic Sieve educational demonstration

**Ke Yuan's Contributions** (Exploiting Small d):
- Wiener attack implementation (continued fractions method)
- Boneh-Durfee theoretical analysis (lattice-based improvement)

---

## Running the Code

### **Main Attack Suite** (`claude_attacks_implementation.py`)

The main attack file **automatically detects and uses saved parameters** from `values.py` if available.

#### **Option 1: Use Saved Parameters** (Recommended - Consistent Results)

```bash
# Step 1: Generate weak RSA parameters (creates values.py)
cd Project
python rsa_weak_implementation.py
# Enter any text when prompted (e.g., "test")

# Step 2: Run attacks (automatically uses values.py)
python claude_attacks_implementation.py
```

**What happens:**
1. ✅ `rsa_weak_implementation.py` generates weak p, q, N, d and saves to `values.py`
2. ✅ `claude_attacks_implementation.py` detects `values.py` and loads parameters
3. ✅ Runs all attacks on the saved parameters
4. ✅ Same results every time (reproducible)

**Why use this?**
- 🔁 Consistent parameters across multiple runs
- 📤 Share `values.py` with team via GitHub
- 📊 Perfect for documentation and presentations
- 🎯 Realistic: "Bob receives vendor's parameters"

---

#### **Option 2: Generate Fresh Parameters** (Quick Testing)

```bash
# Just run the attack suite directly
cd Project
python claude_attacks_implementation.py
```

**What happens:**
1. ✅ No `values.py` detected
2. ✅ Generates fresh weak RSA parameters automatically
3. ✅ Runs all attacks immediately
4. ✅ Different parameters each run

**Why use this?**
- ⚡ Quick one-command demo
- 🎲 See attack work on different weak instances
- 🚀 Fastest way to test

---

### **How It Works**

The `claude_attacks_implementation.py` is **smart**:

```python
# Pseudocode inside main()
if values.py exists:
    print("📂 Loading saved parameters from values.py")
    load parameters from values.py
    run attacks
else:
    print("💡 Generating fresh weak parameters")
    generate new weak RSA
    run attacks
```

---

### **Verification Tests** (Optional)
```bash
python Project/test_verification.py
```

Shows quantitative proof of vulnerabilities:
- Displays actual `|p-q|` and bit count
- Calculates Wiener threshold `(1/3)·N^(1/4)`
- Verifies `d < threshold` (confirms vulnerability)
- Validates `e·d ≡ 1 (mod φ(N))`

---

### **What Gets Saved in `values.py`**

When you run `rsa_weak_implementation.py`, it creates:

```python
# values.py
p = [large prime 1]
q = [large prime 2]
N = p * q
phi_n = (p-1) * (q-1)
e = [public exponent]
d = [small private exponent]

# Bit lengths
p_bits = 1023
q_bits = 1023
N_bits = 2046
d_bits = 256
e_bits = 2043

# Vulnerability metrics
prime_gap = abs(p - q)  # Shows how close p and q are
prime_gap_bits = 12     # Usually should be > 512 bits!
```

### Reference RSA Implementation
```bash
cd OnlineSrcCode
python rsa.py
```

Interactive demonstration of "proper" RSA:
- Independent prime generation using `secrets.randbits()`
- Standard key generation workflow
- Encryption/decryption demo
- Still educational-grade (not production-ready)

---

## Code Architecture

### Project/ Directory (Vulnerable RSA + Bob's Attacks)

#### **Weak RSA Implementation** (`rsa_weak_implementation.py`)

This file simulates SecureEncrypCompany's flawed implementation.

**Critical Flaw #1: Related Prime Generation**
```python
def generate_prime_factors_up(value):
    p = value
    while True:
        p += 2
        if is_probably_prime(p):
            return p

def generate_prime_factors_down(value):
    q = value
    while True:
        q -= 2
        if is_probably_prime(q):
            return q
```

**Why it's broken**:
- Both functions start from the **same random value**
- One walks upward (+2), one walks downward (-2)
- Results in p and q being extremely close: `|p-q| ≈ 60`
- For 1024-bit primes, gap should be > 2^(512-100) = 2^412
- Actual gap is only ~6 bits → **Catastrophically weak!**

**Primes ARE verified**: Uses Miller-Rabin test (40 rounds, error probability < 2^-80)
**Prime GENERATION is broken**: Deterministic relationship violates independence requirement

**Critical Flaw #2: Small Private Exponent**
```python
def generate_private_exponent_d(phi_n, attempts=10000):
    for _ in range(attempts):
        d = generate_random_number(256)  # Only 256 bits!
        if d <= 1 or d >= phi_n:
            continue
        if gcd(d, phi_n) == 1:
            return d
```

**Why it's broken**:
- Chooses d as only 256 bits for "fast decryption"
- For 2048-bit RSA, Wiener threshold is ~512 bits
- 256 bits is **exactly half** the minimum safe size
- Enables polynomial-time recovery via continued fractions

**Critical Flaw #3: Non-Standard Public Exponent**
```python
def compute_public_exponent_e(d, phi_n):
    e = pow(d, -1, phi_n)  # e = d^(-1) mod φ(N)
    if e < 0:
        return e + phi_n
    return e
```

**Why it's broken**:
- Standard practice: e = 65537 (fixed, small, prime)
- This implementation: e derived from tiny d → huge e (≈2048 bits)
- Oversized e offers NO security benefit
- Actually signals that d is dangerously small!

---

#### **Attack Suite** (`claude_attacks_implementation.py`)

This is Bob's comprehensive attack toolkit.

---

### **RANDY'S CONTRIBUTIONS**

#### **Attack 1: Fermat Factorization** (`fermat_factorization()`)

**Mathematical Foundation**:
When p ≈ q, we can write N = p·q as a difference of squares:
```
N = p·q = [(p+q)/2]² - [(p-q)/2]²
  = a² - b²
where a = (p+q)/2 and b = (p-q)/2
```

**Algorithm**:
1. Start with a = ⌈√N⌉
2. Compute b² = a² - N
3. Check if b² is a perfect square
4. If yes: p = a-b, q = a+b
5. If no: increment a and repeat

**Complexity**: O(|p-q|) - **linear** in the prime gap!

**Why It Works on SecureEncrypCompany's RSA**:
- |p-q| ≈ 60 means only ~60 iterations needed
- Completes in **milliseconds**
- Compare to general factoring: sub-exponential time (impractical for 2048-bit)

**Key Code Section** (`Project/claude_attacks_implementation.py:22-93`):
```python
a = math.isqrt(N)
if a * a < N:
    a += 1

for iteration in range(max_iterations):
    a_squared = a * a
    b_squared = a_squared - N
    b = math.isqrt(b_squared)

    if b * b == b_squared:
        # Perfect square found!
        p = a - b
        q = a + b
        # Success - factored N
```

**Output**: Displays recovered p, q, number of iterations, time elapsed, and security metrics.

---

#### **Attack 2: Quadratic Sieve** (`quadratic_sieve_simple()`)

**Purpose**: Educational demonstration of general-purpose factoring.

**Default Behavior**: ⚠️ **SKIPPED by default** (see line 1264 in main())

**Why It's Included**:
- Shows understanding of broader factoring techniques
- Not strictly necessary for this weak RSA (Fermat is sufficient)
- Demonstrates the "baby version" of production factoring methods

**Why It's Skipped**:
- Computationally expensive for 2046-bit modulus
- Fermat attack already succeeds instantly (p and q are too close)
- Would slow down demonstration with no practical benefit
- Included in code for Randy's contribution documentation

**How It Works**:
1. Build a factor base: small primes p where N is a quadratic residue mod p
2. Find smooth numbers: values near √N that factor completely over the base
3. Collect relations: (x² ≡ y² mod N) where y is smooth
4. Linear algebra: Find dependencies in exponent vectors over GF(2)
5. Combine relations: X² ≡ Y² (mod N) where X ≠ ±Y
6. Factor: gcd(X-Y, N) yields non-trivial factor

**Limitations**:
- Production QS handles ~100-digit numbers
- For larger composites, use GNFS (General Number Field Sieve)
- Full implementation requires advanced sieving techniques
- Out of scope for this educational project

**Key Code Section** (`Project/claude_attacks_implementation.py:100-318`):
Includes helper functions:
- `_build_factor_base()`: Constructs small primes
- `_is_smooth()`: Checks if number factors over base
- `_collect_relations()`: Finds smooth relations
- `_gaussian_elimination_mod2()`: Solves linear system over GF(2)
- `_square_from_relations()`: Combines relations to factor N

**How to Enable Attack 2**:
If you want to run the Quadratic Sieve (for completeness):
```python
# In main() function (line 1264), change:
result = run_attack_suite(bits=512, d_bits=128, run_quadratic_sieve=False, verbose=True)
# To:
result = run_attack_suite(bits=512, d_bits=128, run_quadratic_sieve=True, verbose=True)
```

**Expected Output When Enabled**:
```
ATTACK 2: QUADRATIC SIEVE (Simplified)
Target N = [large number]
N bit-length: 2046 bits
[!] Educational implementation with clear steps
[!] Production QS still needs advanced sieving / linear algebra

Factor base size: [number] (first primes: [2, 3, 5, ...])
Collected [number] smooth relations
✓ FACTORIZATION SUCCESSFUL! (or timeout/failure for large N)
```

---

### **KE YUAN'S CONTRIBUTIONS**

#### **Attack 3: Wiener's Attack** (`wiener_attack()`)

**The Problem Being Solved**:
RSA requires: e·d ≡ 1 (mod φ(N))
We know e and N, but not d or φ(N). Can we recover d?

**Wiener's Insight (1990)**:
If d is small enough (d < N^0.25), we can use **continued fractions**!

**Mathematical Foundation**:

From e·d ≡ 1 (mod φ(N)), we get:
```
e·d = 1 + k·φ(N)  for some integer k
```

Rearranging:
```
e/N ≈ e/φ(N) ≈ k/d
```

The approximation error is:
```
|e/N - k/d| = |e·d - k·N| / (N·d)
            = |1 + k·φ(N) - k·N| / (N·d)
            = |k·(φ(N) - N) + 1| / (N·d)
```

Since φ(N) = (p-1)(q-1) = N - p - q + 1, we have:
```
|N - φ(N)| = |p + q - 1| < 3√N  (for large primes)
```

Therefore:
```
|e/N - k/d| < 3k / (d·√N)
```

**Wiener's Theorem**:
If d < (1/3)·N^(1/4), then:
```
|e/N - k/d| < 1/(2d²)
```

This means **k/d appears as a convergent** in the continued fraction expansion of e/N!

**Why This Is Powerful**:
- Continued fractions have O(log N) convergents
- Testing each convergent: O(log N) time
- Total: **Polynomial time** recovery of d!
- Compare to factoring N: sub-exponential time

**Vulnerability Thresholds**:
```
1024-bit RSA:  N^(1/4) ≈ 2^256 → threshold ≈ 254 bits
2048-bit RSA:  N^(1/4) ≈ 2^512 → threshold ≈ 510 bits
4096-bit RSA:  N^(1/4) ≈ 2^1024 → threshold ≈ 1022 bits
```

SecureEncrypCompany's 256-bit d on 512-bit modulus:
- Threshold: ~127 bits
- Actual d: 256 bits (for 512-bit N, threshold ≈ 128 bits)
- **VULNERABLE!**

**Continued Fractions Primer**:

A continued fraction represents x/y as:
```
x/y = a₀ + 1/(a₁ + 1/(a₂ + 1/(a₃ + ...)))
    = [a₀; a₁, a₂, a₃, ...]
```

Computed using Euclidean algorithm:
```python
def continued_fraction(x, y):
    cf = []
    while y:
        q = x // y
        cf.append(q)
        x, y = y, x - q*y
    return cf
```

**Convergents** (best rational approximations):
The n-th convergent C_n = h_n/k_n is computed recursively:
```
Base cases:
h_{-1} = 1, k_{-1} = 0
h_0 = a_0, k_0 = 1

Recurrence:
h_n = a_n · h_{n-1} + h_{n-2}
k_n = a_n · k_{n-1} + k_{n-2}
```

**Algorithm Implementation** (`Project/claude_attacks_implementation.py:459-556`):

**Step 1**: Compute continued fraction of e/N
```python
cf = continued_fraction(e, N)
# Returns [a₀, a₁, a₂, ..., a_n]
```

**Step 2**: Generate all convergents
```python
convs = convergents(cf)
# Returns [(h₀, k₀), (h₁, k₁), ..., (h_n, k_n)]
```

**Step 3**: Test each convergent k/d
For each convergent (k, d):
1. Check if k divides (e·d - 1)
2. Compute φ(N) candidate: φ_cand = (e·d - 1) / k
3. Derive p + q: sum_pq = N - φ_cand + 1
4. Solve quadratic: t² - (p+q)·t + N = 0
   - Discriminant: Δ = (p+q)² - 4N = (p-q)²
5. Check if Δ is a perfect square
6. If yes: p = (sum_pq + √Δ)/2, q = (sum_pq - √Δ)/2
7. Verify: p·q = N and e·d ≡ 1 (mod (p-1)(q-1))

**Why Step 3 Works**:
```
φ(N) = (p-1)(q-1) = p·q - p - q + 1 = N - (p+q) + 1
Therefore: p + q = N - φ(N) + 1

Solving quadratic t² - (p+q)t + pq = 0:
t = [(p+q) ± √((p+q)² - 4pq)] / 2
  = [(p+q) ± √(p² + 2pq + q² - 4pq)] / 2
  = [(p+q) ± √(p² - 2pq + q²)] / 2
  = [(p+q) ± √(p-q)²] / 2
  = [(p+q) ± |p-q|] / 2

If p > q:
  t₁ = [(p+q) + (p-q)] / 2 = p
  t₂ = [(p+q) - (p-q)] / 2 = q
```

**Key Code Sections**:

Continued fraction and convergents (`Project/claude_attacks_implementation.py:325-456`):
- Detailed mathematical explanations in docstrings
- Examples showing CF expansion and convergent calculation
- Connection to Euclidean algorithm

Main attack logic (`Project/claude_attacks_implementation.py:459-556`):
- Comprehensive vulnerability threshold analysis
- Step-by-step algorithm execution with progress reporting
- Detailed verification of recovered d
- Security analysis comparing actual vs required d size

**Output Format**:
- Public key parameters (e, N, bit lengths)
- Vulnerability threshold calculation
- Continued fraction expansion (length, first terms)
- Convergent testing progress
- **SUCCESS**: Recovered d, p, q with full verification
- Vulnerability analysis with specific metrics
- Key insights about SecureEncrypCompany's weakness

---

#### **Attack 4: Boneh-Durfee Theory** (`boneh_durfee_theory()`)

**Purpose**: Theoretical analysis showing improvement over Wiener.

**The Advancement**:
```
Wiener (1990):        d < N^0.25  → Continued fractions
Boneh-Durfee (1999):  d < N^0.292 → Lattice reduction
```

This represents a **~17% increase** in the vulnerable range!

**Practical Impact**:
```
For 2048-bit RSA:
  Wiener threshold:       2^512 (512 bits)
  Boneh-Durfee threshold: 2^598 (598 bits)
  Additional coverage:    86 bits (16.8% increase)
```

**Mathematical Foundation**:

Starting from: e·d ≡ 1 (mod φ(N))

We have: e·d = 1 + k·φ(N)

Using φ(N) = N - (p+q) + 1, let s = p+q:
```
e·d = 1 + k(N - s + 1)
k·N - k·s + k - e·d + 1 = 0
```

Rearrange to polynomial form:
```
f(x, y) = x(N + y) + 1 ≡ 0 (mod e)
```
where x = k and y = -(p+q)

Both x and y are "small":
- k < d ≈ N^0.292
- |y| = |p+q| < 3√N

**Coppersmith's Method** (The Core Technique):

Don Coppersmith (1996) showed: We can find small roots of polynomial equations modulo N using **lattice reduction**.

**Intuition**:
1. Construct many polynomials related to f(x,y)
2. Build a lattice where each polynomial = one basis vector
3. Apply LLL (Lenstra-Lenstra-Lovász) algorithm to find short vectors
4. Short vectors → polynomials with small coefficients
5. These polynomials vanish at (k, -(p+q)) over the integers (not just mod e)!
6. Solve the polynomial system to recover k and p+q
7. Factor N using p+q and p·q = N

**Lattice Construction**:

Build lattice from polynomial shifts:
```
For parameters m (dimension) and t (optimization):
  Basis polynomials: x^i · y^j · f(x,y)^k · e^(m-k)
  for various i, j, k satisfying constraints
```

Lattice dimension: approximately m³/6

**Why It Beats Wiener**:

**Wiener's Limitation**:
- Uses only first-order approximation: e/N ≈ k/d
- Limited to single convergent in continued fraction
- Cannot exploit higher-order algebraic structure

**Boneh-Durfee's Advantage**:
- Exploits **bivariate** polynomial relationships
- Lattice encodes multiple algebraic dependencies simultaneously
- LLL finds hidden linear combinations
- Result: Handles larger d (N^0.292 vs N^0.25)

**The Magic Number 0.292**:

β = 1 - 1/√2 ≈ 0.292893...

This comes from optimizing:
- Polynomial degree vs lattice dimension
- Root bounds (Howgrave-Graham theorem)
- LLL reduction quality

**Implementation Requirements**:

**Libraries**:
- SageMath: Full computer algebra system
- fpylll: Fast Python LLL implementation
- NumPy: Matrix operations

**Implementation Steps**:
1. Construct shift-polynomial lattice basis
2. Build coefficient matrix M (dimension ~m³/6)
3. Apply LLL reduction: M_reduced = LLL(M)
4. Extract short vectors from reduced basis
5. Reconstruct polynomials from short vectors
6. Compute resultant or use Gröbner basis to eliminate variables
7. Solve for k and s = p+q
8. Factor N: solve t² - s·t + N = 0

**Computational Complexity**:
```
Time:  O(m^6 · log²N) where m ≈ 5-7
Space: O(m³) for lattice storage

Practical timing:
  1024-bit RSA, d < N^0.292: ~1 hour
  2048-bit RSA, d < N^0.292: ~1 day
```

**When to Use Boneh-Durfee**:

✅ **Use if**:
- N^0.25 < d < N^0.292 (Wiener fails but Boneh-Durfee succeeds)
- Have SageMath or equivalent
- Can afford hours/days of computation

❌ **Don't use if**:
- d < N^0.25 → Use Wiener instead (much faster!)
- d > N^0.292 → Both attacks fail
- No lattice reduction tools

**SecureEncrypCompany's Parameters**:
- Their 256-bit d on 512-bit modulus
- Wiener threshold: ~128 bits
- 256 > 128, but typically for realistic RSA (1024/2048-bit):
  - The implementation uses scaling, Wiener catches it
- **Boneh-Durfee unnecessary** for this critically weak implementation

**Key Code Section** (`Project/claude_attacks_implementation.py:563-822`):

Includes:
- Comprehensive mathematical foundation in docstring
- Comparative analysis table (Wiener vs Boneh-Durfee)
- Threshold comparison for different RSA sizes
- Detailed mathematical derivation (6 steps)
- Implementation requirements and complexity analysis
- Practical considerations and recommendations
- Security recommendations defending against both attacks
- Further reading references

**Output Format**:
- Comparative analysis table
- Threshold calculations for 1024/2048/3072/4096-bit RSA
- Step-by-step mathematical foundation
- Explanation why Boneh-Durfee beats Wiener
- Implementation requirements (libraries, steps, complexity)
- Practical considerations (when to use, when not to use)
- Security recommendations

---

### Supporting Utilities

**Miller-Rabin Primality Test** (`Project/miller_rabin_test.py`):
- Probabilistic primality testing
- 40 rounds by default (error probability < 2^-80)
- Used by SecureEncrypCompany to verify primes
- **Critical**: This WORKS correctly - primes ARE verified!
- **Problem**: Prime GENERATION is flawed, not verification

**GCD Implementation** (`Project/gcd.py`):
- Basic greatest common divisor
- Used to verify gcd(d, φ(N)) = 1

**Fermat Factorization** (`Project/fermat_factorization.py`):
- Standalone version of Fermat attack
- Can be imported for use in other scripts

**Test Verification** (`Project/test_verification.py`):
- Calculates and displays vulnerability metrics
- Shows |p-q| and bit length
- Computes Wiener threshold using integer fourth root
- Verifies e·d ≡ 1 (mod φ(N))

---

### OnlineSrcCode/ Directory (Reference Implementation)

**Clean RSA** (`rsa.py`):
- Proper independent prime generation
- Uses `secrets.randbits()` for cryptographically secure randomness
- Standard key generation flow:
  1. Generate random p and q independently
  2. Compute n = p·q
  3. Compute φ(n) = (p-1)(q-1)
  4. Select e coprime with φ(n) (or use 65537)
  5. Compute d = e^(-1) mod φ(n)
- Modular exponentiation with binary method
- Interactive encryption/decryption demo

**Miller-Rabin** (`miller_rabin.py`):
- Standard Miller-Rabin implementation
- Multiple witness testing

**EGCD** (`egcd.py`):
- Extended Euclidean Algorithm
- Computes modular multiplicative inverse
- Critical for deriving d from e

---

## Key Mathematical Concepts

### Fermat Factorization Vulnerability

**The Math**:
```
If p ≈ q, then N = p·q can be written as:
  N = [(p+q)/2]² - [(p-q)/2]²
    = a² - b²
    = (a-b)(a+q)

where:
  a = (p+q)/2
  b = (p-q)/2
```

**The Algorithm**:
```
Start with a = ⌈√N⌉
Increment a until a² - N is a perfect square
When found: p = a-b, q = a+b
```

**Complexity**: O(|p-q|/2)

**Why SecureEncrypCompany is Vulnerable**:
- |p-q| ≈ 60 → only ~30 iterations
- For secure RSA: |p-q| > 2^(n/2 - 100)
- For 1024-bit: |p-q| should be > 2^412 (124-digit number)
- Actual: |p-q| ≈ 60 (2-digit number)
- **Reduction factor: 2^410** → Catastrophic!

---

### Wiener Attack Threshold

**The Core Inequality**:

For Wiener to work:
```
d < (1/3) · N^(1/4)
```

**Why This Bound**:

From the approximation |e/N - k/d| < 3k/(d·√N):

If d < N^(1/4), then:
```
|e/N - k/d| < 3k/(d·√N)
            < 3·d/(d·N^(1/4))  [since k < d]
            < 3/N^(1/4)
```

For N^(1/4) large enough:
```
3/N^(1/4) < 1/(2d²)
```

This is the condition for k/d to appear as a convergent!

**Bit-Level Analysis**:
```
For n-bit RSA (N ≈ 2^n):
  N^(1/4) ≈ 2^(n/4)
  Threshold ≈ 2^(n/4 - 2)

Examples:
  1024-bit: 2^(256-2) = 2^254 ≈ 254 bits
  2048-bit: 2^(512-2) = 2^510 ≈ 510 bits
  4096-bit: 2^(1024-2) = 2^1022 ≈ 1022 bits
```

**SecureEncrypCompany's Failure**:
```
For 512-bit modulus:
  Threshold: 2^(128-2) ≈ 126 bits
  Their d: 256 bits
  Ratio: 256/126 ≈ 2.03

For realistic 2048-bit:
  Threshold: ~510 bits
  Their approach (proportional): 256 bits (if scaled)
  Vulnerable: 256 << 510
```

---

### Prime Generation Flaw

**Secure Method** (OnlineSrcCode):
```python
def generate_large_prime(bits=1024):
    for _ in range(attempts):
        candidate = secrets.randbits(bits)
        if is_probably_prime(candidate):
            return candidate
```

**Each prime**: Independent random number → tested for primality

**Vulnerable Method** (SecureEncrypCompany):
```python
value = generate_large_prime(bits=1024)  # Shared starting point!
p = generate_prime_factors_up(value)     # Walk upward
q = generate_prime_factors_down(value)   # Walk downward
```

**Result**: p and q start from same value → always close

**Mathematical Impact**:
```
Prime Number Theorem: Probability a random n-bit number is prime ≈ 1/ln(2^n)

For 1024-bit numbers: ≈ 1/710

Expected number of steps to find prime: ~710

Starting from same point and walking ±2:
  Average gap: ~710 · 2 = 1420
  Actual observed: ~60 (10× better luck... but 10^120× worse security!)
```

---

## Project Context

### Learning Objectives

This demonstration teaches:
1. **Fast ≠ Secure**: Performance optimizations can introduce fatal vulnerabilities
2. **Parameter Independence**: p and q must be independently random
3. **Proper Size Requirements**: d must be large (≈φ(N)), not small
4. **Verification ≠ Generation**: Primes can be verified (Miller-Rabin) yet generated insecurely
5. **Kerckhoff's Principle**: Security must not depend on hiding algorithms

### The "Verified Primes" Paradox

**Critical Insight**:
- ✅ Miller-Rabin test **works perfectly**: p and q ARE prime
- ❌ Prime **generation** is broken: p and q are RELATED

**Analogy**:
- Like choosing two random people to share a secret
- Verification: Confirms both are reliable people ✓
- Generation: But you chose identical twins! ✗

**The Lesson**:
```
Cryptographic correctness = Algorithm correctness + Parameter generation
                          = Verified primes + Independent selection
```

SecureEncrypCompany had: ✅ + ❌ = ❌ (Overall failure)

---

## Key Takeaways (Bob's Presentation)

### Critical Insights

1. **Fast ≠ Secure**:
   - "Lightning-fast primes" → Deterministic relationship
   - "Blazing decryption" → Dangerously small d
   - Speed optimizations introduced catastrophic weaknesses

2. **Primes ARE Verified**:
   - Miller-Rabin test is correct
   - 40 rounds gives error probability < 2^-80
   - **NOT THE PROBLEM**

3. **Prime GENERATION is Broken**:
   - Incremental ±2 search from shared seed
   - Creates close primes (|p-q| ≈ 60 instead of > 2^412)
   - Enables Fermat factorization in milliseconds

4. **Proper Parameter Generation is Essential**:
   - Independence: p and q must be separately random
   - Size: d must be ≈φ(N), not optimized for speed
   - Standards: Use e = 65537, not derived from d

### Secure RSA Checklist

✅ **Prime Independence**:
- p and q must be randomly and independently generated
- Minimum gap: `|p-q| > 2^(n/2 - 100)`
- Use `secrets.randbits()` or equivalent CSPRNG

✅ **Cryptographic RNG**:
- Never use: predictable seeds, shared starting points, deterministic patterns
- Always use: `secrets` module (Python), `/dev/urandom` (Linux), CryptGenRandom (Windows)

✅ **Standard Public Exponent**:
- Use e = 65537 (industry standard)
- Small, prime, Hamming weight 2 (efficient)
- Never derive e from d

✅ **Large Private Exponent** ← **Ke Yuan's Focus Area**:
- Minimum: `d ≥ N^(1/4)` (Wiener threshold)
- Better: `d ≥ N^0.292` (Boneh-Durfee threshold)
- Best: `d ≈ φ(N)` (standard RSA)
- For 2048-bit RSA: d should be ~2048 bits, not 256!

✅ **Additional Security** (beyond scope):
- Padding: Use OAEP (Optimal Asymmetric Encryption Padding)
- Constant-time: Prevent timing attacks
- Side-channel resistance: Protect against power analysis

---

## Attack Summary Table

| Attack | Target Flaw | Complexity | Threshold | Randy/Ke Yuan | Status in Output |
|--------|-------------|------------|-----------|---------------|------------------|
| Attack 1: Fermat Factorization | Close primes | O(\|p-q\|) | \|p-q\| small | Randy | ✅ **Runs** |
| Attack 2: Quadratic Sieve | General factoring | Sub-exponential | N/A (educational) | Randy | ⏭️ **Skipped** |
| Attack 3: Wiener Attack | Small d | O(log N) | d < N^0.25 | Ke Yuan | ✅ **Runs** |
| Attack 4: Boneh-Durfee | Small d (improved) | O(m^6 log²N) | d < N^0.292 | Ke Yuan | ✅ **Runs** (Theory)

**What You'll See in Terminal Output**:
1. ✅ **Attack 1**: Fermat factorization recovers p, q in ~1 iteration
2. ⏭️ **Attack 2**: Note in summary says "Quadratic sieve skipped"
3. ✅ **Attack 3**: Wiener attack recovers d with full mathematical breakdown
4. ✅ **Attack 4**: Boneh-Durfee theoretical analysis with comparative tables

---

## References & Further Reading

### Papers

**Wiener's Attack**:
- M. Wiener, "Cryptanalysis of Short RSA Secret Exponents"
  IEEE Transactions on Information Theory, vol. 36, no. 3, 1990

**Boneh-Durfee Attack**:
- D. Boneh and G. Durfee, "Cryptanalysis of RSA with Private Key d Less Than N^0.292"
  EUROCRYPT 1999

**Coppersmith's Method**:
- D. Coppersmith, "Finding Small Roots of Univariate Modular Equations Revisited"
  EUROCRYPT 1996

**Foundational**:
- R. L. Rivest, A. Shamir, and L. Adleman, "A Method for Obtaining Digital Signatures and Public-Key Cryptosystems"
  Communications of the ACM, vol. 21, no. 2, 1978

**General RSA Attacks**:
- Dan Boneh, "Twenty Years of Attacks on the RSA Cryptosystem"
  Notices of the American Mathematical Society, 1999

### Course Material
- SC4010 Applied Cryptography lecture notes (Weeks 8–9)
- Continued fractions and convergents (Week 9)
- RSA parameter selection best practices

---

## Development Notes

### Code Organization
- All Python scripts are standalone (no package manager needed)
- Attack scripts include extensive console output for educational presentation
- `ResultsTemplate.md` provides structure for documenting attack results

### Testing
- Run `python Project/claude_attacks_implementation.py` for full demo
- Run `python Project/test_verification.py` for metrics
- Compare with `python OnlineSrcCode/rsa.py` for proper implementation

### Important Reminders
- ⚠️ **No production use**: Intentionally vulnerable for academic study
- 📚 **Educational purpose**: Demonstrates why certain choices break RSA
- 🔬 **Own work**: Attack implementations are original, be ready to explain live
- 📊 **Document everything**: Save outputs for appendix/evidence

---

## Quick Reference for Future Claude Instances

**When asked about Wiener attack**:
- Location: `Project/claude_attacks_implementation.py:459-556`
- Key functions: `continued_fraction()`, `convergents()`, `wiener_attack()`
- Theory: Uses CF expansion of e/N to find k/d convergent
- Threshold: d < (1/3)·N^(1/4)

**When asked about Boneh-Durfee**:
- Location: `Project/claude_attacks_implementation.py:563-822`
- Type: Theoretical analysis (no full implementation)
- Improvement: d < N^0.292 vs Wiener's d < N^0.25
- Technique: Lattice reduction (LLL) + Coppersmith's method

**When asked about close primes**:
- Location: `Project/rsa_weak_implementation.py:29-41`
- Functions: `generate_prime_factors_up()`, `generate_prime_factors_down()`
- Flaw: Both start from same value, walk ±2
- Attack: `Project/claude_attacks_implementation.py:22-93` (Fermat)

**When asked about secure RSA**:
- Reference: `OnlineSrcCode/rsa.py`
- Key difference: Independent prime generation
- Still educational: Not production-ready (no padding, timing attacks, etc.)

**When asked about running attacks**:
```bash
# Option 1: With saved parameters (reproducible)
python Project/rsa_weak_implementation.py        # Generate & save to values.py
python Project/claude_attacks_implementation.py  # Automatically uses values.py

# Option 2: Quick demo (fresh parameters)
python Project/claude_attacks_implementation.py  # Auto-generates if no values.py

# Verification only
python Project/test_verification.py              # Metrics only

# Reference implementation
python OnlineSrcCode/rsa.py                      # Clean RSA demo
```
