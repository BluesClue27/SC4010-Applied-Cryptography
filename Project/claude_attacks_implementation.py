"""
RSA Security Analysis Suite
Demonstrating vulnerabilities in SecureEncrypCompany's implementation

Author: Bob (SC4010 Applied Cryptography Alumni)
Purpose: Prove insecurity of improper RSA parameter choices
"""

import math
import time
import random
import io
from dataclasses import dataclass, field
from contextlib import nullcontext, redirect_stdout
from typing import Tuple, Optional, List


# ============================================================================
# ATTACK 1: FERMAT FACTORIZATION (for close primes)
# ============================================================================

def fermat_factorization(N: int, max_iterations: int = 10**7) -> Optional[Tuple[int, int]]:
    """
    Fermat's Factorization Attack - exploits p ≈ q
    
    Theory: If N = p*q where p ≈ q, then N ≈ p² 
    We can write: N = a² - b² = (a-b)(a+b) where a = (p+q)/2, b = (p-q)/2
    
    Algorithm:
    1. Start with a = ⌈√N⌉
    2. Compute b² = a² - N
    3. Check if b² is a perfect square
    4. If yes: p = a-b, q = a+b
    5. If no: increment a and repeat
    
    Complexity: O(|p-q|) - LINEAR in the difference!
    Critical flaw: If |p-q| is small, attack is trivial
    """
    print(f"\n{'='*70}")
    print("ATTACK 1: FERMAT FACTORIZATION")
    print(f"{'='*70}")
    print(f"Target N = {N}")
    print(f"N bit-length: {N.bit_length()} bits")
    
    start_time = time.time()
    
    # Starting point: ceiling of √N
    a = math.isqrt(N)
    if a * a < N:
        a += 1
    
    print(f"Starting search from a = ⌈√N⌉ = {a}\n")
    
    for iteration in range(max_iterations):
        a_squared = a * a
        b_squared = a_squared - N
        
        # Check if b_squared is a perfect square
        b = math.isqrt(b_squared)
        
        if b * b == b_squared:
            # Success!
            p = a - b
            q = a + b
            elapsed = time.time() - start_time
            
            print(f"✓ FACTORIZATION SUCCESSFUL!")
            print(f"  Iterations: {iteration + 1:,}")
            print(f"  Time: {elapsed:.6f} seconds")
            print(f"\n  p = {p}")
            print(f"  q = {q}")
            print(f"  Verify: p × q = N? {p * q == N}")
            
            # Security analysis
            diff = abs(p - q)
            print(f"\n  Security Metrics:")
            print(f"    |p - q| = {diff:,}")
            print(f"    |p - q| bits = {diff.bit_length()}")
            
            n_bits = N.bit_length()
            required_min = n_bits // 2 - 100
            print(f"    Required: |p-q| > 2^{required_min} ≈ {2**required_min:.2e}")
            print(f"    VULNERABLE: {diff < 2**required_min}")
            
            return p, q
        
        a += 1
        
        if iteration > 0 and iteration % 100000 == 0:
            print(f"  ... iteration {iteration:,}")
    
    print(f"\n✗ Failed after {max_iterations:,} iterations")
    return None, None


# ============================================================================
# ATTACK 2: QUADRATIC SIEVE (general purpose factoring)
# ============================================================================

@dataclass
class Relation:
    """Book-keeping for a single smooth value x² − N."""
    x: int
    value: int
    factors: List[Tuple[int, int]]
    parity: List[int]


def _sieve_primes(limit: int) -> List[int]:
    """Return all primes ≤ limit (simple Eratosthenes)."""
    sieve = [True] * (limit + 1)
    sieve[0] = sieve[1] = False
    for i in range(2, int(limit ** 0.5) + 1):
        if sieve[i]:
            step = i
            start = i * i
            sieve[start:limit + 1:step] = [False] * ((limit - start) // step + 1)
    return [i for i, is_prime in enumerate(sieve) if is_prime]


def _build_factor_base(N: int, base_size: int, prime_bound: int) -> List[int]:
    """
    Build a factor base: primes p such that (N | p) = 1 (quadratic residue).
    We over-sieve up to prime_bound and keep the first base_size hits.
    """
    factor_base: List[int] = []
    for p in _sieve_primes(prime_bound):
        if pow(N, (p - 1) // 2, p) == 1:
            factor_base.append(p)
            if len(factor_base) == base_size:
                break
    return factor_base


def _trial_division(value: int, factor_base: List[int]) -> Optional[List[Tuple[int, int]]]:
    """Factor |value| over the factor base; return exponents or None."""
    remaining = abs(value)
    factors: List[Tuple[int, int]] = []
    for p in factor_base:
        if p * p > remaining:
            break
        exp = 0
        while remaining % p == 0:
            remaining //= p
            exp += 1
        if exp:
            factors.append((p, exp))
    # If remainder > 1 it must itself be in the base (since base not complete)
    if remaining != 1:
        if remaining in factor_base:
            factors.append((remaining, 1))
            remaining = 1
        else:
            return None
    return factors if remaining == 1 else None


def _parity_vector(factors: List[Tuple[int, int]], factor_base: List[int]) -> List[int]:
    """Parity (mod 2) of exponents aligned with factor_base order."""
    parity = [0] * len(factor_base)
    index = {p: idx for idx, p in enumerate(factor_base)}
    for prime, exp in factors:
        parity[index[prime]] ^= exp & 1
    return parity


def _collect_relations(
    N: int,
    factor_base: List[int],
    sieve_span: int,
    relation_target: int,
) -> List[Relation]:
    """
    Gather smooth values x² − N for x in [⌈√N⌉, ⌈√N⌉ + sieve_span).
    This uses straightforward trial division for clarity.
    """
    relations: List[Relation] = []
    start_x = math.isqrt(N)
    if start_x * start_x < N:
        start_x += 1

    for x in range(start_x, start_x + sieve_span):
        value = x * x - N
        if value <= 0:
            continue
        factors = _trial_division(value, factor_base)
        if factors is None:
            continue
        parity = _parity_vector(factors, factor_base)
        relations.append(Relation(x=x, value=value, factors=factors, parity=parity))
        if len(relations) >= relation_target:
            break
    return relations


def _gaussian_elimination_mod2(relations: List[Relation]) -> List[List[int]]:
    """
    Perform Gaussian elimination over GF(2) to find a dependency.
    We augment the matrix with an identity matrix to keep track of the
    combination of original rows that produces the zero vector.
    """
    if not relations:
        return []

    m = len(relations[0].parity)
    n = len(relations)

    # Build augmented matrix [parity | identity]
    matrix = [
        relations[i].parity[:] + [1 if i == j else 0 for j in range(n)]
        for i in range(n)
    ]

    row = 0
    for col in range(m):
        pivot = None
        for r in range(row, n):
            if matrix[r][col]:
                pivot = r
                break
        if pivot is None:
            continue
        matrix[row], matrix[pivot] = matrix[pivot], matrix[row]
        for r in range(n):
            if r != row and matrix[r][col]:
                matrix[r] = [
                    (matrix[r][c] ^ matrix[row][c]) for c in range(m + n)
                ]
        row += 1

    dependencies: List[List[int]] = []
    for r in range(n):
        if all(v == 0 for v in matrix[r][:m]):
            combo = matrix[r][m:]
            indices = [idx for idx, bit in enumerate(combo) if bit]
            if indices:
                dependencies.append(indices)
    return dependencies


def _square_from_relations(N: int, relations: List[Relation], indices: List[int]) -> Tuple[int, int]:
    """Combine chosen relations into X² ≡ Y² (mod N)."""
    exponent_totals = {}
    X = 1
    for idx in indices:
        relation = relations[idx]
        X = (X * relation.x) % N
        for prime, exp in relation.factors:
            exponent_totals[prime] = exponent_totals.get(prime, 0) + exp

    Y = 1
    for prime, exp in exponent_totals.items():
        Y = (Y * pow(prime, exp // 2, N)) % N
    return X, Y


def quadratic_sieve_simple(
    N: int,
    factor_base_size: int = 100,
    sieve_span: int = 20000,
    prime_bound: int = 200000,
) -> Optional[Tuple[int, int]]:
    """
    Quadratic Sieve (structured teaching version)

    This refactored variant mirrors the real QS flow while keeping the maths
    gentle: we build a factor base, collect smooth relations, solve for a
    linear dependency over GF(2), and combine the relations into an RSA break.
    """
    print(f"\n{'='*70}")
    print("ATTACK 2: QUADRATIC SIEVE (Simplified)")
    print(f"{'='*70}")
    print(f"Target N = {N}")
    print(f"N bit-length: {N.bit_length()} bits")
    print("\n[!] Educational implementation with clear steps")
    print("[!] Production QS still needs advanced sieving / linear algebra\n")

    start_time = time.time()

    factor_base = _build_factor_base(N, factor_base_size, prime_bound)
    if len(factor_base) < factor_base_size:
        print("✗ Could not assemble requested factor base size – enlarge prime_bound.")
        return None, None

    print(f"Factor base size: {len(factor_base)} (first primes: {factor_base[:10]})")

    # Need slightly more relations than base size for a kernel vector
    relation_target = factor_base_size + 15
    relations = _collect_relations(N, factor_base, sieve_span, relation_target)
    print(f"Collected {len(relations)} smooth relations")

    if len(relations) <= factor_base_size:
        print("\n✗ Insufficient smooth relations – raise sieve_span or base size.")
        return None, None

    dependencies = _gaussian_elimination_mod2(relations)
    if not dependencies:
        print("\n✗ Failed to find a linear dependency – collect more relations.")
        return None, None

    for dependency in dependencies:
        X, Y = _square_from_relations(N, relations, dependency)
        factor = math.gcd(X - Y, N)
        if factor in (1, N):
            factor = math.gcd(X + Y, N)

        if 1 < factor < N:
            other = N // factor
            elapsed = time.time() - start_time
            print(f"\n✓ FACTORIZATION SUCCESSFUL!")
            print(f"  Time: {elapsed:.6f} seconds")
            print(f"\n  p = {min(factor, other)}")
            print(f"  q = {max(factor, other)}")
            print(f"  Verify: p × q = N? {factor * other == N}")
            return min(factor, other), max(factor, other)

    print("\n✗ Dependencies led to trivial factors – collect more relations and retry.")
    return None, None


# ============================================================================
# ATTACK 3: WIENER'S ATTACK (for small d)
# ============================================================================

def continued_fraction(numerator: int, denominator: int) -> List[int]:
    """
    Compute continued fraction expansion of numerator/denominator
    
    A continued fraction represents a rational number as:
    a₀ + 1/(a₁ + 1/(a₂ + 1/(a₃ + ...)))
    
    Returns: [a₀, a₁, a₂, ...]
    """
    cf = []
    while denominator:
        q = numerator // denominator
        cf.append(q)
        numerator, denominator = denominator, numerator - q * denominator
    return cf


def convergents(cf: List[int]) -> List[Tuple[int, int]]:
    """
    Compute convergents (best rational approximations) from continued fraction
    
    Convergents are the "best" rational approximations at each step
    """
    convs = []
    h_prev2, h_prev1 = 0, 1
    k_prev2, k_prev1 = 1, 0
    
    for a in cf:
        h = a * h_prev1 + h_prev2
        k = a * k_prev1 + k_prev2
        convs.append((h, k))
        h_prev2, h_prev1 = h_prev1, h
        k_prev2, k_prev1 = k_prev1, k
    
    return convs


def wiener_attack(e: int, N: int) -> Optional[int]:
    """
    Wiener's Attack - exploits small private exponent d
    
    Theory: If d < (1/3) * N^(1/4), then d can be recovered from e/N using
    continued fractions. The attack works because k/d (where ed = 1 + kφ(N))
    is a convergent of e/N.
    
    Algorithm:
    1. Compute continued fraction expansion of e/N
    2. For each convergent k/d:
       a. Check if d is valid by testing if ed ≡ 1 (mod φ(N))
       b. Use candidate d to derive φ(N) = (ed - 1)/k
       c. Solve for p, q using φ(N) = (p-1)(q-1)
    
    Vulnerability threshold: d < (1/3) * N^0.25
    Boneh-Durfee extends to: d < N^0.292
    
    Complexity: O(log N) - polynomial time!
    """
    print(f"\n{'='*70}")
    print("ATTACK 3: WIENER'S ATTACK")
    print(f"{'='*70}")
    print(f"Public key (e, N):")
    print(f"  e = {e}")
    print(f"  N = {N}")
    print(f"  N bit-length: {N.bit_length()} bits")
    
    # Check if attack is theoretically applicable
    threshold = int((1/3) * (N ** 0.25))
    print(f"\nWiener threshold: d < (1/3) × N^(1/4) ≈ {threshold}")
    print(f"                       ≈ 2^{threshold.bit_length()} ({threshold.bit_length()} bits)")
    
    start_time = time.time()
    
    # Step 1: Compute continued fraction of e/N
    print("\nComputing continued fraction expansion of e/N...")
    cf = continued_fraction(e, N)
    print(f"CF length: {len(cf)}")
    
    # Step 2: Test each convergent
    print("\nTesting convergents k/d...")
    convs = convergents(cf)
    
    for i, (k, d) in enumerate(convs):
        if k == 0:
            continue
        
        # Candidate for φ(N)
        phi_candidate = (e * d - 1) // k
        
        # Solve: N = pq, φ(N) = (p-1)(q-1) = pq - p - q + 1
        # Therefore: p + q = N - φ(N) + 1
        sum_pq = N - phi_candidate + 1
        
        # Solve quadratic: x² - (sum_pq)x + N = 0
        discriminant = sum_pq * sum_pq - 4 * N
        
        if discriminant >= 0:
            sqrt_disc = math.isqrt(discriminant)
            
            if sqrt_disc * sqrt_disc == discriminant:
                # Perfect square! We found p and q
                p = (sum_pq + sqrt_disc) // 2
                q = (sum_pq - sqrt_disc) // 2
                
                if p * q == N:
                    elapsed = time.time() - start_time
                    
                    print(f"\n✓ PRIVATE KEY RECOVERED!")
                    print(f"  Convergent index: {i}")
                    print(f"  Time: {elapsed:.6f} seconds")
                    print(f"\n  Private exponent d = {d}")
                    print(f"  d bit-length: {d.bit_length()} bits")
                    print(f"\n  Factors:")
                    print(f"    p = {p}")
                    print(f"    q = {q}")
                    print(f"  Verify: p × q = N? {p * q == N}")
                    
                    # Verify d
                    phi_n = (p - 1) * (q - 1)
                    print(f"\n  Verification:")
                    print(f"    φ(N) = {phi_n}")
                    print(f"    e × d mod φ(N) = {(e * d) % phi_n}")
                    print(f"    Valid? {(e * d) % phi_n == 1}")
                    
                    print(f"\n  Security Analysis:")
                    print(f"    d < threshold? {d < threshold} (VULNERABLE)")
                    print(f"    d / N^0.25 = {d / (N ** 0.25):.6f} (should be >> 1)")
                    
                    return d
        
        if i % 10 == 0 and i > 0:
            print(f"  ... tested {i} convergents")
    
    elapsed = time.time() - start_time
    print(f"\n✗ Attack failed (time: {elapsed:.6f}s)")
    print("   Possible reasons:")
    print("   - d is too large (d ≥ N^0.25)")
    print("   - Different attack needed (try Boneh-Durfee)")
    return None


# ============================================================================
# ATTACK 4: BONEH-DURFEE ATTACK (theoretical improvement)
# ============================================================================

def boneh_durfee_theory():
    """
    Boneh-Durfee Attack - Theoretical Overview
    
    This is a THEORETICAL explanation since full implementation requires
    lattice reduction (LLL algorithm) and is computationally intensive.
    
    Improvement over Wiener:
    - Wiener: works for d < N^0.25
    - Boneh-Durfee: works for d < N^0.292
    
    Theory:
    The attack uses lattice-based techniques (Coppersmith's method) to solve
    the modular polynomial equation: ed ≡ 1 (mod φ(N))
    
    Key insight: Transform the problem into finding small solutions to a
    bivariate polynomial modulo e, then use LLL lattice reduction.
    
    For implementation, one would:
    1. Construct a lattice from the polynomial coefficients
    2. Use LLL algorithm to find short vectors
    3. Extract small roots that correspond to factorization
    
    Libraries needed: SageMath, fpylll, or similar
    """
    print(f"\n{'='*70}")
    print("ATTACK 4: BONEH-DURFEE ATTACK (Theoretical)")
    print(f"{'='*70}")
    print("\n📚 THEORETICAL OVERVIEW")
    print("\nBoneh-Durfee extends Wiener's attack from d < N^0.25 to d < N^0.292")
    print("\nKey Differences from Wiener:")
    print("  • Wiener: Continued fractions (elementary number theory)")
    print("  • Boneh-Durfee: Lattice reduction (advanced algebraic techniques)")
    print("\nAlgorithm Outline:")
    print("  1. Start with: ed ≡ 1 (mod φ(N)) where φ(N) ≈ N")
    print("  2. Rewrite as: ed - 1 = kφ(N) for some integer k")
    print("  3. Since φ(N) = N - p - q + 1, substitute and rearrange")
    print("  4. Construct bivariate polynomial f(x,y) = x(N + y) + 1")
    print("     where x = k, y = -(p+q)")
    print("  5. Build lattice from polynomial coefficients")
    print("  6. Apply LLL to find short vectors")
    print("  7. Extract small roots → recover p, q")
    
    print("\n🔧 Implementation Requirements:")
    print("  • LLL lattice reduction algorithm")
    print("  • Coppersmith's method for finding small roots")
    print("  • Libraries: SageMath, fpylll, or custom implementation")
    
    print("\n📊 Complexity:")
    print("  • Time: O(e² log² e) - polynomial in log(N)")
    print("  • Space: Requires storing and reducing large lattices")
    
    print("\n⚠️  Practical Notes:")
    print("  • More complex than Wiener, but handles larger d")
    print("  • For d > N^0.292, even Boneh-Durfee fails")
    print("  • Production tools: SageMath scripts widely available")
    
    print("\n💡 For Bob's presentation:")
    print("  • Focus on Wiener for practical demonstration")
    print("  • Mention Boneh-Durfee as theoretical extension")
    print("  • Emphasize: d should be close to φ(N) ≈ N for security")
    
    print("\n📖 Reference:")
    print("  D. Boneh and G. Durfee, 'Cryptanalysis of RSA with private")
    print("  key d less than N^0.292', EUROCRYPT 1999")


# ============================================================================
# SUPPORTING DATA STRUCTURES & HELPERS
# ============================================================================

@dataclass
class RSAParameters:
    """Container for vulnerable RSA parameters."""
    N: int
    e: int
    d: int
    p: int
    q: int
    phi_n: int
    bits: int

    @property
    def modulus_bits(self) -> int:
        return self.N.bit_length()

    @property
    def d_bits(self) -> int:
        return self.d.bit_length()

    @property
    def e_bits(self) -> int:
        return self.e.bit_length()

    @property
    def gap(self) -> int:
        return abs(self.p - self.q)

    @property
    def gap_bits(self) -> int:
        gap_value = self.gap
        return gap_value.bit_length() if gap_value else 0


@dataclass
class AttackSuiteResult:
    """Structured record of attack outcomes."""
    rsa: RSAParameters
    fermat_factors: Optional[Tuple[int, int]]
    quadratic_factors: Optional[Tuple[int, int]]
    wiener_d: Optional[int]
    wiener_threshold: int
    notes: List[str] = field(default_factory=list)

    @property
    def fermat_success(self) -> bool:
        return self.fermat_factors is not None and all(self.fermat_factors)

    @property
    def quadratic_success(self) -> bool:
        return self.quadratic_factors is not None and all(self.quadratic_factors)

    @property
    def wiener_success(self) -> bool:
        return self.wiener_d is not None

    @property
    def wiener_threshold_bits(self) -> int:
        return self.wiener_threshold.bit_length() if self.wiener_threshold else 0

    def summary_lines(self) -> List[str]:
        """Return human-readable summary lines for reporting."""
        lines = [
            f"Modulus bits: {self.rsa.modulus_bits}",
            f"|p - q| = {self.rsa.gap} (bits: {self.rsa.gap_bits})",
            f"Private exponent bits: {self.rsa.d_bits}",
            f"Public exponent bits: {self.rsa.e_bits}",
            f"Wiener threshold (n^(1/4)/3): {self.wiener_threshold} (bits: {self.wiener_threshold_bits})",
            f"Fermat factorization success: {self.fermat_success}",
            f"Wiener attack success: {self.wiener_success}",
            f"Quadratic sieve success: {self.quadratic_success}",
        ]
        if self.wiener_success and self.wiener_d is not None:
            lines.append(f"Recovered d: {self.wiener_d}")
        for note in self.notes:
            lines.append(f"Note: {note}")
        return lines


def integer_fourth_root(n: int) -> int:
    """Integer fourth root using Newton iteration (avoids float overflow)."""
    if n == 0:
        return 0
    x = 1 << ((n.bit_length() + 3) // 4)
    while True:
        x_cubed = x ** 3
        x_new = (3 * x + n // x_cubed) // 4
        if x_new >= x:
            return x
        x = x_new


def _stdout_context(verbose: bool):
    """Utility context manager to silence prints when verbose is False."""
    return nullcontext() if verbose else redirect_stdout(io.StringIO())


def run_attack_suite(
    bits: int = 512,
    d_bits: int = 128,
    run_quadratic_sieve: bool = False,
    verbose: bool = True,
) -> AttackSuiteResult:
    """
    Execute the full vulnerable RSA generation and attack sequence.

    Args:
        bits: Target modulus bit length for the vulnerable RSA instance.
        d_bits: Bit length for the intentionally small private exponent.
        run_quadratic_sieve: Whether to run the quadratic sieve demonstration.
        verbose: If False, suppress console output from the underlying routines.

    Returns:
        AttackSuiteResult summarising recovered data and key metrics.
    """
    with _stdout_context(verbose):
        rsa_dict = generate_vulnerable_rsa(bits=bits, d_bits=d_bits)
        rsa = RSAParameters(**rsa_dict)

        fermat_factors = fermat_factorization(rsa.N)
        quadratic_factors = None
        if run_quadratic_sieve:
            quadratic_factors = quadratic_sieve_simple(rsa.N)
        wiener_d = wiener_attack(rsa.e, rsa.N)

    threshold = integer_fourth_root(rsa.N) // 3

    notes: List[str] = []
    if rsa.gap_bits < max(0, rsa.modulus_bits // 2 - 100):
        notes.append("Gap between p and q violates recommended lower bound.")
    if wiener_d is not None:
        notes.append("Wiener attack successfully recovered the private exponent.")
    if not run_quadratic_sieve:
        notes.append("Quadratic sieve skipped (set run_quadratic_sieve=True to execute).")

    return AttackSuiteResult(
        rsa=rsa,
        fermat_factors=fermat_factors,
        quadratic_factors=quadratic_factors,
        wiener_d=wiener_d,
        wiener_threshold=threshold,
        notes=notes,
    )


# ============================================================================
# DEMONSTRATION & TESTING
# ============================================================================

def generate_vulnerable_rsa(bits: int = 512, d_bits: int = 256) -> dict:
    """
    Simulate SecureEncrypCompany's VULNERABLE RSA generation
    """
    print(f"\n{'#'*70}")
    print("SIMULATING SecureEncrypCompany's VULNERABLE RSA Generation")
    print(f"{'#'*70}")
    
    # Generate close primes (VULNERABLE!)
    print(f"\n1. Generating 'close' primes (VULNERABLE METHOD)...")
    base = random.getrandbits(bits // 2)
    base |= (1 << (bits // 2 - 1)) | 1  # Ensure high bit and odd
    
    # Find next primes (incrementally - BAD!)
    p = base
    while not is_prime_mr(p):
        p += 2
    
    q = p + random.randint(2, 1000) * 2  # Close to p!
    while not is_prime_mr(q):
        q += 2
    
    N = p * q
    phi_n = (p - 1) * (q - 1)
    
    print(f"   p bit-length: {p.bit_length()}")
    print(f"   q bit-length: {q.bit_length()}")
    print(f"   |p - q| = {abs(p - q):,}")
    print(f"   |p - q| bits = {abs(p - q).bit_length()} (DANGEROUSLY SMALL!)")
    
    # Generate small d (VULNERABLE!)
    print(f"\n2. Generating SMALL private exponent d (VULNERABLE METHOD)...")
    d = random.getrandbits(d_bits) | 1  # Odd
    while math.gcd(d, phi_n) != 1:
        d = random.getrandbits(d_bits) | 1
    
    # Compute large e
    e = pow(d, -1, phi_n)
    
    print(f"   d bit-length: {d.bit_length()} bits (DANGEROUSLY SMALL!)")
    print(f"   e bit-length: {e.bit_length()} bits (Artificially large)")
    print(f"   Recommended: d ≈ φ(N) ≈ {phi_n.bit_length()} bits")
    
    return {
        'N': N,
        'e': e,
        'd': d,
        'p': p,
        'q': q,
        'phi_n': phi_n,
        'bits': bits
    }


def is_prime_mr(n: int, k: int = 40) -> bool:
    """Miller-Rabin primality test (used by SecureEncrypCompany)"""
    if n < 2: return False
    if n == 2 or n == 3: return True
    if n % 2 == 0: return False
    
    # Write n-1 as 2^r × d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    # Witness loop
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        
        if x == 1 or x == n - 1:
            continue
        
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    
    return True


def main():
    """
    Bob's Complete Security Demonstration
    """
    print("\n" + "="*70)
    print(" "*15 + "BOB'S RSA SECURITY ANALYSIS")
    print(" "*10 + "Exposing SecureEncrypCompany's Vulnerabilities")
    print("="*70)
    
    result = run_attack_suite(bits=512, d_bits=128, run_quadratic_sieve=False, verbose=True)
    
    # ATTACK 4: Boneh-Durfee (theoretical)
    boneh_durfee_theory()
    
    # Summary
    print(f"\n{'='*70}")
    print("SECURITY AUDIT SUMMARY")
    print(f"{'='*70}")
    print("\n✗ CRITICAL VULNERABILITIES FOUND:")
    print(f"  1. Close primes: |p - q| = {result.rsa.gap:,} (bits: {result.rsa.gap_bits})")
    print(f"     → Fermat factorization success: {result.fermat_success}")
    print(f"  2. Small private exponent: {result.rsa.d_bits} bits")
    print(f"     → Wiener threshold bits: {result.wiener_threshold_bits}")
    print(f"     → Wiener attack recovered d: {result.wiener_success}")
    print(f"  3. Non-standard public exponent: {result.rsa.e_bits} bits (expected 17 bits for e=65537)")
    
    print("\n✓ BOB'S RECOMMENDATIONS:")
    print("  1. Use cryptographically secure random primes")
    print("  2. Ensure |p - q| > 2^(n/2 - 100)")
    print("  3. Use standard e = 65537")
    print("  4. Ensure d ≈ φ(N) in size")
    print("  5. Never prioritize 'speed' over security!")

    if result.notes:
        print("\nNotes:")
        for note in result.notes:
            print(f"  • {note}")
    
    print("\n" + "="*70)
    print("Bob's conclusion: REJECT SecureEncrypCompany's implementation!")
    print("="*70)


if __name__ == "__main__":
    main()
