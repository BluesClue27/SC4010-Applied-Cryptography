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
    Compute Continued Fraction Expansion (from SC4010 lectures)

    MATHEMATICAL DEFINITION:
    ========================
    A continued fraction represents a rational number x/y as:
        x/y = a₀ + 1/(a₁ + 1/(a₂ + 1/(a₃ + 1/(a₄ + ...))))

    More compactly: [a₀; a₁, a₂, a₃, ...]

    ALGORITHM (Euclidean Algorithm Based):
    ======================================
    Given x/y, compute terms iteratively:
        1. a₀ = ⌊x/y⌋ (integer part)
        2. Remainder: r = x - a₀·y
        3. If r = 0, stop
        4. Otherwise, compute CF of y/r
        5. Repeat

    This is essentially the Euclidean algorithm for GCD!

    EXAMPLE:
    ========
    For 22/7 (approximation of π):
        22/7 = 3 + 1/7
             = 3 + 1/(7/1)
        So CF = [3; 7]

    For 649/200:
        649/200 = 3 + 49/200
        200/49 = 4 + 4/49
        49/4 = 12 + 1/4
        4/1 = 4
        So CF = [3; 4, 12, 4]

    CONNECTION TO WIENER ATTACK:
    ============================
    For e/N, the CF expansion contains convergents k_i/d_i
    One of these convergents equals k/d where ed ≡ 1 (mod φ(N))
    This allows us to test candidates for the private exponent d!

    Returns:
        List[int]: The continued fraction coefficients [a₀, a₁, a₂, ...]
    """
    cf = []
    while denominator:
        # Integer division: a = ⌊numerator/denominator⌋
        q = numerator // denominator
        cf.append(q)

        # Update for next iteration: swap and take remainder
        # This is the Euclidean algorithm step
        numerator, denominator = denominator, numerator - q * denominator

    return cf


def convergents(cf: List[int]) -> List[Tuple[int, int]]:
    """
    Compute Convergents from Continued Fraction (from SC4010 lectures)

    MATHEMATICAL DEFINITION:
    ========================
    The n-th convergent C_n = p_n/q_n is the rational number obtained by
    truncating the CF after n terms.

    For CF = [a₀; a₁, a₂, ..., a_n]:
        C₀ = a₀/1
        C₁ = (a₁·a₀ + 1)/a₁ = (a₀·a₁ + 1)/a₁
        C₂ = ... (computed recursively)

    RECURSIVE FORMULA:
    ==================
    Let h_n = numerator of C_n, k_n = denominator of C_n

    Base cases:
        h₋₁ = 1,  k₋₁ = 0
        h₀ = a₀,  k₀ = 1

    Recurrence (the KEY formula):
        h_n = a_n · h_{n-1} + h_{n-2}
        k_n = a_n · k_{n-1} + k_{n-2}

    This gives us C_n = h_n/k_n

    PROPERTIES:
    ===========
    1. Best Approximations: Each convergent is the "best" rational
       approximation to the original number with denominator ≤ k_n
    2. Alternating: Convergents alternate around the true value
    3. Error Bound: |x - p_n/q_n| < 1/(q_n · q_{n+1})

    WHY THIS MATTERS FOR WIENER:
    =============================
    If |e/N - k/d| < 1/(2d²), then k/d MUST appear as a convergent!
    This is guaranteed when d < (1/3)·N^(1/4)

    EXAMPLE:
    ========
    For CF = [3; 4, 12, 4]:
        C₀ = 3/1
        C₁ = (4·3 + 1)/(4·1 + 0) = 13/4
        C₂ = (12·13 + 3)/(12·4 + 1) = 159/49
        C₃ = (4·159 + 13)/(4·49 + 4) = 649/200

    Args:
        cf: Continued fraction coefficients [a₀, a₁, a₂, ...]

    Returns:
        List[(h, k)]: List of convergents as (numerator, denominator) pairs
    """
    convs = []

    # Initialize with base cases: h₋₁ = 1, k₋₁ = 0, h₀ = a₀, k₀ = 1
    h_prev2, h_prev1 = 0, 1  # h_{-1}, h_{0} (before first CF term)
    k_prev2, k_prev1 = 1, 0  # k_{-1}, k_{0}

    # Compute each convergent using recurrence relation
    for a in cf:
        # Recurrence: h_n = a_n · h_{n-1} + h_{n-2}
        h = a * h_prev1 + h_prev2
        # Recurrence: k_n = a_n · k_{n-1} + k_{n-2}
        k = a * k_prev1 + k_prev2

        convs.append((h, k))

        # Shift for next iteration
        h_prev2, h_prev1 = h_prev1, h
        k_prev2, k_prev1 = k_prev1, k

    return convs


def wiener_attack(e: int, N: int) -> Optional[int]:
    """
    Wiener's Attack - exploits small private exponent d (Ke Yuan's Implementation)

    MATHEMATICAL FOUNDATION:
    ========================
    In RSA, we have: e·d ≡ 1 (mod φ(N))
    This means: e·d = 1 + k·φ(N) for some integer k
    Rearranging: e/N ≈ k/d (since φ(N) ≈ N for large primes)

    The approximation error is: |e/N - k/d| ≈ |k·(N - φ(N))|/(N·d)
    Since N - φ(N) = p + q - 1 < 3√N, we get:
    |e/N - k/d| < 3k/(d·√N)

    WIENER'S KEY INSIGHT:
    ====================
    If d < (1/3)·N^(1/4), then k/d is a convergent of the continued fraction
    expansion of e/N. This is because the error bound satisfies:
    |e/N - k/d| < 1/(2d²)

    By testing all convergents (which number O(log N)), we can recover d in
    polynomial time!

    VULNERABILITY THRESHOLD:
    ========================
    For 1024-bit RSA: N^(1/4) ≈ 2^256 bits
                      d < N^(1/4)/3 ≈ 2^254 bits (VULNERABLE)
    For 2048-bit RSA: N^(1/4) ≈ 2^512 bits
                      d < N^(1/4)/3 ≈ 2^510 bits (VULNERABLE)

    SecureEncrypCompany's 256-bit d is WELL BELOW these thresholds!

    ALGORITHM STEPS (from SC4010 lectures):
    ========================================
    1. Compute continued fraction expansion of e/N
    2. Calculate all convergents k_i/d_i from the CF
    3. For each convergent k/d:
       a. Compute φ(N) candidate = (e·d - 1)/k
       b. Derive p + q = N - φ(N) + 1
       c. Solve quadratic: t² - (p+q)·t + N = 0
       d. Check if discriminant is a perfect square
       e. If yes, recover p and q!

    Complexity: O(log N) convergents × O(1) arithmetic = O(log N) - POLYNOMIAL!
    Compare to factoring which takes sub-exponential time.

    BONEH-DURFEE IMPROVEMENT:
    =========================
    Wiener: d < N^0.25
    Boneh-Durfee: d < N^0.292 (using lattice techniques)
    """
    print(f"\n{'='*70}")
    print("ATTACK 3: WIENER'S ATTACK (Ke Yuan's Implementation)")
    print(f"{'='*70}")
    print("📚 Based on: M. Wiener, 'Cryptanalysis of Short RSA Secret Exponents'")
    print("             IEEE Transactions on Information Theory, 1990")
    print(f"{'='*70}")

    print(f"\n📊 PUBLIC KEY PARAMETERS:")
    print(f"  e = {e}")
    print(f"  e bit-length: {e.bit_length()} bits")
    print(f"  N = {N}")
    print(f"  N bit-length: {N.bit_length()} bits")

    # Check if attack is theoretically applicable
    n_fourth_root = integer_fourth_root(N)
    threshold = n_fourth_root // 3

    print(f"\n🎯 VULNERABILITY THRESHOLD ANALYSIS:")
    print(f"  N^(1/4) = {n_fourth_root}")
    print(f"  N^(1/4) bits = {n_fourth_root.bit_length()}")
    print(f"  Wiener threshold: d < (1/3) × N^(1/4)")
    print(f"                    d < {threshold}")
    print(f"                    d < 2^{threshold.bit_length()} ({threshold.bit_length()} bits)")
    print(f"\n  ⚠️  Any d smaller than {threshold.bit_length()} bits is VULNERABLE to this attack!")
    
    start_time = time.time()

    # Step 1: Compute continued fraction of e/N
    print(f"\n{'─'*70}")
    print("STEP 1: Computing Continued Fraction Expansion of e/N")
    print(f"{'─'*70}")
    print(f"  The continued fraction represents e/N as:")
    print(f"  e/N = a₀ + 1/(a₁ + 1/(a₂ + 1/(a₃ + ...)))")
    print(f"\n  Computing expansion...")
    cf = continued_fraction(e, N)
    print(f"  ✓ CF expansion computed: length = {len(cf)}")
    print(f"  First 10 terms: {cf[:10]}...")

    # Step 2: Test each convergent
    print(f"\n{'─'*70}")
    print("STEP 2: Computing and Testing Convergents")
    print(f"{'─'*70}")
    print(f"  Convergents are 'best rational approximations' at each CF level")
    print(f"  We expect k/d (where ed = 1 + kφ(N)) to appear as a convergent\n")
    convs = convergents(cf)
    print(f"  ✓ Generated {len(convs)} convergents to test")
    
    print(f"\n{'─'*70}")
    print("STEP 3: Testing Each Convergent k/d")
    print(f"{'─'*70}")

    for i, (k, d) in enumerate(convs):
        if k == 0:
            continue

        if i % 10 == 0 and i > 0:
            print(f"  ... tested {i} convergents so far...")

        # Candidate for φ(N): ed = 1 + kφ(N) → φ(N) = (ed - 1)/k
        if (e * d - 1) % k != 0:
            continue

        phi_candidate = (e * d - 1) // k

        # MATHEMATICAL INSIGHT:
        # We know: N = p·q and φ(N) = (p-1)(q-1) = pq - p - q + 1
        # Therefore: p + q = N - φ(N) + 1
        sum_pq = N - phi_candidate + 1

        # Now solve the quadratic equation: t² - (p+q)t + pq = 0
        # Using quadratic formula: t = [(p+q) ± √((p+q)² - 4pq)] / 2
        # Discriminant: Δ = (p+q)² - 4pq = (p-q)²
        discriminant = sum_pq * sum_pq - 4 * N

        if discriminant >= 0:
            sqrt_disc = math.isqrt(discriminant)

            # Check if discriminant is a perfect square
            if sqrt_disc * sqrt_disc == discriminant:
                # Perfect square! Extract p and q
                p = (sum_pq + sqrt_disc) // 2
                q = (sum_pq - sqrt_disc) // 2

                # Verify factorization
                if p * q == N:
                    elapsed = time.time() - start_time

                    print(f"\n{'='*70}")
                    print("🎉 SUCCESS! PRIVATE KEY RECOVERED!")
                    print(f"{'='*70}")
                    print(f"\n✓ Found at convergent index: {i}/{len(convs)}")
                    print(f"✓ Attack completed in: {elapsed:.6f} seconds")
                    print(f"\n{'─'*70}")
                    print("RECOVERED PRIVATE EXPONENT:")
                    print(f"{'─'*70}")
                    print(f"  d = {d}")
                    print(f"  d bit-length: {d.bit_length()} bits")
                    print(f"  k = {k} (where ed = 1 + kφ(N))")

                    print(f"\n{'─'*70}")
                    print("RECOVERED PRIME FACTORS:")
                    print(f"{'─'*70}")
                    print(f"  p = {p}")
                    print(f"  q = {q}")
                    print(f"  |p - q| = {abs(p - q)}")

                    # Verify correctness
                    phi_n = (p - 1) * (q - 1)
                    print(f"\n{'─'*70}")
                    print("VERIFICATION:")
                    print(f"{'─'*70}")
                    print(f"  ✓ p × q = N? {p * q == N}")
                    print(f"  ✓ φ(N) = (p-1)(q-1) = {phi_n}")
                    print(f"  ✓ e × d mod φ(N) = {(e * d) % phi_n} (expected: 1)")
                    print(f"  ✓ Cryptographic validity: {(e * d) % phi_n == 1}")

                    print(f"\n{'─'*70}")
                    print("VULNERABILITY ANALYSIS:")
                    print(f"{'─'*70}")
                    print(f"  Wiener threshold: {threshold.bit_length()} bits")
                    print(f"  Actual d: {d.bit_length()} bits")
                    print(f"  Vulnerable? {d < threshold} ✓")

                    # Calculate ratio more carefully
                    ratio = d / n_fourth_root
                    print(f"  d / N^(1/4) = {ratio:.15e}")  # Scientific notation for very small numbers
                    print(f"  Expected for security: d / N^(1/4) should be ≥ 0.333...")
                    print(f"  Actual ratio: {ratio:.15e} << 0.333 (CRITICALLY WEAK!)")

                    print(f"\n💡 KEY INSIGHT:")
                    print(f"  SecureEncrypCompany chose d = {d.bit_length()} bits for 'blazing decryption'")

                    # Better threshold comparison
                    bits_below = threshold.bit_length() - d.bit_length()
                    if bits_below > 0:
                        print(f"  This is {bits_below} bits BELOW the Wiener threshold!")
                    else:
                        print(f"  But it's still vulnerable (d < threshold by value)")

                    print(f"\n  The convergent k/d appeared at position {i} in the CF expansion:")
                    print(f"    k = {k}")
                    print(f"    d = {d}")
                    print(f"    k bit-length: {k.bit_length()} bits")
                    print(f"    d bit-length: {d.bit_length()} bits")

                    return d

    elapsed = time.time() - start_time
    print(f"\n{'='*70}")
    print("✗ ATTACK FAILED")
    print(f"{'='*70}")
    print(f"  Time elapsed: {elapsed:.6f} seconds")
    print(f"  Convergents tested: {len(convs)}")
    print(f"\n  Possible reasons:")
    print(f"    • d ≥ (1/3)·N^(1/4) (too large for Wiener)")
    print(f"    • For d < N^0.292, try Boneh-Durfee attack instead")
    print(f"    • RSA parameters may be secure against this attack")
    return None


# ============================================================================
# ATTACK 4: BONEH-DURFEE ATTACK (theoretical improvement)
# ============================================================================

def boneh_durfee_theory():
    """
    Boneh-Durfee Attack - Comprehensive Theoretical Overview (Ke Yuan's Analysis)

    THEORETICAL IMPROVEMENT OVER WIENER:
    ====================================
    Wiener (1990):        d < N^0.25        [Continued fractions]
    Boneh-Durfee (1999):  d < N^0.292       [Lattice reduction + Coppersmith's method]

    This represents a ~17% increase in the vulnerable range!
    For 2048-bit RSA: N^0.292 ≈ 2^598 bits vs N^0.25 ≈ 2^512 bits

    MATHEMATICAL FOUNDATION:
    ========================
    Starting point: ed ≡ 1 (mod φ(N))
    This means: ed = 1 + kφ(N) for some integer k

    Key observation: φ(N) = N - p - q + 1
    Let s = p + q, then: φ(N) = N - s + 1

    Substituting:
        ed = 1 + k(N - s + 1)
        ed - 1 = kN - ks + k
        k(N + 1) - ed + 1 = ks

    Define: A = k(N + 1) - ed + 1
    Then: A = ks, which means k divides A

    COPPERSMITH'S METHOD (The Core Technique):
    ==========================================
    Coppersmith (1996) showed how to find small roots of polynomial equations
    modulo N using lattice reduction techniques.

    For Boneh-Durfee, we construct a bivariate polynomial:
        f(x, y) = x(N + y) + 1 = 0  (mod e)

    where:
        x = k  (small: k < d ≈ N^0.292)
        y = -(p + q)  (small: |y| < 3√N since p, q ≈ √N)

    The goal is to find small (x₀, y₀) such that f(x₀, y₀) ≡ 0 (mod e)

    LATTICE REDUCTION (LLL Algorithm):
    ==================================
    Lenstra-Lenstra-Lovász (1982) algorithm finds short vectors in lattices.

    Construction:
    1. Build a lattice L from polynomial f and its shifts:
       - Shifts: x^i · y^j · f(x,y)^k · e^(m-k) for various i,j,k
       - These create a matrix where each row represents a polynomial

    2. Each polynomial P(x,y) in the lattice can be written as:
       P(x,y) = Σ a_ij · x^i · y^j

    3. Build coefficient matrix M where M[i,j] represents coefficient of x^i·y^j

    4. Apply LLL to find short vector v in lattice
       - Short vector → small coefficients
       - Evaluate at (x₀, y₀) gives small value
       - If small enough, equals 0 over integers (not just mod e)!

    5. Get two polynomials P₁(x,y) = 0 and P₂(x,y) = 0
       - Use resultant or Gröbner basis to eliminate variables
       - Solve for k and s = p + q
       - Factor N knowing p + q

    DIMENSION ANALYSIS:
    ===================
    The lattice dimension depends on parameter m (complexity/accuracy tradeoff):
        dim(L) ≈ m³/6

    For successful attack, need:
        d < N^β where β = 1 - 1/√2 ≈ 0.292

    Larger m → better bound but higher complexity
        m = 3:  ~50 dimensions
        m = 5:  ~200 dimensions
        m = 7:  ~550 dimensions

    WHY IT WORKS (The Mathematical Insight):
    =========================================
    Wiener's limitation comes from using only first-order approximation e/N ≈ k/d

    Boneh-Durfee uses higher-order relationships through lattice basis:
    - Multiple polynomial shifts create dependencies
    - LLL finds linear combinations that vanish at (k, -(p+q))
    - This "amplifies" the signal hidden in the algebraic structure

    The bound δ = 0.292 comes from optimization of lattice parameters
    to balance:
        • Polynomial degree vs lattice dimension
        • Root bounds (Howgrave-Graham theorem)
        • LLL reduction quality

    COMPLEXITY ANALYSIS:
    ====================
    Time: O(m^6 · log²N) where m depends on desired bound
    Space: O(m³) for lattice storage

    For practical attacks:
        • 1024-bit RSA, d < N^0.292: ~1 hour on modern hardware
        • 2048-bit RSA, d < N^0.292: ~1 day
        • Requires significant computational resources

    Compare to Wiener: O(log N) - much faster but more restrictive!
    """
    print(f"\n{'='*70}")
    print("ATTACK 4: BONEH-DURFEE ATTACK")
    print("Theoretical Analysis (Ke Yuan's Implementation)")
    print(f"{'='*70}")
    print("📚 Based on: D. Boneh and G. Durfee,")
    print("            'Cryptanalysis of RSA with Private Key d Less Than N^0.292'")
    print("             EUROCRYPT 1999")
    print(f"{'='*70}")

    print("\n" + "="*70)
    print("COMPARATIVE ANALYSIS: WIENER vs BONEH-DURFEE")
    print("="*70)

    print(f"\n{'ASPECT':<30} {'WIENER':<20} {'BONEH-DURFEE':<20}")
    print("─"*70)
    print(f"{'Vulnerability Threshold':<30} {'d < N^0.25':<20} {'d < N^0.292':<20}")
    print(f"{'Technique':<30} {'Continued Frac.':<20} {'Lattice Reduction':<20}")
    print(f"{'Time Complexity':<30} {'O(log N)':<20} {'O(m^6 log²N)':<20}")
    print(f"{'Difficulty':<30} {'Elementary':<20} {'Advanced':<20}")
    print(f"{'Implementation':<30} {'~100 lines':<20} {'Requires SageMath':<20}")

    print("\n" + "="*70)
    print("THRESHOLD COMPARISON (Different RSA Sizes)")
    print("="*70)

    for n_bits in [1024, 2048, 3072, 4096]:
        N_example = 2 ** n_bits
        wiener_bits = int(0.25 * n_bits)
        boneh_bits = int(0.292 * n_bits)
        diff = boneh_bits - wiener_bits

        print(f"\n{n_bits}-bit RSA (N ≈ 2^{n_bits}):")
        print(f"  Wiener threshold:       d < 2^{wiener_bits:<4} ({wiener_bits} bits)")
        print(f"  Boneh-Durfee threshold: d < 2^{boneh_bits:<4} ({boneh_bits} bits)")
        print(f"  Additional coverage:    {diff} bits ({(diff/wiener_bits)*100:.1f}% increase)")

    print("\n" + "="*70)
    print("MATHEMATICAL FOUNDATION")
    print("="*70)

    print("\n1️⃣  STARTING EQUATION:")
    print("   ed ≡ 1 (mod φ(N))  →  ed = 1 + kφ(N)")

    print("\n2️⃣  SUBSTITUTION:")
    print("   φ(N) = N - (p + q) + 1")
    print("   Let s = p + q, then φ(N) = N - s + 1")

    print("\n3️⃣  POLYNOMIAL FORMULATION:")
    print("   f(x, y) = x(N + y) + 1")
    print("   where x = k (small), y = -(p+q) (small)")
    print("   Goal: Find roots (x₀, y₀) such that f(x₀, y₀) ≡ 0 (mod e)")

    print("\n4️⃣  COPPERSMITH'S METHOD:")
    print("   Use lattice reduction to find small roots of f(x,y) mod e")
    print("   Build lattice from polynomial shifts: x^i · y^j · f^k · e^(m-k)")

    print("\n5️⃣  LLL LATTICE REDUCTION:")
    print("   • Construct coefficient matrix M (dimension ≈ m³/6)")
    print("   • Apply LLL to find short vectors")
    print("   • Short vectors → polynomials that vanish at (k, -(p+q))")
    print("   • Solve system to recover k and p+q")

    print("\n6️⃣  FACTORIZATION:")
    print("   Knowing p + q and p·q = N, solve quadratic:")
    print("   t² - (p+q)·t + N = 0")
    print("   t = [(p+q) ± √((p+q)² - 4N)] / 2")

    print("\n" + "="*70)
    print("WHY BONEH-DURFEE BEATS WIENER")
    print("="*70)

    print("\n🔍 Wiener's Limitation:")
    print("   Uses only linear approximation: e/N ≈ k/d")
    print("   Limited by first convergent in continued fraction")
    print("   Cannot exploit higher-order algebraic structure")

    print("\n✨ Boneh-Durfee's Advantage:")
    print("   Exploits bivariate polynomial relationships")
    print("   Lattice encodes multiple algebraic dependencies simultaneously")
    print("   LLL finds hidden linear combinations")
    print("   Result: Can handle larger d (up to N^0.292 vs N^0.25)")

    print("\n" + "="*70)
    print("IMPLEMENTATION REQUIREMENTS")
    print("="*70)

    print("\n📦 Required Libraries:")
    print("   • SageMath: Full computer algebra system")
    print("   • fpylll: Fast Python LLL implementation")
    print("   • NumPy: Matrix operations")

    print("\n🔧 Implementation Steps:")
    print("   1. Construct shift-polynomial lattice basis")
    print("   2. Build coefficient matrix M")
    print("   3. Apply LLL reduction: M_reduced = LLL(M)")
    print("   4. Extract short vectors from reduced basis")
    print("   5. Reconstruct polynomials from short vectors")
    print("   6. Compute resultant or use Gröbner basis")
    print("   7. Solve for k and s = p + q")
    print("   8. Factor N using quadratic formula")

    print("\n⏱️  Computational Complexity:")
    print("   • Lattice dimension: ~m³/6 (m = 5 to 7 typical)")
    print("   • LLL time: O(n⁴ · B) for n×n matrix, B = bit size")
    print("   • Overall: O(m⁶ log²N)")
    print("   • 1024-bit RSA: ~1 hour")
    print("   • 2048-bit RSA: ~1 day")

    print("\n" + "="*70)
    print("PRACTICAL CONSIDERATIONS")
    print("="*70)

    print("\n✅ When to Use Boneh-Durfee:")
    print("   • d falls in range: N^0.25 < d < N^0.292")
    print("   • Wiener attack fails")
    print("   • Have access to SageMath or equivalent")
    print("   • Can afford computation time (hours to days)")

    print("\n❌ When NOT to Use:")
    print("   • d < N^0.25 → Use Wiener instead (much faster!)")
    print("   • d > N^0.292 → Both attacks fail, try factoring")
    print("   • No lattice reduction tools available")

    print("\n⚠️  SecureEncrypCompany's Parameters:")
    print("   For their 256-bit d on 512-bit modulus:")
    print("   • d bit ratio: 256/512 = 0.5 (as exponent)")
    print("   • N^0.5 = √N - way above N^0.292!")
    print("   • BUT: Wiener already catches it (d < N^0.25)")
    print("   • Boneh-Durfee unnecessary for this weak implementation")

    print("\n" + "="*70)
    print("SECURITY RECOMMENDATIONS")
    print("="*70)

    print("\n🛡️  To Defend Against Both Attacks:")
    print("   1. Ensure d > N^0.292 (better: d ≈ φ(N))")
    print("   2. For 1024-bit RSA: d should be > 299 bits")
    print("   3. For 2048-bit RSA: d should be > 598 bits")
    print("   4. Standard practice: d ≈ φ(N) ≈ N (2048 bits for 2048-bit RSA)")
    print("   5. Use e = 65537 (standard choice)")

    print("\n📖 Further Reading:")
    print("   • Boneh-Durfee original paper (EUROCRYPT 1999)")
    print("   • Coppersmith, 'Finding Small Roots of Univariate Modular Equations'")
    print("   • Howgrave-Graham, 'Finding Small Roots of Univariate Modular Equations Revisited'")
    print("   • Bleichenbacher-May improvements (2006)")

    print("\n💡 KEY TAKEAWAY:")
    print("   Boneh-Durfee is a powerful theoretical tool that extends")
    print("   Wiener's attack by 17%. However, for SecureEncrypCompany's")
    print("   critically weak 256-bit d, Wiener attack is sufficient.")
    print("   Both attacks emphasize: NEVER use small d for 'performance'!")

    print("\n" + "="*70)


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


def load_from_values_file():
    """
    Load RSA parameters from values.py if it exists.

    Returns:
        dict with RSA parameters if values.py exists, None otherwise
    """
    import os
    if os.path.exists('values.py'):
        try:
            print("\n" + "="*70)
            print("📂 FOUND values.py - Loading saved parameters")
            print("="*70)

            from values import N, e, d, p, q, phi_n

            print(f"✓ Loaded parameters from values.py")
            print(f"  Generated: {open('values.py').readlines()[2].split(': ')[1].strip()}")
            print(f"  N: {N.bit_length()} bits")
            print(f"  d: {d.bit_length()} bits")
            print(f"  |p-q|: {abs(p-q):,}")
            print("="*70 + "\n")

            return {
                'N': N,
                'e': e,
                'd': d,
                'p': p,
                'q': q,
                'phi_n': phi_n,
                'bits': N.bit_length()
            }
        except ImportError as e:
            print(f"⚠️  Warning: values.py exists but couldn't import: {e}")
            print("   Generating fresh parameters instead...\n")
            return None
    return None


def main():
    """
    Bob's Complete Security Demonstration

    Workflow:
    1. Check if values.py exists (from rsa_weak_implementation.py)
    2. If yes: Load parameters from values.py
    3. If no: Generate fresh weak parameters
    4. Run all attacks
    """
    print("\n" + "="*70)
    print(" "*15 + "BOB'S RSA SECURITY ANALYSIS")
    print(" "*10 + "Exposing SecureEncrypCompany's Vulnerabilities")
    print("="*70)

    # Try to load from values.py first
    saved_params = load_from_values_file()

    if saved_params:
        # Use saved parameters
        print("\n💡 Using parameters from values.py (generated by rsa_weak_implementation.py)")
        print("   To generate new parameters: python rsa_weak_implementation.py\n")

        # Create RSA parameters object
        rsa = RSAParameters(**saved_params)

        # Run attacks manually
        print(f"\n{'='*70}")
        print("RUNNING ATTACK SUITE ON SAVED PARAMETERS")
        print(f"{'='*70}\n")

        fermat_factors = fermat_factorization(rsa.N)
        wiener_d = wiener_attack(rsa.e, rsa.N)

        threshold = integer_fourth_root(rsa.N) // 3

        result = AttackSuiteResult(
            rsa=rsa,
            fermat_factors=fermat_factors,
            quadratic_factors=None,
            wiener_d=wiener_d,
            wiener_threshold=threshold,
            notes=[
                "Parameters loaded from values.py",
                "Wiener attack successfully recovered the private exponent." if wiener_d else "Wiener attack failed",
                "Quadratic sieve skipped"
            ]
        )
    else:
        # Generate fresh parameters
        print("\n💡 No values.py found - Generating fresh weak parameters")
        print("   To use saved parameters: python rsa_weak_implementation.py first\n")

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
