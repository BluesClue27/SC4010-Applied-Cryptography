"""
RSA Security Analysis Suite
Demonstrating vulnerabilities in SecureEncrypCompany's implementation

Author: Bob (SC4010 Applied Cryptography Alumni)
Purpose: Prove insecurity of improper RSA parameter choices
"""

import math
import time
from fractions import Fraction
from typing import Tuple, Optional, List
import random


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

def quadratic_sieve_simple(N: int, factor_base_size: int = 100) -> Optional[Tuple[int, int]]:
    """
    Simplified Quadratic Sieve - general purpose factoring
    
    Theory: Find integers x such that x² ≡ y² (mod N), then gcd(x-y, N) may factor N
    
    This is a SIMPLIFIED educational version. Production QS is much more complex.
    
    Algorithm:
    1. Choose factor base of small primes
    2. Find smooth numbers (factor over base) near √N
    3. Use linear algebra to find subset whose product is a square
    4. Compute gcd to extract factors
    
    Complexity: O(exp(√(ln N ln ln N))) - sub-exponential
    Note: For large N (>100 digits), use optimized implementations
    """
    print(f"\n{'='*70}")
    print("ATTACK 2: QUADRATIC SIEVE (Simplified)")
    print(f"{'='*70}")
    print(f"Target N = {N}")
    print(f"N bit-length: {N.bit_length()} bits")
    print("\n[!] This is an educational simplified implementation")
    print("[!] For production use, consider YAFU, msieve, or CADO-NFS\n")
    
    start_time = time.time()
    
    # Step 1: Generate factor base (small primes where N is a quadratic residue)
    def sieve_primes(limit):
        """Sieve of Eratosthenes"""
        sieve = [True] * (limit + 1)
        sieve[0] = sieve[1] = False
        for i in range(2, int(limit**0.5) + 1):
            if sieve[i]:
                for j in range(i*i, limit + 1, i):
                    sieve[j] = False
        return [i for i in range(2, limit + 1) if sieve[i]]
    
    primes = sieve_primes(10000)
    
    # Choose primes where N is a quadratic residue (Legendre symbol = 1)
    factor_base = []
    for p in primes:
        if pow(N, (p - 1) // 2, p) == 1:
            factor_base.append(p)
            if len(factor_base) >= factor_base_size:
                break
    
    print(f"Factor base size: {len(factor_base)}")
    print(f"Factor base: {factor_base[:20]}..." if len(factor_base) > 20 else f"Factor base: {factor_base}")
    
    # Step 2: Sieving - find smooth numbers
    sqrt_n = math.isqrt(N)
    sieve_range = 10000
    smooth_numbers = []
    
    print(f"\nSieving for smooth numbers around √N...")
    
    for x in range(sqrt_n, sqrt_n + sieve_range):
        q = x * x - N
        if q <= 0:
            continue
        
        # Try to factor q over factor base
        temp_q = abs(q)
        factors = []
        
        for p in factor_base:
            exp = 0
            while temp_q % p == 0:
                temp_q //= p
                exp += 1
            if exp > 0:
                factors.append((p, exp))
        
        # If fully factored (smooth), save it
        if temp_q == 1:
            smooth_numbers.append((x, q, factors))
            if len(smooth_numbers) >= factor_base_size + 10:
                break
    
    print(f"Found {len(smooth_numbers)} smooth numbers")
    
    if len(smooth_numbers) < factor_base_size:
        print("\n✗ Insufficient smooth numbers found")
        print("   Consider: larger sieve range or factor base")
        return None, None
    
    # Step 3: Linear algebra to find dependencies
    # (Simplified: try random combinations)
    print("\nSearching for linear dependencies...")
    
    for _ in range(1000):
        # Randomly select subset
        subset_size = random.randint(2, min(10, len(smooth_numbers)))
        subset = random.sample(smooth_numbers, subset_size)
        
        # Compute product
        x_prod = 1
        for x, _, _ in subset:
            x_prod = (x_prod * x) % N
        
        # Check if product of q values is a perfect square
        exp_sums = {}
        for _, q, factors in subset:
            for p, exp in factors:
                exp_sums[p] = exp_sums.get(p, 0) + exp
        
        # All exponents must be even for perfect square
        if all(exp % 2 == 0 for exp in exp_sums.values()):
            # Compute y = √(product of q values) mod N
            y_squared = 1
            for p, exp in exp_sums.items():
                y_squared = (y_squared * pow(p, exp // 2, N)) % N
            
            # Try gcd
            factor = math.gcd(x_prod - y_squared, N)
            
            if 1 < factor < N:
                p = factor
                q = N // factor
                elapsed = time.time() - start_time
                
                print(f"\n✓ FACTORIZATION SUCCESSFUL!")
                print(f"  Time: {elapsed:.6f} seconds")
                print(f"\n  p = {p}")
                print(f"  q = {q}")
                print(f"  Verify: p × q = N? {p * q == N}")
                
                return min(p, q), max(p, q)
    
    elapsed = time.time() - start_time
    print(f"\n✗ No factors found (time: {elapsed:.6f}s)")
    print("   Note: This simplified version may not always succeed")
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
    
    # Generate vulnerable RSA parameters
    rsa = generate_vulnerable_rsa(bits=512, d_bits=128)
    
    print(f"\n{'='*70}")
    print("Generated RSA Parameters:")
    print(f"{'='*70}")
    print(f"N = {rsa['N']}")
    print(f"e = {rsa['e']}")
    print(f"d = {rsa['d']} (SECRET - but we'll recover it!)")
    print(f"\nActual factors (for verification):")
    print(f"p = {rsa['p']}")
    print(f"q = {rsa['q']}")
    
    # ATTACK 1: Fermat Factorization
    p_fermat, q_fermat = fermat_factorization(rsa['N'])
    
    # ATTACK 2: Quadratic Sieve (optional, may not always succeed)
    print("\n" + "="*70)
    print("NOTE: Quadratic Sieve is computationally intensive.")
    print("Skipping full QS demonstration for time. Use for larger N.")
    print("="*70)
    # Uncomment to run: p_qs, q_qs = quadratic_sieve_simple(rsa['N'])
    
    # ATTACK 3: Wiener's Attack
    d_recovered = wiener_attack(rsa['e'], rsa['N'])
    
    # ATTACK 4: Boneh-Durfee (theoretical)
    boneh_durfee_theory()
    
    # Summary
    print(f"\n{'='*70}")
    print("SECURITY AUDIT SUMMARY")
    print(f"{'='*70}")
    print("\n✗ CRITICAL VULNERABILITIES FOUND:")
    print(f"  1. Close Primes: |p-q| = {abs(rsa['p'] - rsa['q']):,} bits")
    print(f"     → Broken by Fermat in {fermat_factorization.__doc__}")
    print(f"  2. Small d: {rsa['d'].bit_length()} bits (should be ~{rsa['bits']} bits)")
    print(f"     → Broken by Wiener attack")
    print(f"  3. Non-standard e: {rsa['e'].bit_length()} bits (should be 17 bits, e=65537)")
    
    print("\n✓ BOB'S RECOMMENDATIONS:")
    print("  1. Use cryptographically secure random primes")
    print("  2. Ensure |p - q| > 2^(n/2 - 100)")
    print("  3. Use standard e = 65537")
    print("  4. Ensure d ≈ φ(N) in size")
    print("  5. Never prioritize 'speed' over security!")
    
    print("\n" + "="*70)
    print("Bob's conclusion: REJECT SecureEncrypCompany's implementation!")
    print("="*70)


if __name__ == "__main__":
    main()