"""
Baby Example: Breaking RSA using Quadratic Sieve
Following the handwritten example methodology

This demonstrates how the Quadratic Sieve algorithm can factor composite numbers
used in RSA encryption. For educational purposes, we use small numbers.

=== HOW QUADRATIC SIEVE WORKS ===

The security of RSA relies on the difficulty of factoring large composite numbers.
The Quadratic Sieve is one of the fastest algorithms for factoring numbers up to
about 100 digits.

The algorithm works by:
1. Parameter Selection: Choose factor base size B and generate primes up to B
2. Factor Base Construction: Generate primes where N is a quadratic residue
3. Sieving Phase: Find x values where Q(x) = x² - N factors completely over the factor base
4. Linear Algebra Phase: Find linear dependencies in the exponent matrix (mod 2)
5. GCD Computation: Use dependencies to find non-trivial factors

Key Idea:
If we can find x and y such that x² ≡ y² (mod N), but x ≢ ±y (mod N),
then GCD(x-y, N) or GCD(x+y, N) will give us a non-trivial factor of N.

Why "Quadratic"?
We evaluate Q(x) = x² - N for values near √N.
The goal is to find values where Q(x) factors completely over a small set of primes
(the "factor base").

Why "Sieve"?
We use a sieving technique to efficiently identify which Q(x) values are
"B-smooth" (all prime factors ≤ B).

=== WHY THIS BREAKS RSA ===

RSA's security depends on keeping p and q secret. Once we factor n=p*q:
1. We can compute φ(n) = (p-1)(q-1)
2. We can compute the private key d = e⁻¹ (mod φ(n))
3. We can decrypt any messages encrypted with the public key (n, e)
"""

import math
from collections import defaultdict
from gcd import gcd


def prime_factorization(n, factor_base):
    """
    Factor n over the factor base, return the prime factorization.
    Returns a dictionary {prime: exponent} or None if n is not B-smooth.
    """
    factorization = {}
    original_n = abs(n)
    
    if n == 0:
        return None
    
    # Handle negative numbers
    if n < 0:
        factorization[-1] = 1
        n = -n
    
    # Try to factor over the factor base
    for prime in factor_base:
        exponent = 0
        while n % prime == 0:
            n //= prime
            exponent += 1
        if exponent > 0:
            factorization[prime] = exponent
    
    # If n is not completely factored, it's not B-smooth
    if n != 1:
        return None
    
    return factorization


def print_factorization(x, q_x, factorization):
    """Pretty print a factorization"""
    if factorization is None:
        return f"x={x}: Q({x}) = {q_x} → NOT B-smooth"
    
    # Build factorization string
    terms = []
    for prime in sorted(factorization.keys()):
        exp = factorization[prime]
        if prime == -1:
            continue  # Skip the sign
        if exp == 1:
            terms.append(f"{prime}")
        else:
            terms.append(f"{prime}^{exp}")
    
    fact_str = " · ".join(terms) if terms else "1"
    return f"x={x}: Q({x}) = {q_x} = {fact_str} → B-smooth, keep!"


def find_linear_dependencies(smooth_relations, factor_base):
    """
    Find linear dependencies in the exponent matrix (mod 2).
    
    For the product to be a perfect square, all exponents must be even.
    This means we need to find subsets of smooth relations where the sum
    of exponents for each prime is even (i.e., ≡ 0 (mod 2)).
    
    Returns list of viable subsets (indices into smooth_relations).
    """
    print("\n" + "="*70)
    print("STEP 4: LINEAR ALGEBRA PHASE")
    print("="*70)
    print("\nBuilding exponent matrix from smooth relations...")
    print("Goal: Find subsets where all exponents sum to even values (mod 2)\n")
    
    # Build exponent matrix
    # Each row corresponds to a smooth relation
    # Each column corresponds to a prime in the factor base
    exponent_matrix = []
    
    for i, (x, q_x, factorization) in enumerate(smooth_relations):
        row = []
        for prime in factor_base:
            exp = factorization.get(prime, 0)
            row.append(exp % 2)  # We only care about parity
        exponent_matrix.append(row)
        
        # Print the factorization
        fact_str_parts = []
        for prime in factor_base:
            exp = factorization.get(prime, 0)
            if exp > 0:
                fact_str_parts.append(f"{prime}^{exp}")
        fact_str = " · ".join(fact_str_parts)
        print(f"  Relation {i+1} (x={x}): {fact_str}")
    
    print(f"\nWe have {len(smooth_relations)} smooth relations.")
    print("Now searching for linear dependencies (subsets with all even exponents)...\n")
    
    # For baby example, try all combinations
    from itertools import combinations
    
    dependencies = []
    
    for size in range(2, len(smooth_relations) + 1):
        for combo in combinations(range(len(smooth_relations)), size):
            # Sum exponent vectors (mod 2)
            sum_vector = [0] * len(factor_base)
            for idx in combo:
                for j in range(len(factor_base)):
                    sum_vector[j] = (sum_vector[j] + exponent_matrix[idx][j]) % 2
            
            # Check if all exponents are even (all zeros mod 2)
            if all(exp == 0 for exp in sum_vector):
                dependencies.append(combo)
                print(f"✓ Found dependency: relations {[i+1 for i in combo]}")
                
                # Show the system of equations that led to this
                print(f"  Using relations: {', '.join([f'x={smooth_relations[i][0]}' for i in combo])}")
                
                # For first dependency, show more detail
                if len(dependencies) == 1:
                    print("\n  Verification (exponent sums mod 2):")
                    for j, prime in enumerate(factor_base):
                        total_exp = sum(exponent_matrix[idx][j] for idx in combo)
                        print(f"    {prime}: {' + '.join([str(exponent_matrix[idx][j]) for idx in combo])} = {total_exp} ≡ {total_exp % 2} (mod 2)")
                
                print()
    
    return dependencies


def quadratic_sieve_handwritten_example(N):
    """
    Quadratic Sieve implementation following the handwritten example.
    
    Example: N = 539873
    
    The handwritten example shows:
    1. Factor base selection: {2, 3, 5, 7, 11, 13, 17, 19}
    2. Starting from x = ⌈√N⌉ = 735
    3. Finding smooth numbers
    4. Linear algebra to find dependencies
    5. GCD computation
    """
    print("="*70)
    print("QUADRATIC SIEVE")
    print("="*70)
    print(f"\nTarget: N = {N}")
    
    # Calculate sqrt(N)
    sqrt_n = math.isqrt(N)
    print(f"√N ≈ {sqrt_n}")
    
    print("\n" + "="*70)
    print("STEP 1: PARAMETER SELECTION")
    print("="*70)
    
    B = 19
    print(f"\nChoosing factor base size B = {B}")
    print("This means we'll use all prime factors ≤ 19")
    
    print("\n" + "="*70)
    print("STEP 2: FACTOR BASE CONSTRUCTION")
    print("="*70)
    
    # Generate factor base (primes up to B where N is a quadratic residue)
    # For simplicity in example, use all small primes
    factor_base = [2, 3, 5, 7, 11, 13, 17, 19]
    print(f"\nFactor Base FB = {factor_base}")
    
    print("\n" + "="*70)
    print("STEP 3: SIEVING PHASE")
    print("="*70)
    print(f"\nStarting from x = ⌈√N⌉ = {sqrt_n}, we increment x by 1 each step.")
    print("For each x, we compute Q(x) = x² - N and attempt to factor it over FB.")
    print("If Q(x) is B-smooth (factors completely over FB), we keep it!\n")
    
    # Sieving phase - find smooth numbers
    smooth_relations = []
    x = sqrt_n
    max_attempts = 2000  # Safety limit - increase to find more smooth numbers
    
    for attempt in range(max_attempts):
        # Compute Q(x) = x² - N
        q_x = x * x - N
        
        # Try to factor Q(x) over the factor base
        factorization = prime_factorization(q_x, factor_base)
        
        # Only print smooth numbers to reduce clutter
        if factorization is not None:
            result_str = print_factorization(x, q_x, factorization)
            print(f"  ✓ {result_str}")
            smooth_relations.append((x, q_x, factorization))
        
        # Stop when we have enough smooth relations
        # We need at least |FB| relations to have a chance at finding dependencies
        if len(smooth_relations) >= len(factor_base):
            print(f"\n  Found {len(smooth_relations)} smooth relations - attempting factorization!")
            break
        
        x += 1
    
    print(f"\n  Total smooth relations found: {len(smooth_relations)}")
    
    # Check if we have enough
    if len(smooth_relations) < len(factor_base) - 1:
        print("\n✗ Insufficient smooth numbers found!")
        print(f"   Found: {len(smooth_relations)}, Need: at least {len(factor_base) - 1}")
        return None, None
    
    # Linear algebra phase - find dependencies
    dependencies = find_linear_dependencies(smooth_relations, factor_base)
    
    if not dependencies:
        print("✗ No dependencies found!")
        return None, None
    
    print("\n" + "="*70)
    print("STEP 5: GCD COMPUTATION")
    print("="*70)
    
    # Try each dependency
    for dep_idx, dependency in enumerate(dependencies):
        print(f"\nTrying dependency {dep_idx + 1}: relations {[i+1 for i in dependency]}")
        
        # Compute x and y from the dependency
        # x is the product of all x values in the dependency
        # y² is the product of all Q(x) values (which should be a perfect square)
        
        x_product = 1
        y_squared_factors = defaultdict(int)
        
        for idx in dependency:
            x_val, q_x, factorization = smooth_relations[idx]
            x_product = (x_product * x_val) % N
            
            # Accumulate factorization
            for prime, exp in factorization.items():
                y_squared_factors[prime] += exp
        
        # Compute y from the factorization
        y = 1
        for prime, exp in y_squared_factors.items():
            if prime == -1:
                continue
            if exp % 2 != 0:
                print("  ERROR: Exponent not even! This shouldn't happen.")
                continue
            y = (y * pow(prime, exp // 2, N)) % N
        
        print(f"\n  Computed values:")
        print(f"    x ≡ {x_product} (mod {N})")
        print(f"    y ≡ {y} (mod {N})")
        
        # Verify x² ≡ y² (mod N)
        x_squared_mod_n = (x_product * x_product) % N
        y_squared_mod_n = (y * y) % N
        print(f"\n  Verification:")
        print(f"    x² ≡ {x_squared_mod_n} (mod {N})")
        print(f"    y² ≡ {y_squared_mod_n} (mod {N})")
        print(f"    x² ≡ y² (mod N)? {x_squared_mod_n == y_squared_mod_n}")
        
        # Try GCD
        z1 = gcd(x_product - y, N)
        z2 = gcd(x_product + y, N)
        
        print(f"\n  GCD computations:")
        print(f"    GCD(x - y, N) = GCD({x_product} - {y}, {N}) = {z1}")
        print(f"    GCD(x + y, N) = GCD({x_product} + {y}, {N}) = {z2}")
        
        # Check if we found a non-trivial factor
        if 1 < z1 < N:
            p = z1
            q = N // z1
            print(f"\n  ✓ SUCCESS! Found non-trivial factor:")
            print(f"    Factor 1: {p}")
            print(f"    Factor 2: {q}")
            print(f"    Verification: {p} × {q} = {p * q}")
            print(f"    Correct? {p * q == N}")
            return p, q
        
        if 1 < z2 < N:
            p = z2
            q = N // z2
            print(f"\n  ✓ SUCCESS! Found non-trivial factor:")
            print(f"    Factor 1: {p}")
            print(f"    Factor 2: {q}")
            print(f"    Verification: {p} × {q} = {p * q}")
            print(f"    Correct? {p * q == N}")
            return p, q
        
        print(f"  This dependency gave trivial factors, trying next one...")
    
    print("\n✗ No non-trivial factors found from any dependency")
    return None, None


def main():
    print("\n" + "="*70)
    print("RSA BREAKING EXAMPLE - QUADRATIC SIEVE")
    print("="*70)
    
    # Use the exact example from the handwritten notes
    N = 539873
    
    print(f"Factoring N = {N}")

    
    p, q = quadratic_sieve_handwritten_example(N)
    
    if p and q:
        print("\n" + "="*70)
        print("BREAKING RSA WITH QUADRATIC SIEVE")
        print("="*70)
        print(f"\nIf this was an RSA modulus N = {N}:")
        print(f"  We've broken the encryption by finding p = {p} and q = {q}!")
        print(f"\nNow we can:")
        print(f"  1. Compute φ(N) = (p-1)(q-1) = {(p-1)*(q-1)}")
        print(f"  2. Given public exponent e, compute d = e⁻¹ (mod φ(N))")
        print(f"  3. Decrypt any ciphertext encrypted with the public key (N, e)")
        print("\n" + "="*70)
        print("KEY INSIGHT")
        print("="*70)
        print("\nThe Quadratic Sieve works by:")
        print("  • Finding values x where x² ≡ y² (mod N)")
        print("  • But x ≢ ±y (mod N)")
        print("  • Then GCD(x±y, N) gives us a factor!")
        print("\nThis is why the algorithm is so powerful - it transforms the")
        print("factoring problem into a linear algebra problem!")
        print("\n" + "="*70)
    else:
        print("\n" + "="*70)
        print("Factorization was not successful with current parameters.")
        print("="*70)
        
if __name__ == "__main__":
    main()