"""
Baby Example: Breaking RSA using Quadratic Sieve

This demonstrates how the Quadratic Sieve algorithm can factor composite numbers
used in RSA encryption. For educational purposes, we use small numbers.

=== HOW QUADRATIC SIEVE WORKS ===

The security of RSA relies on the difficulty of factoring large composite numbers.
The Quadratic Sieve is one of the fastest algorithms for factoring numbers up to
about 100 digits.

The algorithm works by:
1. Finding smooth numbers (numbers whose prime factors are all small)
2. Building congruences of squares modulo n
3. Using linear algebra to find dependencies
4. Computing GCD to extract factors

Key Idea:
If we can find x and y such that x^2 = y^2 (mod n), but x != +/- y (mod n),
then GCD(x-y, n) or GCD(x+y, n) will give us a non-trivial factor of n.

Example:
If n = 15, and we find x=4, y=1 where 4^2 = 16 = 1 (mod 15) = 1^2
Then GCD(4-1, 15) = GCD(3, 15) = 3, which is a factor!
And 15/3 = 5, so we've factored 15 = 3 * 5

=== WHY THIS BREAKS RSA ===

RSA's security depends on keeping p and q secret. Once we factor n=p*q:
1. We can compute phi(n) = (p-1)(q-1)
2. We can compute the private key d = e^-1 (mod phi(n))
3. We can decrypt any messages encrypted with the public key (n, e)
"""

import math
from collections import defaultdict
from gcd import gcd


def is_smooth(num, factor_base):
    """Check if a number is smooth over the factor base"""
    if num < 0:
        num = -num
    if num == 0:
        return False

    for prime in factor_base:
        while num % prime == 0:
            num //= prime

    return num == 1


def factor_over_base(num, factor_base):
    """Factor a number over the factor base, return exponent vector"""
    exponents = []
    original = num
    is_negative = num < 0

    if num < 0:
        num = -num

    for prime in factor_base:
        exp = 0
        while num % prime == 0:
            num //= prime
            exp += 1
        exponents.append(exp % 2)  # We only care about parity

    if num != 1:
        return None  # Not smooth

    return exponents


def generate_factor_base(n, size=10):
    """Generate a small factor base of primes for which n is a quadratic residue"""
    factor_base = []
    candidate = 2

    while len(factor_base) < size:
        # Check if candidate is prime (simple trial division for small numbers)
        is_prime = True
        if candidate > 2:
            for i in range(2, int(math.sqrt(candidate)) + 1):
                if candidate % i == 0:
                    is_prime = False
                    break

        if is_prime:
            # Check if n is a quadratic residue modulo candidate
            # For p=2, always include
            # For odd p, use Legendre symbol (simplified check)
            if candidate == 2 or pow(n, (candidate - 1) // 2, candidate) == 1:
                factor_base.append(candidate)

        candidate += 1

    return factor_base


def quadratic_sieve_simple(n):
    """
    Simplified Quadratic Sieve for small numbers
    Returns factors p and q of n
    """
    print(f"Attempting to factor n = {n}")
    print(f"sqrt(n) approx {math.isqrt(n)}")
    print()

    # Generate factor base
    factor_base = generate_factor_base(n, size=10)
    print(f"Factor base: {factor_base}")
    print()

    # Find smooth numbers
    smooth_relations = []
    exponent_vectors = []

    # Try values near sqrt(n)
    sqrt_n = math.isqrt(n)
    search_range = 200

    print("Searching for smooth relations...")
    for i in range(-search_range, search_range):
        x = sqrt_n + i
        if x <= 0:
            continue

        # Compute Q(x) = x^2 - n
        q_x = (x * x) - n

        if q_x == 0:
            continue

        # Check if q_x is smooth
        exp_vector = factor_over_base(q_x, factor_base)

        if exp_vector is not None:
            smooth_relations.append((x, q_x))
            exponent_vectors.append(exp_vector)
            print(f"  Found: x={x}, Q(x)={q_x}, smooth!")

            # For baby example, stop after finding enough relations
            if len(smooth_relations) >= len(factor_base) + 3:
                break

    print(f"\nFound {len(smooth_relations)} smooth relations")
    print()

    # Find linear dependencies (simplified - try all subsets for baby example)
    print("Looking for linear dependencies...")

    # Try to find subset where sum of exponent vectors is zero (mod 2)
    from itertools import combinations

    for size in range(2, len(smooth_relations) + 1):
        for combo in combinations(range(len(smooth_relations)), size):
            # Sum exponent vectors
            sum_vector = [0] * len(factor_base)
            for idx in combo:
                for j in range(len(factor_base)):
                    sum_vector[j] += exponent_vectors[idx][j]

            # Check if all even (congruence of squares)
            if all(v % 2 == 0 for v in sum_vector):
                print(f"Found dependency using relations: {combo}")

                # Compute x and y
                x_product = 1
                y_squared = 1

                for idx in combo:
                    x_val, q_val = smooth_relations[idx]
                    x_product = (x_product * x_val) % n
                    y_squared = (y_squared * abs(q_val)) % n

                # y_squared should be a perfect square
                y = math.isqrt(y_squared)

                print(f"  x = {x_product} (mod n)")
                print(f"  y = {y} (mod n)")

                # Try to factor using GCD
                factor1 = gcd(x_product - y, n)
                factor2 = gcd(x_product + y, n)

                if 1 < factor1 < n:
                    other_factor = n // factor1
                    print(f"\nSuccess! Found factors:")
                    print(f"  p = {factor1}")
                    print(f"  q = {other_factor}")
                    return factor1, other_factor

                if 1 < factor2 < n:
                    other_factor = n // factor2
                    print(f"\nSuccess! Found factors:")
                    print(f"  p = {factor2}")
                    print(f"  q = {other_factor}")
                    return factor2, other_factor

    print("Could not find factors with current relations")
    return None, None


def main():
    print("=" * 60)
    print("Baby RSA Breaking Example using Quadratic Sieve")
    print("=" * 60)
    print()

    # Use a small composite number for demonstration
    # This would normally be the RSA modulus n = p * q

    print("Example 1: Small composite number")
    print("-" * 60)
    n1 = 539873  # = 61 * 97 (two primes)
    p1, q1 = quadratic_sieve_simple(n1)
    if p1 and q1:
        print(f"Verification: {p1} * {q1} = {p1 * q1}")
        print(f"\nIf this was RSA modulus n:")
        print(f"  We've broken the encryption by finding p={p1} and q={q1}!")
        print(f"  We can now compute phi(n) = (p-1)(q-1) = {(p1-1)*(q1-1)}")
        print(f"  And derive the private key d from public exponent e")
    print()

    print("=" * 60)
    print("Key Insight:")
    print("The Quadratic Sieve finds numbers x where x^2 = y^2 (mod n)")
    print("Then GCD(x-y, n) or GCD(x+y, n) gives us a factor!")
    print()
    print("Note: This is a simplified baby version. Real QS implementations")
    print("use advanced techniques like sieving, Gaussian elimination, and")
    print("handle much larger numbers (100+ digits).")
    print("=" * 60)


if __name__ == "__main__":
    main()
