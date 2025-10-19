"""
Miller-Rabin Primality Test
A probabilistic algorithm to test whether a given number is prime.
Based on Fermat's Little Theorem and properties of composite numbers.
"""

import secrets

def miller_rabin(n, rounds=40):
    """
    Miller-Rabin primality test - a probabilistic algorithm for testing primality.

    The algorithm is based on the fact that for a prime p and any integer a:
    - Either a^d ≡ 1 (mod p), or
    - a^(2^i * d) ≡ -1 (mod p) for some 0 ≤ i < r
    where p - 1 = 2^r * d with d odd.

    If a number passes the test for multiple random bases (witnesses),
    it is very likely prime. If it fails once, it is definitely composite.

    Args:
        n: The number to test for primality
        rounds: Number of test rounds with different random witnesses (default 40)
                More rounds increase accuracy. With 40 rounds, error probability < 2^-80

    Returns:
        True if n is probably prime, False if n is definitely composite

    Time complexity: O(k * log³n) where k is the number of rounds
    """
    # Handle trivial cases
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:  # Even numbers (except 2) are not prime
        return False

    # Write n-1 as 2^r * d where d is odd
    # This factorization is used in the test
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Perform multiple rounds of testing with different random witnesses
    for _ in range(rounds):
        # Choose a random witness a in the range [2, n-2]
        a = secrets.randbelow(n - 3) + 2  # Random integer in [2, n-2]
        x = pow(a, d, n)  # Compute a^d mod n efficiently

        # If x = 1 or x = n-1, this witness passes (n might be prime)
        if x == 1 or x == n - 1:
            continue

        # Square x repeatedly r-1 times
        # If we find x ≡ -1 (mod n) at any point, this witness passes
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            # If we never found x ≡ -1 (mod n), n is composite
            return False

    # Passed all rounds: n is probably prime
    return True
