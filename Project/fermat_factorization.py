import math

def fermat_factorization(n: int, max_iterations: int = 10**7):
    """
    Classic Fermat factorization for odd composites where p ≈ q.

    Args:
        n: Composite integer to factor. Must be odd and non-square.
        max_iterations: Safety bound to prevent infinite loops.

    Returns:
        Tuple (p, q) if a factor pair is found, otherwise (None, None).
    """
    if n <= 0:
        raise ValueError("Input must be a positive integer.")
    if n % 2 == 0:
        return (2, n // 2) if n > 2 else (None, None)

    a = math.isqrt(n)
    if a * a < n:
        a += 1

    for _ in range(max_iterations):
        b_squared = a * a - n
        b = math.isqrt(b_squared)
        if b * b == b_squared:
            return a - b, a + b
        a += 1

    return None, None
