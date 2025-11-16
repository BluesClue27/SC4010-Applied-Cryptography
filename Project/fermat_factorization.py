import math

def fermat_factorization(n, max_iterations=10**7):
    if n % 2 == 0:
        return (2, n // 2) if n > 2 else (None, None)

    a = math.isqrt(n)
    if a * a < n:
        a += 1

    for _ in range(max_iterations):
        b_squared = (a * a) - n
        b = math.isqrt(b_squared)
        if b * b == b_squared:
            return a - b, a + b
        a += 1

    return None, None


