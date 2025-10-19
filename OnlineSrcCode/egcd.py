"""
Extended Euclidean Algorithm (EGCD)
Computes the greatest common divisor (GCD) and the coefficients of Bézout's identity.
Used in RSA to compute the modular multiplicative inverse for the private key.
"""

def egcd(a, b):
    """
    Extended Euclidean Algorithm (iterative implementation).

    Computes integers x and y such that:
        a*x + b*y = gcd(a, b)

    This is known as Bézout's identity. The algorithm extends the standard
    Euclidean algorithm by keeping track of the coefficients in the linear
    combination at each step.

    In RSA, this is used to find the modular multiplicative inverse:
    If gcd(a, b) = 1, then x is the multiplicative inverse of a modulo b,
    meaning: a*x ≡ 1 (mod b)

    Args:
        a: First integer
        b: Second integer

    Returns:
        Tuple (gcd, x, y) where:
        - gcd: Greatest common divisor of a and b
        - x: Coefficient for a in Bézout's identity
        - y: Coefficient for b in Bézout's identity

    Example:
        egcd(240, 46) returns (2, -9, 47) because:
        240*(-9) + 46*47 = -2160 + 2162 = 2 = gcd(240, 46)

    Time complexity: O(log(min(a, b)))
    """
    # Initialize coefficients for the linear combination
    # At each step: a = x0*a_orig + y0*b_orig
    #               b = x1*a_orig + y1*b_orig
    x0, x1, y0, y1 = 1, 0, 0, 1

    # Apply the Euclidean algorithm while tracking coefficients
    while b != 0:
        # Compute quotient and perform division step
        q, a, b = a // b, b, a % b

        # Update x coefficients: new_x = old_x - quotient * new_x
        x0, x1 = x1, x0 - q * x1

        # Update y coefficients: new_y = old_y - quotient * new_y
        y0, y1 = y1, y0 - q * y1

    # When b becomes 0, a contains the GCD, and x0, y0 are the coefficients
    return (a, x0, y0)
