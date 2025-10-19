"""
RSA Cryptosystem Implementation
Educational implementation of the RSA public-key cryptosystem.
This demonstrates key generation, encryption, and decryption processes.
"""

import secrets
import miller_rabin
import egcd


def is_probably_prime(x, rounds=40):
    """
    Test if a number is probably prime using the Miller-Rabin primality test.

    Args:
        x: The number to test for primality
        rounds: Number of test rounds (higher = more accurate, default 40)

    Returns:
        True if x is probably prime, False if composite
    """
    return miller_rabin.miller_rabin(x, rounds)


def generate_random_number(bits):
    """
    Generate a cryptographically secure random number with the specified bit length.

    Args:
        bits: Number of bits for the random number

    Returns:
        A random integer with the specified bit length
    """
    return secrets.randbits(bits)


def generate_large_prime(bits=1024, attempts=10000):
    """
    Generate a large prime number with the specified bit length.
    Uses trial and error: generates random numbers and tests for primality.

    Args:
        bits: Bit length of the desired prime number (default 1024)
        attempts: Maximum number of attempts before giving up (default 10000)

    Returns:
        A large prime number with the specified bit length

    Raises:
        Exception if unable to generate a prime after the specified attempts
    """
    for _ in range(attempts):
        candidate = generate_random_number(bits)
        if is_probably_prime(candidate):
            return candidate

    raise f"Failed to generate probably prime number of length {bits} in {attempts} attempts."


def generate_prime_factors(factor_bits=1024, min_factor_delta_bits=256, attempts=10000):
    """
    Generate two large prime numbers (p and q) for RSA with sufficient difference.
    The primes must differ by at least min_factor_delta_bits to ensure security.

    Args:
        factor_bits: Bit length for each prime factor (default 1024)
        min_factor_delta_bits: Minimum bit length difference between p and q (default 256)
        attempts: Maximum attempts for generating each prime (default 10000)

    Returns:
        Tuple (p, q) of two sufficiently different prime numbers

    Raises:
        Exception if unable to generate suitable primes
    """
    while True:
        p = generate_large_prime(factor_bits, attempts)
        q = generate_large_prime(factor_bits, attempts)
        # Ensure p and q are sufficiently different to prevent factorization attacks
        if abs(p - q).bit_length() >= min_factor_delta_bits:
            return p, q
    raise f"Failed to generate two prime factors in {attempts} attempts."


def generate_public_exponent(p, q, attempts=1000):
    """
    Generate the public exponent (e) for RSA encryption.
    Must satisfy: 1 < e < φ(n) and gcd(e, φ(n)) = 1
    where φ(n) = (p-1)(q-1) is Euler's totient function.

    Args:
        p: First prime factor
        q: Second prime factor
        attempts: Maximum number of attempts to find valid exponent (default 1000)

    Returns:
        Public exponent e that is coprime with φ(n)

    Raises:
        Exception if unable to generate a valid public exponent
    """
    euler_totient = (p - 1) * (q - 1)

    # Choose a random number [a] such that GCD(a, phi(n)) = 1 and 1 < a < phi(n).
    # Additionally, let's make sure that [a] is at least [min_bits_for_exponent] long.
    for _ in range(attempts):
        a = generate_random_number(euler_totient.bit_length())

        # Verify the exponent is in the valid range
        if a <= 1 or a >= euler_totient:
            continue

        # Check if a is coprime with φ(n) using Extended Euclidean Algorithm
        # We only need GCD, but we can also run Extended GCD since that library is already available.
        gcd, _, _ = egcd.egcd(a, euler_totient)
        if gcd == 1:
            return a

    raise f"Failed to generate public exponent for p={p} and q={q}. Attempted {attempts} times."


def compute_private_exponent(a, p, q):
    """
    Compute the private exponent (d) for RSA decryption.
    Finds d such that: (a * d) ≡ 1 (mod φ(n))
    This means d is the modular multiplicative inverse of a modulo φ(n).

    Args:
        a: Public exponent
        p: First prime factor
        q: Second prime factor

    Returns:
        Private exponent d

    Raises:
        AssertionError if gcd(a, φ(n)) ≠ 1
    """
    phi = (p - 1) * (q - 1)
    # The Extended Euclidean Algorithm solves: tx + zy = GCD(t, z)
    # In our case: t=a and z=phi.
    # The solution for [x] is the private exponent.
    gcd, b, _ = egcd.egcd(a, phi)
    # Verify that a and φ(n) are coprime (required for valid RSA keys)
    assert(abs(gcd) == 1)

    # EEA may return a negative number, but we need a remainder, so we convert it to the positive number.
    if b < 0:
        return b + phi
    return b


def modular_exponent(x, a, n):
    """
    Compute (x^a) mod n efficiently using binary exponentiation.
    This is the core operation for both RSA encryption and decryption.
    Time complexity: O(log a)

    Args:
        x: Base value
        a: Exponent
        n: Modulus

    Returns:
        Result of (x^a) mod n
    """
    result = 1
    base = x % n
    exponent = a

    # Binary exponentiation: square and multiply algorithm
    while exponent > 0:
        # If current bit is 1, multiply result by current base
        if exponent % 2 == 1:
            result = (result * base) % n
        # Right shift exponent (divide by 2)
        exponent = exponent >> 1
        # Square the base for next iteration
        base = (base * base) % n

    return result


def encrypt(x, a, n):
    """
    Encrypt a message using RSA public key.
    Ciphertext = (plaintext^e) mod n

    Args:
        x: Plaintext message (as integer)
        a: Public exponent e
        n: Modulus (p * q)

    Returns:
        Encrypted ciphertext
    """
    return modular_exponent(x, a, n)


def decrypt(y, b, n):
    """
    Decrypt a ciphertext using RSA private key.
    Plaintext = (ciphertext^d) mod n

    Args:
        y: Ciphertext (as integer)
        b: Private exponent d
        n: Modulus (p * q)

    Returns:
        Decrypted plaintext
    """
    return modular_exponent(y, b, n)


"""
MAIN EXECUTION: RSA Key Generation and Demonstration
Demonstrates the complete RSA workflow from key generation to encryption/decryption.
"""

# Step 1: Generate RSA keys
# Use fewer bits for demonstration purposes because the numbers don't fit on the screen otherwise.
p, q = generate_prime_factors(factor_bits=1024, min_factor_delta_bits=32)
n = p * q  # Modulus: product of two primes
a = generate_public_exponent(p, q)  # Public exponent
b = compute_private_exponent(a, p, q)  # Private exponent

# Display generated keys
print("p = ", p)
print("q = ", q)
print("n = ", n)
print("e = ", a)
print("d = ", b)
print()
print(f"Public Key:")
print(f"  n={n}")
print(f"  e={a}")
print()
print(f"Private Key:")
print(f"  p={p}")
print(f"  q={q}")
print(f"  d={b}")
print()

# Step 2: Get user input for encryption
user_input = input("Enter text to encrypt: ")

# Step 3: Convert text to numerical representation
# Convert to ASCII, then to binary, concatenate, and convert to decimal
ascii_codes = [ord(char) for char in user_input]
binary_string = ''.join(format(code, '08b') for code in ascii_codes)
x = int(binary_string, 2)  # Final numerical representation of the message

print(f"\nASCII codes: {ascii_codes}")
print(f"Binary concatenated: {binary_string}")
print(f"Decimal representation: {x}")
print()

# Step 4: Encrypt and decrypt the message
# Encrypt the decimal number using public key (a, n)
y = encrypt(x, a, n)
# Decrypt the ciphertext using private key (b, n)
decrypted = decrypt(y, b, n)

print(f"Encrypted: {y}")
print(f"Decrypted: {decrypted}")
print()

# Step 5: Verify that decryption recovers the original message
assert(x == decrypted)
print("Encryption/Decryption successful!")