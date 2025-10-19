import secrets
from miller_rabin_test import miller_rabin_test
from gcd import gcd

# test for primality using Miller-Rabin test
def is_probably_prime(x, rounds=40):
    return miller_rabin_test(x, rounds)

# randomly generate a number with specified bit length
def generate_random_number(bits):
    return secrets.randbits(bits)

# generate a large prime number with specified bit length
# test for primality using Miller-Rabin test
def generate_large_prime(bits=1024,attempts=10000):
    for _ in range(attempts):
        candidate = generate_random_number(bits)
        if is_probably_prime(candidate):
            return candidate
    
# generate two large prime numbers p and q for RSA
def generate_prime_factors(factor_bits=1024, min_factor_delta_bits=256):
    while True:
        p = generate_large_prime(factor_bits)
        q = generate_large_prime(factor_bits)
        if abs(p - q).bit_length() >= min_factor_delta_bits:
            return p, q
        
# generate a random public exponent e for RSA
# instead of using common value 65537
def generate_public_exponent_e(phi_n,attempts=10000):

    for _ in range(attempts):
        e = generate_random_number(phi_n.bit_length())

        # recompute public exponent e until 1 < e < phi_n
        if e <=1 or e >= phi_n:
            continue

        # check gcd(e,phi_n) == 1 to ensure inverse exists
        if gcd(e, phi_n) == 1:
            return e

# compute private exponent d for RSA
# have to implement check for d < (1/3) * N^(1/4) to avoid small d attacks
def compute_private_exponent_d(e, phi_n):
    d = pow(e, -1, phi_n)

    if d < 0:
        return d + phi_n
    return d

def modular_exponent(x,a,n):
    result = 1
    base = x % n
    exponent = a

    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % n

        exponent = exponent >> 1
        base = (base * base) % n 
    
    return result

def encrypt_message(m, e, n):
    return modular_exponent(m, e, n)

def decrypt_message(c, d, n):
    return modular_exponent(c, d, n)

p, q = generate_prime_factors(factor_bits=1024, min_factor_delta_bits=256)
n = p * q
phi_n = (p - 1) * (q - 1)
e = generate_public_exponent_e(phi_n)
# e = 65537  # alternatively, use common public exponent
# can implement check for small d attacks here as well
d = compute_private_exponent_d(e, phi_n)

print("p = ", p)
print("q = ", q)
print("n = ", n)
print("phi_n = ", phi_n)
print("e = ", e)
print("d = ", d)
print()
print(f"Public Key:")
print(f"  n={n}")
print(f"  e={e}")
print()
print(f"Private Key:")
print(f"  p={p}")
print(f"  q={q}")
print(f"  d={d}")
print()

user_input = input("Enter text to encrypt: ")

ascii_codes = [ord(char) for char in user_input]
binary_string = ''.join(format(code, '08b') for code in ascii_codes)
plaintext_m = int(binary_string, 2)

print(f"\nASCII codes: {ascii_codes}")
print(f"Binary concatenated: {binary_string}")
print(f"Decimal representation: {plaintext_m}")
print()

ciphertext_c = encrypt_message(plaintext_m, e, n)
original_message_m = decrypt_message(ciphertext_c, d, n)
    
print(f"Encrypted: {ciphertext_c}")
print(f"Decrypted: {original_message_m}")
print()