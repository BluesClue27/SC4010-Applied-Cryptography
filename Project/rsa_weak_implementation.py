import secrets
import time
from miller_rabin_test import miller_rabin_test, trial_division
from gcd import gcd

# test for primality using Miller-Rabin test
def is_probably_prime(x, rounds=40):
    if not trial_division(x):
        # print("Failed trial division")
        return False
    if not miller_rabin_test(x, rounds):
        # print("Failed Miller-Rabin test")
        return False
    return True

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
def generate_prime_factors_up(value):
    p = value
    while True:
        p += 2
        if is_probably_prime(p):
            return p
        
def generate_prime_factors_down(value):
    q = value
    while True:
        q -= 2
        if is_probably_prime(q):
            return q
        
# generate a random public exponent e for RSA
# instead of using common value 65537
def generate_private_exponent_d(phi_n,attempts=10000):

    for _ in range(attempts):
        # generate a random private exponent d which is small
        # fast decryption
        d = generate_random_number(256)

        # recompute public exponent d until 1 < d < phi_n
        if d <=1 or d >= phi_n:
            continue

        # check gcd(d,phi_n) == 1 to ensure inverse exists
        if gcd(d, phi_n) == 1:
            return d

# compute private exponent d for RSA
# have to implement check for d < (1/3) * N^(1/4) to avoid small d attacks
def compute_public_exponent_e(d, phi_n):
    e = pow(d, -1, phi_n)

    if e < 0:
        return e + phi_n
    return e

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

value = generate_large_prime(bits=1024)
p = generate_prime_factors_up(value)
q = generate_prime_factors_down(value)
n = p * q
phi_n = (p - 1) * (q - 1)
d = generate_private_exponent_d(phi_n)
e = compute_public_exponent_e(d, phi_n)
#e = 65537  # alternatively, use common public exponent

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