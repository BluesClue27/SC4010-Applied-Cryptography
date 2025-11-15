import time
from fermat_factorization import fermat_factorization
from gcd import gcd
import values

print("=" * 60)
print("RSA Breaking Attack using Fermat Factorization")
print("=" * 60)
print()

print("Public Key (Known):")
print(f"  n = {values.n}")
print(f"  e = {values.e}")
print()

print("Actual Private Key (for verification):")
print(f"  p = {values.p}")
print(f"  q = {values.q}")
print(f"  d = {values.d}")
print()

# Perform Fermat Factorization Attack
print("=" * 60)
print("Performing Fermat Factorization Attack...")
print("=" * 60)

start_time = time.time()
p_recovered, q_recovered = fermat_factorization(values.n)
end_time = time.time()

if p_recovered and q_recovered:
    print(f"\nFactorization successful!")
    print(f"Time taken: {end_time - start_time:.6f} seconds")
    print()

    print("Recovered factors:")
    print(f"  p_recovered = {p_recovered}")
    print(f"  q_recovered = {q_recovered}")
    print()

    # Verify the factors are correct
    if p_recovered * q_recovered == values.n:
        print("Verification: p_recovered * q_recovered == n")
    else:
        print("Verification: FAILED")

    # Check if we recovered the correct primes
    if (p_recovered == values.p and q_recovered == values.q) or \
       (p_recovered == values.q and q_recovered == values.p):
        print("Recovered the correct prime factors!")
    else:
        print("Warning: Recovered different factors than original")
    print()

    # Recover the private exponent d
    phi_n_recovered = (p_recovered - 1) * (q_recovered - 1)

    # Check if e and phi_n are coprime
    if gcd(values.e, phi_n_recovered) == 1:
        d_recovered = pow(values.e, -1, phi_n_recovered)

        print("Recovered private exponent:")
        print(f"  d_recovered = {d_recovered}")
        print()

        # Verify d is correct
        if d_recovered == values.d:
            print("Successfully recovered the private key! ")

    else:
        print("Error: gcd(e, phi_n) != 1, cannot compute d")
else:
    print("\nFactorization failed!")
    print(f"Time taken: {end_time - start_time:.6f} seconds")
    print("Fermat's method did not find factors within the iteration limit.")

print()
print("=" * 60)
