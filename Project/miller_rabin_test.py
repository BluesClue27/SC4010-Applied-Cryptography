import secrets 
import time

# list of first 99 prime numbers for trial division
prime_numbers = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 
    43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    101, 103, 107, 109, 113, 127, 131, 137, 139, 149,
    151, 157, 163, 167, 173, 179, 181, 191, 193, 197,
    199, 211, 223, 227, 229, 233, 239, 241, 251, 257,
    263, 269, 271, 277, 281, 283, 293, 307, 311, 313,
    317, 331, 337, 347, 349, 353, 359, 367, 373, 379,
    383, 389, 397, 401, 409, 419, 421, 433, 439, 443,
    449, 457, 461, 463, 467, 479, 487, 491, 499, 503,
    509, 521, 523, 541
]

def trial_division(n):
    for i in prime_numbers:
        if n % i == 0 and n != i:
            return False
    return True

def miller_rabin_test(n, rounds = 40):
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    
    r, d = 0, n - 1 
    while d % 2 == 0:
        r += 1
        d //= 2

    for i in range(rounds):
        # Miller Rabin witness generation
        a = secrets.randbelow(n-3) + 2
        x = pow(a,d,n)

        # the first iteration of x0 must be +-1 to be sure
        # its NOT a composite number
        # so we can continue to test the witness
        if x == 1 or x == n - 1:
            continue

        # We are looking for x^2 = 1 (mod n) with x != -1
        for j in range(r-1):
            x = pow(x,2,n)
            # if x = -1 (mod n), means this witness passed, does not prove n is composite
            if x == n-1:
                break
        else:
            # if we completed all r-1 rounds without finding x = -1 (mod n)
            # n is composite
            return False
    # the number n passed all 40 rounds of testing
    # it is probably prime  
    return True
        