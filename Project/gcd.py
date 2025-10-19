# Implementation of the Euclidean algorithm to compute GCD
def gcd(a,b):
    m, n = a, b
    while n != 0:
        remainder = m % n
        m = n
        n = remainder
    return (m)