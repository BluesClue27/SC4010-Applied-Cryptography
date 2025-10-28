# SC4010 Applied Cryptography – Breaking SecureEncrypCompany’s RSA

## Storyline: Bob vs SecureEncrypCompany
- Bob is ready to ship his SaaS and outsources RSA to “SecureEncrypCompany”, a vendor boasting lightning‑fast primes, blazing decryption, and a huge public exponent.
- His SC4010 Applied Cryptography instincts scream *red flag*: fast primes → likely related `p` and `q`; fast decryption + giant `e` → probably a tiny `d`.
- The vendor quotes Kerckhoff’s principle and hands over the source. Bob reverse-engineers it and prepares a demo to prove the system is fatally weak.

## Repository Map
- `Project/rsa_weak_implementation.py` – vendor’s flawed RSA: primes grown from the same seed, 256‑bit private exponent chosen first, enormous public exponent derived afterward.
- `Project/claude_attacks_implementation.py` – Bob’s attack suite (Fermat factorization, simplified quadratic sieve, Wiener attack, Boneh–Durfee overview) with rich console narration.
- `Project/test_verification.py` – sanity checks showing how the weak parameters violate Wiener’s threshold and expose close primes.
- `OnlineSrcCode/` – baseline “good” RSA implementation from course material (clean Miller–Rabin, EGCD, interactive demo).
- Top-level helpers (`gcd.py`, `miller_rabin_test.py`, etc.) – supporting algorithms reused across scripts.

## Weak RSA Findings (ordered by exploitability)
- **CRITICAL – Close primes (`|p-q| = 60 ≈ 2⁶`)**: incremental search around a single seed yields adjacent primes. Fermat’s method recovers `p` and `q` in milliseconds (`Project/rsa_weak_implementation.py`).
- **HIGH – Small private exponent (`d = 256` bits vs. `N ≈ 2047` bits)**: well below Wiener’s bound `d < (1/3)·N^{1/4}`, so continued fractions recover `d` immediately (`Project/test_verification.py`).
- **MEDIUM – Oversized public exponent (`e ≈ 2048` bits)**: derived as the inverse of the tiny `d`, offers no extra security and invites efficiency issues; can be reduced modulo φ(N) with trivial effort.

Fast does **not** mean secure—weak randomness, related primes, and tiny `d` break Kerckhoff’s promise.

## Attack Toolkit
1. **Fermat Factorization** – exploits `p ≈ q`; implemented with progress reporting and security metrics.
2. **Quadratic Sieve (educational)** – demonstrates general-purpose factoring concepts for when primes are not close.
3. **Wiener’s Attack** – continued fraction analysis to recover a small `d` in polynomial time.
4. **Boneh–Durfee Summary** – theoretical extension covering lattice-based improvements when `d ≤ N^{0.292}`.

Run the full narrative with:

```bash
python Project/claude_attacks_implementation.py
```

The script prints the weak parameters, cracks them, and reiterates the security lessons.

## Quantitative Snapshot
- Generated modulus `N`: 2047-bit composite.
- Private exponent `d`: 256 bits (≈ 8× smaller than Wiener’s safe region).
- Prime gap `|p-q|`: 60 (only 6 bits), so Fermat succeeds after ~60 iterations.
- “Fast” key generation and decryption arise solely from these insecure choices.

## Secure RSA Checklist
- Generate `p` and `q` independently with a CSPRNG; enforce `|p-q| > 2^{n/2 - 100}`.
- Use the standard public exponent `e = 65537` unless there is a compelling, vetted reason not to.
- Ensure `d` is large (≈ φ(N)), and validate against Wiener/Boneh–Durfee bounds.
- Apply padding (e.g., OAEP), constant-time operations, and safe message encoding for real deployments.

## References & Further Reading
- Dan Boneh, “Twenty Years of Attacks on the RSA Cryptosystem”.
- SC4010 Applied Cryptography lecture notes (Weeks 8–9).
- Course attack demos retained in `Project/claude_attacks_implementation.py` – be ready to walk through the code; it is your own work.
