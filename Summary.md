# Project Summary – Breaking SecureEncrypCompany’s RSA

## 1. Narrative Snapshot
- **Cast**: Bob (our protagonist) reviews SecureEncrypCompany’s “state-of-the-art” RSA-as-a-service before adopting it for his SaaS.
- **Vendor Pitch**: lightning-fast primes, blazing decryptions, gigantic public keys, Miller–Rabin “100% verified” primes.
- **Bob’s Instinct**: from SC4010 Applied Cryptography he knows speed often means shortcuts; he demands the source “per Kerckhoff’s principle” and discovers fatal flaws.
- **Your Role**: demonstrate those flaws by running and explaining the attacks that break SecureEncrypCompany’s RSA implementation.

## 2. Repository Layout (quick map)
- `README.md` – high-level storyline, vulnerability summary, secure RSA checklist.
- `Summary.md` – detailed guide to files, workflows, and attack strategy.
- `ResultsTemplate.md` – fill-in template for documenting experiment output.
- `Project/`
  - `rsa_weak_implementation.py` – insecure vendor code Bob received.
  - `claude_attacks_implementation.py` – Bob’s attack toolbox (Fermat, quadratic sieve demo, Wiener, Boneh–Durfee notes).
  - `miller_rabin_test.py`, `gcd.py`, `fermat_factorization.py` – number-theory helpers used by the weak implementation and attacks.
  - `test_verification.py` – quick calculations confirming just how weak the parameters are.
- `OnlineSrcCode/`
  - Clean reference RSA implementation (proper prime generation, EGCD, Miller–Rabin) plus lightweight tests.

## 3. Weak RSA Implementation (what to notice)
- **Close primes**: `Project/rsa_weak_implementation.py` grows `p` and `q` by scanning up/down by 2 from a shared seed – their difference is only 60.
- **Small private exponent**: a 256-bit `d` is chosen first to “speed up” decryptions; `e` becomes enormous as its modular inverse.
- **Non-standard `e`**: instead of 65537, `e` is essentially φ(N)/d. Oversized `e` offers no security benefit and leaks info.
- **Randomness**: the same secure RNG is used, but deterministic tweaking (±2) destroys independence.
- **Outcome**: design violates “random, independent primes” and “large private exponent” best practices. This is what you attack.

## 4. Attack Toolkit (Bob’s code)
| File / Function | What it proves | Key takeaway for your report |
| ---------------- | -------------- | ----------------------------- |
| `Project/claude_attacks_implementation.py::fermat_factorization` | Factors N when `p ≈ q` by walking up from √N until `a²-N` is a square. | Close primes fall instantly. Record recovered `(p,q)` and iteration count (printed). |
| `::quadratic_sieve_simple` | Educational sieve demonstrating general factoring. Optional; good talking point, not always needed. | Shows you understand broader factoring, even if full QS is skipped. |
| `::wiener_attack` | Uses continued fractions of `e/N` to recover small `d`. | Printout displays convergent index, recovered `d`, verification. Record whether `d < (1/3)·N^{1/4}`. |
| `::boneh_durfee_theory` | Narrative on lattice-based extension. | Cite it when discussing improvements over Wiener. |
| `::generate_vulnerable_rsa` | Recreates SecureEncrypCompany’s key generation, exposing bit lengths and gaps. | Use its output as the baseline numbers in your results. |

**Note**: The attacks print rich commentary so you can copy/paste evidence straight into a report.

## 5. Verification Helpers
- `Project/test_verification.py`: reuses one weak key to show `|p-q|`, `d` bit length, Wiener threshold, and verifies `e·d ≡ 1 (mod φ(N))`.
- `Project/fermat_factorization.py`: provides a reusable Fermat routine (updated to mirror the attack module) for smaller scripts/tests.
- `OnlineSrcCode/test.py`: quick sanity checks on prime samples (mostly for course demos).

## 6. Your Assignment Flow (step-by-step)
1. **Generate the weak key & run attacks**  
   `python Project/claude_attacks_implementation.py`  
   - Capture: displayed `p`, `q`, `N`, `e`, `d`, and bit lengths.  
   - Save Fermat and Wiener success messages (iterations, recovered `d`).  

2. **Log quantitative proof**  
   - Copy the numeric highlights into `ResultsTemplate.md`:  
     `|p-q|`, `|p-q|` bits; `d` bits vs `N` bits; Wiener threshold; whether Fermat/Wiener succeeded.  

3. **Optional deep-dive**  
   - Run `python Project/test_verification.py` to confirm threshold math.  
   - (If time) execute `quadratic_sieve_simple` manually for narrative completeness or mention it as “skipped for time” like the script does.

4. **Present findings**  
   - Tie each exploit to SecureEncrypCompany’s marketing claims (fast primes → close primes; fast decrypt → tiny `d`; huge `e` → derived from tiny `d`).  
   - Reference Boneh’s “Twenty Years of Attacks on the RSA Cryptosystem” for credibility.

## 7. Quick Reference – Questions you should be able to answer
1. *Why do close primes break RSA?*  
   Because N = a² − b² when `p ≈ q`, allowing Fermat to factor N in O(|p−q|) steps.
2. *What range must `d` stay above?*  
   For 2048-bit RSA, `d` must exceed approximately `(1/3)·N^{1/4}`; 2048-bit N implies a threshold around 512 bits—your 256-bit `d` fails badly.
3. *Does a huge `e` improve security?*  
   No. `e` is reduced modulo φ(N) during operations; giant `e` only shows that `d` is tiny.
4. *How does Kerckhoff’s principle apply?*  
   Security should not depend on hiding algorithms; even with full source, RSA is safe *if* parameters are generated correctly.
5. *What best practices fix the issues?*  
   Independent random primes, standard `e = 65537`, large `d ≈ φ(N)`, padding schemes, constant-time operations.

## 8. Extra Tips
- Keep raw outputs for your appendix—the scripts already narrate each step.
- Highlight original work: the attack script formatting, helper functions, and verification calculations are yours; be ready to explain them live.
- Mention that Quadratic Sieve and Boneh–Durfee are included to show breadth, even if the main break relies on Fermat + Wiener.

You now have a step-by-step path: run the attacks, capture the numbers, fill the template, and present the story. Good luck breaking SecureEncrypCompany’s “secure” RSA!
