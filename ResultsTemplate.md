# Attack Results Template

> Use this worksheet for each demo run. Copy the sections you need into your report or notes.

## 1. Run Metadata
- Date / Time:
- Script version (git commit / tag):
- Command executed (include arguments):
- Random seed (if set):

## 2. Weak RSA Parameters
| Item | Value | Notes |
| --- | --- | --- |
| Modulus bit length (`N.bit_length()`) |  |  |
| Public exponent bit length (`e.bit_length()`) |  | Expect 17 bits for secure RSA (`e = 65537`) |
| Private exponent bit length (`d.bit_length()`) |  | Compare with Wiener threshold |
| φ(N) bit length (`phi_n.bit_length()`) |  |  |
| Prime gap `|p - q|` |  |  |
| Prime gap bit length |  | Should exceed `n/2 - 100` bits |

## 3. Fermat Factorization
- Success (Y/N):
- Recovered factors: `p = ` ________, `q = ` ________
- Iterations reported:
- Time reported:
- Verification (`p * q == N`): 
- Observations (e.g., why gap was small):

## 4. Wiener Attack
- Success (Y/N):
- Recovered `d` = 
- Wiener threshold `n^(1/4) / 3` =  (bits = )
- `(e * d) mod φ(N)` = 
- Notes (e.g., convergent index, ratio `d / N^0.25`):

## 5. Quadratic Sieve (optional)
- Was the demo executed? (Y/N):
- Outcome / recovered factors:
- Any performance notes:

## 6. Boneh–Durfee Talking Points
- Key takeaway to mention:
- References cited:

## 7. Screenshots / Transcript References
- Fermat output snippet:
- Wiener output snippet:
- Additional logs:

## 8. Lessons / Follow-up
- How SecureEncrypCompany could fix the issue:
- Questions for teammates or instructor:
- Next experiments to run:
