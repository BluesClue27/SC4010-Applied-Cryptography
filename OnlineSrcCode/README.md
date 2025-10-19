# Learning Cryptography through Toy Implementations

<i>This repository contains toy implementations of various cryptographic systems.</i><br>
<i>These implementations are only intended for educational purposes and are not suitable for production.</i>

### Why learn about cryptography?

- It is used to preserve the integrity and confidentiality of sensitive information.
- Cryptography is used for critical tasks such as online banking.
- A large part of ensuring secure communication is done using Cryptographic primitives.
- Encryption systems like email security and file security widely use asymmetrical cryptography.

---

## Project Structure

This implementation demonstrates the RSA cryptosystem through several modules:

### Core Files

- **`rsa.py`** - Main RSA implementation
  - RSA key generation (public and private keys)
  - Prime number generation for RSA factors
  - Encryption and decryption using modular exponentiation
  - Text-to-numerical conversion for message encryption
  - Interactive demonstration of the complete RSA workflow

- **`miller_rabin.py`** - Miller-Rabin Primality Test
  - Probabilistic algorithm for testing whether a number is prime
  - Uses multiple rounds of testing with random witnesses
  - Essential for generating large prime numbers for RSA
  - Default 40 rounds provides error probability < 2^-80

- **`egcd.py`** - Extended Euclidean Algorithm
  - Computes the greatest common divisor (GCD) of two numbers
  - Finds coefficients for Bézout's identity: `a*x + b*y = gcd(a, b)`
  - Used to compute the modular multiplicative inverse
  - Critical for generating RSA private keys

### Key Concepts Demonstrated

1. **Prime Generation**: Uses Miller-Rabin test to generate large probable primes
2. **Key Generation**:
   - Generates two large primes (p, q)
   - Computes modulus n = p * q
   - Calculates Euler's totient φ(n) = (p-1)(q-1)
   - Selects public exponent e coprime with φ(n)
   - Computes private exponent d as modular inverse of e
3. **Encryption**: Ciphertext = plaintext^e mod n
4. **Decryption**: Plaintext = ciphertext^d mod n
5. **Efficiency**: Binary exponentiation for fast modular exponentiation

---

## How to Run the Script

This is the source code used in [**<i>How RSA Cryptosystem WORKS - Intuitive approach</i>**](https://youtu.be/nvcssTsiavg)<br>
Please refer to the blog post for notes and concepts discussed in the video [**<i>How RSA Works</i>**](https://techwithnikola.com/blog/cryptography/how-rsa-works/)

### 1. Create a Virtual Environment (optional but recommended)
- Install a venv manager such as [`virtualenv`](https://github.com/pypa/virtualenv)
- Run `virtualenv .venv`
- Activate the environment:
  - **Bash/Linux/Mac**: `source .venv/bin/activate`
  - **Windows (cmd)**: `.venv\Scripts\activate.bat`
  - **Windows (PowerShell)**: `.venv\Scripts\Activate.ps1`

### 2. Install the Dependencies
```shell
pip install -r requirements.txt
```

### 3. Run the Script
```shell
python rsa.py
```

The script will:
1. Generate RSA keys (p, q, n, public exponent, private exponent)
2. Display the generated keys
3. Prompt you to enter text to encrypt
4. Show the conversion process (text → ASCII → binary → decimal)
5. Encrypt the message using the public key
6. Decrypt the ciphertext using the private key
7. Verify that decryption recovers the original message

---

## Security Notice

⚠️ **WARNING**: This is an educational implementation only. It is NOT secure for production use.

**Known limitations:**
- Uses smaller key sizes for demonstration (1024-bit factors)
- No padding scheme (vulnerable to various attacks)
- No constant-time operations (vulnerable to timing attacks)
- Simplified random number generation
- Converts entire messages to single large numbers (impractical for long messages)
- No proper error handling for edge cases

**For production systems**, use established cryptographic libraries such as:
- Python: `cryptography` library or `PyCryptodome`
- OpenSSL
- LibreSSL
- BoringSSL

---

## Educational Value

This implementation helps understand:
- The mathematical foundations of RSA
- Why prime numbers are crucial for public-key cryptography
- How modular arithmetic enables asymmetric encryption
- The role of Euler's totient function
- Importance of the Extended Euclidean Algorithm
- Primality testing with probabilistic algorithms
- Efficient modular exponentiation techniques

---

## License

Educational use only. Not suitable for production environments.
