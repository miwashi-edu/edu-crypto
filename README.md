# edu-crypto

## Hashing ( with brute force attack )

> MD5 is a widely used cryptographic hash function that produces a 128-bit hash value.
> It is commonly used to check data integrity.
> HOWEVER, MD5 is NOT suitable for further security purposes as it is vulnerable to hash collisions.
> This means that different input values can produce the same hash output, which is a major vulnerability.
> const secretHash = crypto.createHash('md5').update(password).digest('hex');

> SHA-512 is a member of the SHA-2 cryptographic hash functions family.
> It produces a 512-bit hash value, which is typically rendered as a 128-character hex number.
> It's more secure than MD5 and is suitable for further security purposes.

```js
const crypto = require('crypto');
const bf = require('bruteforce');

const password = "abaa";
const secretHash = crypto.createHash('sha512').update(password).digest('hex');

const hack = (attemptedPassword) => {
  // Avoid MD5 for the same reasons mentioned above.
  // const hash = crypto.createHash('md5').update(attemptedPassword).digest('hex');
  // Use SHA-512 for better security.
  const hash = crypto.createHash('sha512').update(attemptedPassword).digest('hex');
  
  console.log(`Trying password: ${attemptedPassword}, Match: ${secretHash === hash}`);
  
  if (secretHash === hash) {
    console.log(`Password found: ${attemptedPassword}`);
    process.exit();  // Stop the process once password is found
  }
}

bf({
  len: password.length,
  chars: ['a', 'b'],
  step: hack
});
```
  Hashing Terms and Concepts

Hashing Terms and Concepts
--------------------------

### 1\. Hash Function

**Hash Function**:

*   A function that takes in an input (or 'message') and returns a fixed-size string, which typically looks random.
*   The output is commonly referred to as the hash code or simply the hash.
*   Any change to the input, even a minor one, will produce a significantly different hash.

### 2\. Cryptographic Hash Function

A special class of hash functions with specific properties making them suitable for use in cryptography. Features include:

*   Irreversibility: It's computationally infeasible to generate the original input value given the hash output. This ensures confidentiality.
*   Deterministic: The same input will always produce the same hash output.
*   Fast to compute: Efficient computation of the hash value for any given input.
*   Pre-image resistant: Given a hash, it's computationally difficult to find an input that hashes to that value.
*   Collision resistant: It's hard to find two different inputs that produce the same hash.

### 3\. Salting

**Salting**:

*   A technique used to safeguard passwords in storage.
*   Random data (the salt) is generated and combined with the password before hashing.
*   The salt is then stored with the hash, allowing the hash+salt combination to be verified against future login attempts.
*   Salting ensures that even if two users have the same password, their hashes will be different due to the unique salts.

### 4\. Rainbow Table

**Rainbow Table**:

*   A precomputed table used for reversing cryptographic hash functions.
*   Designed to crack password hashes by looking up the hash in the table and, if found, the associated password is revealed.
*   Salting hash functions can mitigate the effectiveness of rainbow tables.

### 5\. Hash Algorithms

Commonly used cryptographic hash algorithms include:

*   MD5 (Message Digest Algorithm 5): Fast but considered insecure due to vulnerabilities.
*   SHA-1 (Secure Hash Algorithm 1): Previously widely used, but now also considered insecure for many cryptographic purposes.
*   SHA-256, SHA-384, and SHA-512: Part of the SHA-2 family, they're currently considered secure and are used in various security protocols and systems.

_Hashing is a fundamental concept in computer science and cryptography. Properly understanding and implementing hashing techniques can be crucial for data integrity and security._
