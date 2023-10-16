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

  JWT Terms and Concepts

JWT Terms and Concepts
----------------------

### 1\. JWT

**JWT**: Stands for **JSON Web Token**.

*   A compact, URL-safe means of representing claims to be transferred between two parties.
*   Commonly used for authentication and information exchange in web services.
*   Consists of three parts: header, payload, and signature.

### 2\. Header

The **header** typically consists of two parts:

*   **alg**: The algorithm used to sign the token, e.g., HMAC SHA256 or RSA.
*   **typ**: The type of token, which is JWT.

### 3\. Payload

The **payload** contains claims, which are statements about an entity (typically, the user) and additional data.

*   There are three types of claims: registered, public, and private claims.
*   **Registered claims**: A set of predefined claims like "iss" (issuer), "exp" (expiration time), and "sub" (subject).
*   **Public claims**: Claims that can be defined at will by those using JWTs.
*   **Private claims**: Claims used to share information between parties that agree on them and are not registered or public.

### 4\. Signature

To create the **signature** for the JWT:

*   The base64Url encoded header and payload are combined with a secret using the algorithm specified in the header.
*   The resulting signature is used to verify that the sender of the JWT is who they say they are and to ensure the message wasn't changed along the way.

### 5\. JWS & JWE

**JWS** and **JWE** are two common specifications related to JWT.

*   **JWS (JSON Web Signature)**: Provides a mechanism to represent content secured with digital signatures or Message Authentication Codes (MACs) using JSON data structures.
*   **JWE (JSON Web Encryption)**: Provides a mechanism to represent encrypted content using JSON data structures.

_JWTs are a powerful tool in modern web development, especially for Single Sign-On (SSO) and stateless authentication scenarios. However, they should be used carefully and securely, ensuring that sensitive data isn't exposed and best practices are followed._
