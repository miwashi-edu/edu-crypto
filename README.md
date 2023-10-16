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

