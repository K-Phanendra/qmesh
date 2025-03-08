# QuantumMeshEncryptionV2 🔒⚡

**QuantumMeshEncryptionV2** is an advanced encryption library that provides AES-GCM, ChaCha20-Poly1305, and ECC key exchange with adaptive encryption and compression.

## 🚀 Features
- **AES-256-GCM & ChaCha20-Poly1305** encryption.
- **Adaptive encryption** (Fast & Ultra Secure modes).
- **Password hashing & verification** using Argon2.
- **ECC Key Exchange** for secure shared key generation.
- **Data compression** before encryption.

## 📦 Installation  
```sh
npm install qmesh
```

## 📜 Dependencies
- **crypto** (Node.js built-in module)
- **argon2** (For password hashing)
- **zlib** (Node.js built-in module for compression)

## 🛠️ Usage  

### **1. Import the Library**
```js
import QuantumMeshEncryptionV2 from 'qmesh';
```

### **2. Encrypt & Decrypt Data**
```js
const qme = new QuantumMeshEncryptionV2();
const keys = qme.genkey();
const encrypted = qme.encryptAES("Hello, World!", keys.aesKey, keys.iv);
const decrypted = qme.decryptAES(encrypted, keys.aesKey, keys.iv);

console.log("Encrypted:", encrypted);
console.log("Decrypted:", decrypted);
```

### **3. Password Hashing & Verification**
```js
const hashedPassword = await qme.Hash("mysecurepassword");
const isValid = await qme.VerifyPass("mysecurepassword", hashedPassword);
console.log("Password is valid:", isValid);
```

### **4. ECC Key Exchange**
```js
const aliceKeys = qme.genecc();
const bobKeys = qme.genecc();
const sharedKey = qme.ShareKey(aliceKeys.privateKey, bobKeys.publicKey);
console.log("Shared Secret:", sharedKey);
```

## 🔍 Comparison: V1 vs V2

| Feature | V1 | V2 |
|---------|----|----|
| AES-256-GCM | ✅ | ✅ |
| ChaCha20-Poly1305 | ✅ | ✅ |
| Adaptive Encryption Modes | ❌ | ✅ (Fast & Ultra Secure) |
| Data Compression Before Encryption | ❌ | ✅ |
| Password Hashing (Argon2) | ✅ | ✅ |
| ECC Key Exchange | ✅ | ✅ |
| Secure Key Storage | ❌ | ✅ |

## 🔗 License
This project is licensed under the **MIT License**.

