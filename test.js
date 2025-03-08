import QuantumMeshEncryptionV2 from './qmesh.js';
const qme = new QuantumMeshEncryptionV2();
const password = 'SuperSecurePass!';
const originalData = 'Confidential Data';

(async () => {
    console.log("=== QuantumMeshEncryptionV2 Test ===");
    
    // 🔐 Encrypt Data (Fast Mode)
    const encryptedFast = qme.Encrypt(originalData, "fast");
    console.log("\n🔐 Encrypted (Fast Mode):", encryptedFast);
    
    // 🔓 Decrypt Data (Fast Mode)
    const decryptedFast = qme.Decrypt(encryptedFast.encryptedAES, null, encryptedFast.keys);
    console.log("🔓 Decrypted (Fast Mode):", decryptedFast);
    
    // 🔐 Encrypt Data (Ultra Secure Mode)
    const encryptedUltra = qme.Encrypt(originalData, "ultra_secure");
    console.log("\n🔐 Encrypted (Ultra Secure Mode):", encryptedUltra);
    
    // 🔓 Decrypt Data (Ultra Secure Mode)
    const decryptedUltra = qme.Decrypt(encryptedUltra.encryptedAES, encryptedUltra.encryptedChaCha, encryptedUltra.keys);
    console.log("🔓 Decrypted (Ultra Secure Mode):", decryptedUltra);
    
    // 🔐 Encrypt with Compression
    const compressedEncrypted = qme.EncryptWithCompression(originalData, "fast");
    console.log("\n🔐 Encrypted with Compression:", compressedEncrypted);
    
    // 🔓 Decrypt with Decompression
    const decompressedDecrypted = qme.DecryptWithCompression(compressedEncrypted.encryptedAES, null, compressedEncrypted.keys);
    console.log("🔓 Decrypted with Decompression:", decompressedDecrypted);
    
    // 🔐 Hash Password
    const hashedPassword = await qme.Hash(password);
    console.log("\n🔐 Hashed Password:", hashedPassword);
    
    // ✅ Verify Password
    const isMatch = await qme.VerifyPass(password, hashedPassword);
    console.log("✅ Password Match:", isMatch ? "Yes" : "No");
    
    // 🔑 Generate ECC Keys
    const eccKeys = qme.genecc();
    console.log("\n🔑 ECC Key Pair:", eccKeys);
    
    // 🔑 Generate Shared ECC Key
    const sharedKey = qme.ShareKey(eccKeys.privateKey, eccKeys.publicKey);
    console.log("🔑 Shared ECC Key:", sharedKey);
})();