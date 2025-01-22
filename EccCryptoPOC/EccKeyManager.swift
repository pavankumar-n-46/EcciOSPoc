//
//  ECCKeyManager.swift
//  EccCryptoPOC
//
//  Created by Pavan Kumar N on 21/01/25.
//

import Security
import CryptoKit
import Foundation

enum CryptoError: Error {
    case keyGenerationFailed
    case encryptionFailed
    case decryptionFailed
    case signatureGenerationFailed
    case signatureVerificationFailed
    case keyRetrievalFailed
}

class ECCKeyManager {
    private let keyAgreementTag = "\(Bundle.main.bundleIdentifier ?? "my_app").eccAgreementKey"
    private let signingKeyTag = "\(Bundle.main.bundleIdentifier ?? "my_app").eccSigningKey"
    private let sharedSecretTag = "\(Bundle.main.bundleIdentifier ?? "my_app").sharedSecret"

    private var privateAgreementKey: P256.KeyAgreement.PrivateKey?
    private var privateSigningKey: P256.Signing.PrivateKey?

    init() {
        self.privateAgreementKey = getOrCreateAgreementKey()
        self.privateSigningKey = getOrCreateSigningKey()
    }

    // MARK: - Key Storage in Keychain
    /// Saves a private key to the Keychain
    private func savePrivateKey(_ key: Data, tag: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag as String: tag,
            kSecValueData as String: key,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock
        ]

        // Delete old key before saving new one
        SecItemDelete(query as CFDictionary)
        SecItemAdd(query as CFDictionary, nil)
    }

    /// Loads a private key from the Keychain
    private func loadPrivateKey(tag: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag as String: tag,
            kSecReturnData as String: true
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        if status == errSecSuccess, let keyData = result as? Data {
            return keyData
        }
        return nil
    }

    // MARK: - Key Agreement (ECDH)

    /// Generates or retrieves a private key for ECDH key agreement
    private func getOrCreateAgreementKey() -> P256.KeyAgreement.PrivateKey {
        if let keyData = loadPrivateKey(tag: keyAgreementTag),
           let key = try? P256.KeyAgreement.PrivateKey(rawRepresentation: keyData) {
            return key
        } else {
            let newKey = P256.KeyAgreement.PrivateKey()
            savePrivateKey(newKey.rawRepresentation, tag: keyAgreementTag)
            return newKey
        }
    }

    /// Returns the public key for key agreement (ECDH)
    func getAgreementPublicKey() -> Data {
        return privateAgreementKey!.publicKey.compressedRepresentation
    }

    /// Helper function to encode the public key into a Base64 string
    func encodePublicKeyToBase64() -> String {
        let publicKeyData = getAgreementPublicKey()
        let base64Key = publicKeyData.base64EncodedString()
        log("Public Key (Base64): \(base64Key)")
        return base64Key
    }

    /// Derives a shared secret using ECDH key agreement
    func deriveSharedSecret(peerPublicKey: P256.KeyAgreement.PublicKey) -> SymmetricKey? {
        guard let privateKey = privateAgreementKey else { return nil }

        do {
            let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: peerPublicKey)
            return sharedSecret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: Data(), sharedInfo: Data(), outputByteCount: 32)
        } catch {
            log("Key Agreement failed: \(error)")
            return nil
        }
    }

    // Method to save the shared secret in the Keychain
    func saveSharedSecret(_ secret: Data) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: sharedSecretTag,
            kSecValueData as String: secret,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock
        ]

        // Delete the existing secret if it exists
        SecItemDelete(query as CFDictionary)

        // Save the new shared secret to the Keychain
        let status = SecItemAdd(query as CFDictionary, nil)
        if status == errSecSuccess {
            log("Shared secret saved successfully.")
        } else {
            log("Error saving shared secret: \(status)")
        }
    }

    // Method to load the shared secret from the Keychain
    func loadSharedSecret() -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: sharedSecretTag,
            kSecReturnData as String: true,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        if status == errSecSuccess, let secretData = result as? Data {
            return secretData
        } else {
            log("Error loading shared secret: \(status)")
            return nil
        }
    }

    // MARK: - Signing (ECDSA)

    /// Generates or retrieves a private key for signing (ECDSA)
    private func getOrCreateSigningKey() -> P256.Signing.PrivateKey {
        if let keyData = loadPrivateKey(tag: signingKeyTag),
           let key = try? P256.Signing.PrivateKey(rawRepresentation: keyData) {
            return key
        } else {
            let newKey = P256.Signing.PrivateKey()
            savePrivateKey(newKey.rawRepresentation, tag: signingKeyTag)
            return newKey
        }
    }

    /// Returns the public key for verification
    func getSigningPublicKey() -> P256.Signing.PublicKey {
        return privateSigningKey!.publicKey
    }

    /// Export the public key as a Base64-encoded string
    func exportSigningPublicKey() -> String {
        return getSigningPublicKey().derRepresentation.base64EncodedString()
    }


    /// Signs a message using the private signing key
    func signMessage(_ message: String) throws -> String {
        guard let privateKey = privateSigningKey,
              let messageData = message.data(using: .utf8) else {
            throw CryptoError.signatureGenerationFailed
        }

        do {
            let signature = try privateKey.signature(for: messageData)

            log("Signature (DER): \(signature.derRepresentation.base64EncodedString())\n")
            log("🔹 Message Data (UTF-8): \(message)")
            log("🔹 Message Data (Base64): \(messageData.base64EncodedString())")

            let signatureDERString = signature.derRepresentation.base64EncodedString()
            log("🔹 Signature (DER Base64): \(signatureDERString)")

            return signatureDERString // Ensure DER format is used

        } catch {
            log("❌ Signature Generation Error: \(error)")
            throw CryptoError.signatureGenerationFailed
        }
    }

    /// Verifies a signature using the public signing key
    func verifySignature(_ message: String, signature: Data, publicKey: P256.Signing.PublicKey) -> Bool {
        guard let messageData = message.data(using: .utf8) else { return false }

        do {
            let signatureObject = try P256.Signing.ECDSASignature(derRepresentation: signature)
            return publicKey.isValidSignature(signatureObject, for: messageData)
        } catch {
            log("Signature verification failed: \(error)")
            return false
        }
    }
    
    // MARK: - AES Encryption / Decryption

    // Function to encrypt using the stored shared secret from Keychain
    func encryptMessageUsingStoredKey(_ message: String) -> (ciphertext: Data, nonce: AES.GCM.Nonce, tag: Data)? {
        guard let secretData = loadSharedSecret() else {
            log("❌ Failed to retrieve shared secret from Keychain.")
            return nil
        }

        // Convert secretData (retrieved from Keychain) into a SymmetricKey
        let symmetricKey = SymmetricKey(data: secretData)
        log("✅ Loaded symmetric key from Keychain for encryption.")

        // Encrypt using the retrieved key
        return encryptMessage(message, using: symmetricKey)
    }

    /// Encrypts a message using AES-GCM with the derived symmetric key
    func encryptMessage(_ message: String, using key: SymmetricKey) -> (ciphertext: Data, nonce: AES.GCM.Nonce, tag: Data)? {
        guard let messageData = message.data(using: .utf8) else { return nil }

        do {
            let sealedBox = try AES.GCM.seal(messageData, using: key)
            return (sealedBox.ciphertext, sealedBox.nonce, sealedBox.tag)
        } catch {
            log("Encryption failed: \(error)")
            return nil
        }
    }

    /// Decrypts a message using AES-GCM with the derived symmetric key
    func decryptMessage(from serverResponse: [String: Any]) -> String? {
        do {
            // Extract ciphertext, nonce, and tag from the server's response
            guard let ciphertextB64 = serverResponse["ciphertext"] as? String,
                  let nonceB64 = serverResponse["nonce"] as? String,
                  let tagB64 = serverResponse["tag"] as? String else {
                log("❌ Failed to extract ciphertext, nonce, or tag from response.")
                return nil
            }

            // Convert Base64 strings to Data
            guard let ciphertextData = Data(base64Encoded: ciphertextB64),
                  let nonceData = Data(base64Encoded: nonceB64),
                  let tagData = Data(base64Encoded: tagB64) else {
                log("❌ Failed to decode Base64 data.")
                return nil
            }

            // Convert nonce to AES.GCM.Nonce format
            guard let nonce = try? AES.GCM.Nonce(data: nonceData) else {
                log("❌ Failed to create nonce.")
                return nil
            }

            // Retrieve the symmetric key from Keychain
            guard let secretData = loadSharedSecret() else {
                log("❌ Failed to retrieve shared secret from Keychain.")
                return nil
            }

            let symmetricKey = SymmetricKey(data: secretData)
            log("✅ Loaded symmetric key from Keychain for decryption.")

            // Decrypt the message using the symmetric key and the tag
            let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertextData, tag: tagData)
            let decryptedData = try AES.GCM.open(sealedBox, using: symmetricKey)

            return String(data: decryptedData, encoding: .utf8)
        } catch {
            log("❌ Decryption failed: \(error)")
            return nil
        }
    }
}
