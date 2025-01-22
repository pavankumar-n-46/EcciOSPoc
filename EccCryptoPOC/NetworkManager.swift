//
//  NetworkManager.swift
//  EccCryptoPOC
//
//  Created by Pavan Kumar N on 21/01/25.
//

import Foundation

class NetworkManager {
    private let keyManager = ECCKeyManager()

    func signData(data: String, completion: @escaping (String?) -> Void) {
        let url = URL(string: "http://127.0.0.1:5000/sign")!
        var request = URLRequest(url: url)
        request.httpMethod = "POST"

        let json: [String: Any] = ["data": data]
        let jsonData = try? JSONSerialization.data(withJSONObject: json, options: [])

        request.httpBody = jsonData
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let task = URLSession.shared.dataTask(with: request) { (data, response, error) in
            guard let data = data, error == nil else {
                completion(nil)
                return
            }

            do {
                if let jsonResponse = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any],
                   let signature = jsonResponse["signature"] as? String {
                    completion(signature)
                }
            } catch {
                completion(nil)
            }
        }
        task.resume()
    }

    func encryptData(data: String, completion: @escaping (String?, String?) -> Void) {
        let url = URL(string: "http://127.0.0.1:5000/encrypt")!
        var request = URLRequest(url: url)
        request.httpMethod = "POST"

        let json: [String: Any] = ["data": data]
        let jsonData = try? JSONSerialization.data(withJSONObject: json, options: [])

        request.httpBody = jsonData
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let task = URLSession.shared.dataTask(with: request) { (data, response, error) in
            guard let data = data, error == nil else {
                completion(nil, nil)
                return
            }

            do {
                if let jsonResponse = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any],
                   let iv = jsonResponse["iv"] as? String,
                   let ciphertext = jsonResponse["ciphertext"] as? String {
                    completion(iv, ciphertext)
                }
            } catch {
                completion(nil, nil)
            }
        }
        task.resume()
    }

    func verifySignature(data: String, completion: @escaping (Bool) -> Void) {
        guard let url = URL(string: "http://127.0.0.1:5000/verify") else {
            log("Invalid URL")
            completion(false)
            return
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let signatureDERString = try! keyManager.signMessage(data)
        let publicKey = keyManager.exportSigningPublicKey()

        print("Signature (DER): \(signatureDERString)")
        print("Data: \(data)")
        print("publicKey: \(publicKey)")

        let payload: [String: Any] = [
            "data": data,
            "signature": signatureDERString,
            "publicKey": publicKey
        ]

        guard let jsonData = try? JSONSerialization.data(withJSONObject: payload, options: []) else {
            log("Failed to serialize JSON")
            completion(false)
            return
        }

        request.httpBody = jsonData

        let task = URLSession.shared.dataTask(with: request) { data, response, error in
            guard let data = data, error == nil else {
                log("Network error: \(error?.localizedDescription ?? "Unknown error")")
                completion(false)
                return
            }

            do {
                if let jsonResponse = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any] {
                    if let status = jsonResponse["status"] as? String, status == "verified" {
                        log("Signature verified successfully!")
                        completion(true)
                    } else {
                        log(jsonResponse["error"] as? String ?? "Signature verification failed")
                        completion(false)
                    }
                } else {
                    log("Signature verification failed")
                    completion(false)
                }

            } catch {
                log("Failed to parse JSON response")
                completion(false)
            }
        }

        task.resume()
    }

    func exchangePublicKeyWithServer(completion: @escaping (Bool) -> Void) {
        guard let url = URL(string: "http://127.0.0.1:5000/exchange") else {
            log("Invalid URL")
            completion(false)
            return
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let publicKeyBase64 = keyManager.encodePublicKeyToBase64()
        log("Public Key (Base64): \(publicKeyBase64)")

        let payload: [String: Any] = [
            "publicKey": publicKeyBase64
        ]

        guard let jsonData = try? JSONSerialization.data(withJSONObject: payload, options: []) else {
            log("Failed to serialize JSON")
            completion(false)
            return
        }

        request.httpBody = jsonData

        let task = URLSession.shared.dataTask(with: request) { data, response, error in
            guard let data = data, error == nil else {
                log("Network error: \(error?.localizedDescription ?? "Unknown error")")
                completion(false)
                return
            }

            do {
                if let jsonResponse = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any],
                   let sharedSecret = jsonResponse["sharedSecret"] as? String {
                    // Convert the shared secret from Base64
                    guard let sharedSecretData = Data(base64Encoded: sharedSecret) else {
                        log("Invalid shared secret data")
                        completion(false)
                        return
                    }

                    // Save the shared secret to the Keychain
                    self.keyManager.saveSharedSecret(sharedSecretData)
                    completion(true)
                } else {
                    log("Failed to receive valid response")
                    completion(false)
                }
            } catch {
                log("Failed to parse JSON response")
                completion(false)
            }
        }

        task.resume()
    }

    func encryptAndSendToServer(_ message: String, completion: @escaping (Bool, String?) -> Void) {
        guard let encrypted = keyManager.encryptMessageUsingStoredKey(message) else {
            completion(false, "Encryption failed.")
            return
        }

        let ciphertextB64 = encrypted.ciphertext.base64EncodedString()
        let nonceB64 = encrypted.nonce.withUnsafeBytes { Data($0).base64EncodedString() }
        let tagB64 = encrypted.tag.base64EncodedString()

        log("Ciphertext (Base64): \(ciphertextB64)")
        log("Nonce (Base64): \(nonceB64)")
        log("Tag (Base64): \(tagB64)")

        let url = URL(string: "http://127.0.0.1:5000/decrypt")!  // 🔹 Adjust server URL if needed
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let payload: [String: Any] = [
            "ciphertext": ciphertextB64,
            "nonce": nonceB64,
            "tag": tagB64
        ]

        guard let jsonData = try? JSONSerialization.data(withJSONObject: payload, options: []) else {
            completion(false, "Failed to serialize JSON.")
            return
        }

        request.httpBody = jsonData

        let task = URLSession.shared.dataTask(with: request) { (data, response, error) in
            guard let data = data, error == nil else {
                completion(false, "Network error: \(error?.localizedDescription ?? "Unknown error")")
                return
            }

            do {
                if let jsonResponse = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any] {
                    if let plaintext = jsonResponse["plaintext"] as? String {
                        print("✅ Decryption successful: \(plaintext)")
                        completion(true, plaintext)
                    } else if let errorMsg = jsonResponse["error"] as? String {
                        completion(false, "Server error: \(errorMsg)")
                    }
                } else {
                    completion(false, "Invalid server response.")
                }
            } catch {
                completion(false, "JSON decoding error: \(error)")
            }
        }
        task.resume()
    }

    func encryptDataFromServer(plaintext: String, completion: @escaping (Bool, String?) -> Void) {
        let url = URL(string: "http://127.0.0.1:5000/encrypt")!  // Adjust server URL if needed
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let payload: [String: Any] = ["data": plaintext]

        guard let jsonData = try? JSONSerialization.data(withJSONObject: payload, options: []) else {
            completion(false, "Failed to serialize JSON.")
            return
        }

        request.httpBody = jsonData

        let task = URLSession.shared.dataTask(with: request) { (data, response, error) in
            guard let data = data, error == nil else {
                completion(false, "Network error: \(error?.localizedDescription ?? "Unknown error")")
                return
            }

            do {
                if let jsonResponse = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any] {
                    print("✅ Server Encryption Successful")

                    // Check for errors
                    if let error = jsonResponse["error"] as? String {
                        completion(false, error)
                        return
                    }

                    // Call the updated decryptMessage method to handle all conversions and decryption
                    if let decryptedText = self.keyManager.decryptMessage(from: jsonResponse) {
                        print("✅ Decryption Successful: \(decryptedText)")
                        completion(true, decryptedText)
                    } else {
                        completion(false, "Decryption failed.")
                    }
                } else {
                    completion(false, "Invalid server response.")
                }
            } catch {
                completion(false, "JSON decoding error: \(error)")
            }
        }
        task.resume()
    }
}
