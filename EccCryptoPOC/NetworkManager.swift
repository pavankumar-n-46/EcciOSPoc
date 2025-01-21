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

}
