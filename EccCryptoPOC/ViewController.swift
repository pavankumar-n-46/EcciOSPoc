//
//  ViewController.swift
//  EccCryptoPOC
//
//  Created by Pavan Kumar N on 21/01/25.
//

import UIKit
import CryptoKit

class ViewController: UIViewController {

    private let keyManager = ECCKeyManager()
   // private var peerPublicKey: P256.KeyAgreement.PublicKey?
    private let label = UILabel()
    private var logTextView: UITextView!

    override func viewDidLoad() {
        super.viewDidLoad()
        // Generate or retrieve the ECC key pair
        let publicKey = keyManager.getAgreementPublicKey()
        log("Generated Public Key: \(publicKey)")


//        /// Simulate server's key
//        let serverPrivateKey = P256.KeyAgreement.PrivateKey()
//        let serverPublicKey = serverPrivateKey.publicKey
//        setPeerPublicKey(serverPublicKey)
        setupUI()
    }

    func setupUI() {

        let buttonKeyExchange = UIButton()
        buttonKeyExchange.setTitle("Exchange Key using ECDH", for: .normal)
        buttonKeyExchange.addTarget(self, action: #selector(exchangePublicKey), for: .touchUpInside)
        buttonKeyExchange.backgroundColor = .blue
        buttonKeyExchange.setTitleColor(.white, for: .normal)
        buttonKeyExchange.frame = CGRect(x: 10, y: 100, width: UIScreen.main.bounds.width - 20, height: 40)
        // make this button non expandeable in stack view
        buttonKeyExchange.setContentHuggingPriority(.required, for: .vertical)
        view.addSubview(buttonKeyExchange)

        let buttonEncrypt = UIButton()
        buttonEncrypt.setTitle("Encrypt->Client | Decrypt->Server ", for: .normal)
        buttonEncrypt.addTarget(self, action: #selector(encryptAndSendToDecrypt), for: .touchUpInside)
        buttonEncrypt.backgroundColor = .blue
        buttonEncrypt.setTitleColor(.white, for: .normal)
        buttonEncrypt.frame = CGRect(x: 10, y: 150, width: UIScreen.main.bounds.width - 20, height: 40)
        // make this button non expandeable in stack view
        buttonEncrypt.setContentHuggingPriority(.required, for: .vertical)
        view.addSubview(buttonEncrypt)

        let buttonDecrypt = UIButton()
        buttonDecrypt.setTitle("Encrypt->Server | Decrypt->Client", for: .normal)
        buttonDecrypt.addTarget(self, action: #selector(encryptedFromServer), for: .touchUpInside)
        buttonDecrypt.backgroundColor = .blue
        buttonDecrypt.setTitleColor(.white, for: .normal)
        buttonDecrypt.frame = CGRect(x: 10, y: 200, width: UIScreen.main.bounds.width - 20, height: 40)
        // make this button non expandeable in stack view
        buttonDecrypt.setContentHuggingPriority(.required, for: .vertical)
        view.addSubview(buttonDecrypt)


        let buttonSignature = UIButton()
        buttonSignature.setTitle("Verify Signature using ECDSA", for: .normal)
        buttonSignature.addTarget(self, action: #selector(verifySignature), for: .touchUpInside)
        buttonSignature.backgroundColor = .blue
        buttonSignature.setTitleColor(.white, for: .normal)
        buttonSignature.frame = CGRect(x: 10, y: 250, width: UIScreen.main.bounds.width - 20, height: 40)
        // make this button non expandeable in stack view
        buttonSignature.setContentHuggingPriority(.required, for: .vertical)
        view.addSubview(buttonSignature)


        // Initialize and setup UITextView
        logTextView = UITextView(frame: self.view.bounds)
        logTextView.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        logTextView.isEditable = false
        logTextView.isSelectable = false
        logTextView.backgroundColor = .black
        logTextView.textColor = .green
        logTextView.font = UIFont.monospacedSystemFont(ofSize: 14, weight: .regular)
        logTextView.text = "" // Start with empty log

        // Add logTextView to the view hierarchy
        self.view.addSubview(logTextView)

        // Setup constraints
        logTextView.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            logTextView.bottomAnchor.constraint(equalTo: self.view.bottomAnchor),
            logTextView.leadingAnchor.constraint(equalTo: self.view.leadingAnchor),
            logTextView.trailingAnchor.constraint(equalTo: self.view.trailingAnchor),
            logTextView.topAnchor.constraint(equalTo: self.view.topAnchor, constant: 300)
        ])

        redirectLogToTextView()
    }


    @objc func verifySignature() {
        let message = "Device Binding Data"
        log("Message: \(message)")

            NetworkManager().verifySignature(data: message) { verified in
                if verified {
                    log("Signature verified successfully!")
                } else {
                    log("Signature verification failed.")
                }
            }

    }

    @objc func exchangePublicKey() {
        NetworkManager().exchangePublicKeyWithServer { success in
            if success {
                log("Public key exchange successful.")
            } else {
                log("Public key exchange failed.")
            }
        }
    }

    /// Demonstrates encryption from client and decryption from server using ECC key exchange and AES-GCM
    @objc func encryptAndSendToDecrypt() {
        let message = "Hello, Secure World!"
        log("Original Message: \(message)")
        NetworkManager().encryptAndSendToServer(message) { value, result in
            if value {
                log("Decrypted Message: \(result ?? "error")")
            } else {
                log("Decrypted failed.\(result ?? "error")")
            }
        }
    }

    /// Demonstrates encryption from server and decryption from client using ECC key exchange and AES-GCM
    @objc func encryptedFromServer() {
        let message = "Hello, Secure World!"
        log("Original Message: \(message)")
        NetworkManager().encryptDataFromServer(plaintext: message) { value, result in
            if value {
                log("Decrypted Message: \(result ?? "error")")
            } else {
                log("Decrypted failed.\(result ?? "error")")
            }
        }
    }


    // Function to redirect custom log function to UITextView
    func redirectLogToTextView() {
        LogHandler.shared.setHandler { [weak self] message in
            DispatchQueue.main.async {
                print(message)
                self?.logTextView.text.append(message + "\n\n")
                self?.logTextView.scrollRangeToVisible(NSRange(location: self?.logTextView.text.count ?? 0, length: 0))
            }
        }
    }

}

// Custom log function
func log(_ message: String) {
    LogHandler.shared.print(message)
}

// Singleton log handler to intercept log statements
class LogHandler {
    static let shared = LogHandler()
    private var handler: ((String) -> Void)?

    private init() {}

    func setHandler(handler: @escaping (String) -> Void) {
        self.handler = handler
    }

    func print(_ message: String) {
        handler?(message)
    }
}
