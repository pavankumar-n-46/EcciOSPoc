//
//  AppDelegate.swift
//  EccCryptoPOC
//
//  Created by Pavan Kumar N on 21/01/25.
//

import UIKit
import Security
import CryptoKit

@main
class AppDelegate: UIResponder, UIApplicationDelegate {



    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        // Override point for customization after application launch.
        return true
    }

    // MARK: UISceneSession Lifecycle

    func application(_ application: UIApplication, configurationForConnecting connectingSceneSession: UISceneSession, options: UIScene.ConnectionOptions) -> UISceneConfiguration {
        // Called when a new scene session is being created.
        // Use this method to select a configuration to create the new scene with.
        return UISceneConfiguration(name: "Default Configuration", sessionRole: connectingSceneSession.role)
    }

    func application(_ application: UIApplication, didDiscardSceneSessions sceneSessions: Set<UISceneSession>) {
        // Called when the user discards a scene session.
        // If any sessions were discarded while the application was not running, this will be called shortly after application:didFinishLaunchingWithOptions.
        // Use this method to release any resources that were specific to the discarded scenes, as they will not return.
    }
}

// MARK: ECC Keychain related
extension AppDelegate {

    private func generateKeyPair() {
        let privateKey = P256.Signing.PrivateKey()
        let publicKey = privateKey.publicKey

        do {
            let message = "Device Binding Data".data(using: .utf8)!
            let signature = try privateKey.signature(for: message)

            if publicKey.isValidSignature(signature, for: message) {
                print("Signature is valid")
            } else {
                print("Signature is invalid")
            }
        } catch {
            print("Error: \(error)")
        }
    }

    private func savePrivateKey(_ key: P256.Signing.PrivateKey) {
        let keyData = key.rawRepresentation
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag as String: "com.yourapp.ecc.privatekey",
            kSecValueData as String: keyData,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock
        ]
        SecItemAdd(query as CFDictionary, nil)
    }

}

