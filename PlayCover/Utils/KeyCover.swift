//
//  KeyCover.swift
//  PlayCover
//
//  Created by Venti on 31/01/2023.
//

import Foundation
import CryptoKit
import SwiftUI
import Security

struct KeyCover {
    static var shared = KeyCover()
    static var playChainPath: URL {
        let playChainDir = PlayTools.playCoverContainer.appendingPathComponent("PlayChain")

        if !FileManager.default.fileExists(atPath: playChainDir.path) {
            do {
                try FileManager.default.createDirectory(at: playChainDir, withIntermediateDirectories: true)
            } catch {
                Log.shared.error(error)
            }
        }

        return playChainDir
    }

    // This is only exposed at runtime
    var keyCoverPlainTextKey: String? = KeyCoverPreferences.shared.keyCoverEnabled == .selfGeneratedPassword
    ? KeyCoverPassword.shared.getKeyCoverPassword() : nil

    func isKeyCoverEnabled() -> Bool {
        return KeyCoverPreferences.shared.keyCoverEnabled != .disabled
    }

    func listKeychains() -> [KeyCoverKey] {
        // Enumerate all the keychains
        let keychains = try? FileManager.default
            .contentsOfDirectory(at: KeyCover.playChainPath,
                                 includingPropertiesForKeys: nil,
                                 options: .skipsHiddenFiles)
        var keychainList: [KeyCoverKey] = []
        for keychain in keychains ?? [] {
            let keychainName = keychain.deletingPathExtension().lastPathComponent
            let keychain = KeyCoverKey(appBundleID: keychainName)
            keychainList.append(keychain)
        }
        return keychainList
    }

    func unlockedCount() -> Int {
        var count = 0
        for keychain in listKeychains() where !keychain.chainEncryptionStatus {
            count += 1
        }
        return count
    }

    func unlockChain(_ keychain: KeyCoverKey) async throws {
        if keyCoverPlainTextKey == nil {
            let task = Task {@MainActor in
                KeyCoverObservable.shared.isKeyCoverUnlockingPromptShown = true
            }
            await task.value
            while KeyCoverObservable.shared.isKeyCoverUnlockingPromptShown {
                sleep(1)
            }
        }
        // Check and decrypt under the chain lock, so a lock still running for a previous
        // session finishes first instead of being read half-written.
        try KeyCover.withChainLock {
            if keychain.chainEncryptionStatus {
                try keychain.decryptKeyDB()
            }
        }
    }

    func lockChain(_ keychain: KeyCoverKey) throws {
        if keyCoverPlainTextKey == nil {
            return
        }
        try KeyCover.withChainLock {
            if KeyCover.isChainInUse(keychain.appBundleID) {
                Log.shared.log("KeyCover: \(keychain.appBundleID) is still in use, leaving its chain unlocked")
                return
            }
            if !keychain.chainEncryptionStatus {
                try keychain.encryptKeyDB()
            }
        }
    }

    func lockAllChainsAsync() {
        Task {
            for keychain in KeyCover.shared.listKeychains() {
                try? KeyCover.withChainLock {
                    if !keychain.chainEncryptionStatus && !KeyCover.isChainInUse(keychain.appBundleID) {
                        try keychain.encryptKeyDB()
                    }
                }
            }
        }
    }

    // MARK: Sessions
    //
    // A session spans from unlocking an app's chain before launch until that app has exited.
    // Locking is refused while a session is open (or the app is still running), so the lock
    // that runs after one launch exits can no longer encrypt and delete the database under
    // a launch that started in the meantime.

    private static let chainLock = NSLock()
    private static var activeSessions: [String: Int] = [:]

    static func withChainLock<T>(_ body: () throws -> T) rethrows -> T {
        chainLock.lock()
        defer { chainLock.unlock() }
        return try body()
    }

    func beginSession(_ bundleID: String) {
        KeyCover.withChainLock {
            KeyCover.activeSessions[bundleID, default: 0] += 1
        }
    }

    func endSession(_ bundleID: String) {
        KeyCover.withChainLock {
            let remaining = (KeyCover.activeSessions[bundleID] ?? 0) - 1
            KeyCover.activeSessions[bundleID] = remaining > 0 ? remaining : nil
        }
    }

    // Callers must hold the chain lock.
    private static func isChainInUse(_ bundleID: String) -> Bool {
        if activeSessions[bundleID] != nil {
            return true
        }
        return NSRunningApplication.runningApplications(withBundleIdentifier: bundleID)
            .contains { !$0.isTerminated }
    }
}

class KeyCoverObservable: ObservableObject {
    static var shared = KeyCoverObservable()

    @Published var keyCoverEnabled = KeyCover.shared.isKeyCoverEnabled()
    @Published var unlockedCount = KeyCover.shared.unlockedCount()
    @Published var keychains = KeyCover.shared.listKeychains()

    @Published var isKeyCoverUnlockingPromptShown = KeyCoverPreferences.shared.keyCoverEnabled == .selfGeneratedPassword
    ? false : KeyCoverPreferences.shared.keyCoverEnabled == .disabled
    ? false : KeyCoverPreferences.shared.promptForKeyCoverPasswordAtLaunch

    func update() {
        keyCoverEnabled = KeyCover.shared.isKeyCoverEnabled()
        unlockedCount = KeyCover.shared.unlockedCount()
        keychains = KeyCover.shared.listKeychains()
    }
}

enum KeyCoverError: Error {
    case opensslFailed(Int32)
}

struct KeyCoverKey {
    static let encryptedKeyExtension = "keyCover"

    var appBundleID: String

    var decryptedKeyDB: URL {
        KeyCover.playChainPath
            .appendingPathComponent(appBundleID)
            .appendingPathExtension("db")
    }
    var encryptedKeyDB: URL {
        KeyCover.playChainPath
            .appendingPathComponent(appBundleID)
            .appendingPathExtension(KeyCoverKey.encryptedKeyExtension)
    }

    var chainEncryptionStatus: Bool {
        return FileManager.default.fileExists(atPath: encryptedKeyDB.path)
    }

    func encryptKeyDB() throws {
        if let plainTextKey = KeyCover.shared.keyCoverPlainTextKey {
            // encrypt the db file; the plain db is only deleted once the encrypted copy is complete
            try runOpenSSL(["enc", "-aes-256-cbc", "-A"], plainTextKey: plainTextKey,
                           from: decryptedKeyDB, to: encryptedKeyDB)

            // delete the key dbs
            try deleteKeyDB()

            Task { @MainActor in
                KeyCoverObservable.shared.update()
            }
        }
    }

    func decryptKeyDB() throws {
        if let plainTextKey = KeyCover.shared.keyCoverPlainTextKey {
            // decrypt the db file; the encrypted copy is only deleted once decryption succeeded
            try runOpenSSL(["enc", "-aes-256-cbc", "-A", "-d"], plainTextKey: plainTextKey,
                           from: encryptedKeyDB, to: decryptedKeyDB)
            // delete the encrypted key file
            try FileManager.default.removeItem(at: encryptedKeyDB)

            Task { @MainActor in
                KeyCoverObservable.shared.update()
            }
        }
    }

    // Writes to a hidden temporary file next to the destination and moves it into place only
    // when openssl exits successfully, so neither a failed run (e.g. a wrong key) nor a reader
    // racing the write ever sees a partial file, and the source is never deleted for nothing.
    private func runOpenSSL(_ command: [String], plainTextKey: String, from source: URL, to destination: URL) throws {
        let partial = destination.deletingLastPathComponent()
            .appendingPathComponent(".\(destination.lastPathComponent).partial")
        FileManager.default.delete(at: partial)

        let task = Process()
        task.launchPath = "/usr/bin/openssl"
        task.currentDirectoryPath = KeyCover.playChainPath.path
        task.arguments = command + ["-in", source.path, "-out", partial.path, "-k", plainTextKey]
        task.launch()
        task.waitUntilExit()

        guard task.terminationStatus == 0 else {
            FileManager.default.delete(at: partial)
            throw KeyCoverError.opensslFailed(task.terminationStatus)
        }
        if FileManager.default.fileExists(atPath: destination.path) {
            _ = try FileManager.default.replaceItemAt(destination, withItemAt: partial)
        } else {
            try FileManager.default.moveItem(at: partial, to: destination)
        }
    }

    func deleteKeyDB() throws {
        try FileManager.default.removeItem(at: decryptedKeyDB)
    }

    func deleteEncryptedKeyDB() throws {
        try FileManager.default.removeItem(at: encryptedKeyDB)
    }
}

class KeyCoverPassword {
    static let shared = KeyCoverPassword()

    let tag = "io.playcover.masterkey"

    func setKeyCoverPassword(_ key: String) {
        // swiftlint: disable force_unwrapping
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrService as String: tag,
                                    kSecAttrAccount as String: tag,
                                    kSecValueData as String: key.data(using: .utf8)!]
        // swiftlint: enable force_unwrapping
        // thank you apple very cool
        // Get the key
        let oldKey = getKeyCoverPassword()
        // if it is not nil, then we need to decrypt all the keychains
        if oldKey != nil {
            KeyCover.shared.keyCoverPlainTextKey = oldKey
            for keychain in KeyCover.shared.listKeychains() where keychain.chainEncryptionStatus {
                try? keychain.decryptKeyDB()
            }
            KeyCover.shared.keyCoverPlainTextKey = nil
            // Remove any existing master key
            SecItemDelete(query as CFDictionary)
        }

        // Store the master key in macOS keychain
        Task(priority: .userInitiated) {
            let status = SecItemAdd(query as CFDictionary, nil)
            if status != errSecSuccess {
                print("Error storing master key in keychain: \(status)")
            }
        }

        KeyCover.shared.keyCoverPlainTextKey = key

        // Encrypts all keychains
        for keychain in KeyCover.shared.listKeychains() where !keychain.chainEncryptionStatus {
            try? keychain.encryptKeyDB()
        }

        Task { @MainActor in
            KeyCoverObservable.shared.update()
        }
    }

    func getKeyCoverPassword() -> String? {
        // Get the master key from macOS keychain
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrService as String: tag,
                                    kSecAttrAccount as String: tag,
                                    kSecReturnData as String: kCFBooleanTrue as Any,
                                    kSecMatchLimit as String: kSecMatchLimitOne]

        var dataTypeRef: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &dataTypeRef)
        if status == errSecSuccess {
            if let data = dataTypeRef as? Data {
                return String(data: data, encoding: .utf8)
            }
        }
        return nil
    }

    func removeKeyCoverPassword() {
        // Decrypt all key dbs
        for chain in KeyCover.shared.listKeychains() where chain.chainEncryptionStatus {
                try? chain.decryptKeyDB()
        }

        // Remove the master key from macOS keychain
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrService as String: tag,
                                    kSecAttrAccount as String: tag]

        Task(priority: .userInitiated) {
            let status = SecItemDelete(query as CFDictionary)
            if status != errSecSuccess {
                print("Error removing master key from keychain: \(status)")
            }
        }

        KeyCoverPreferences.shared.keyCoverEnabled = .disabled
        KeyCover.shared.keyCoverPlainTextKey = nil

        Task { @MainActor in
            KeyCoverObservable.shared.update()
        }
    }

    func forceResetKeyCoverPassword() {
        // If a key is in memory, don't do anything (prevent accidental deletion)
        if KeyCover.shared.keyCoverPlainTextKey != nil {
            return
        }
        // Remove the master key from macOS keychain
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrService as String: tag,
                                    kSecAttrAccount as String: tag]

        let status = SecItemDelete(query as CFDictionary)
        if status != errSecSuccess {
            print("Error removing master key from keychain: \(status)")
        }

        KeyCoverPreferences.shared.keyCoverEnabled = .disabled
        KeyCover.shared.keyCoverPlainTextKey = nil

        // Being a force reset, we have to nuke everything (because it's useless otherwise)
        for chain in KeyCover.shared.listKeychains() {
            try? chain.deleteEncryptedKeyDB()
        }

        Task { @MainActor in
            KeyCoverObservable.shared.update()
        }
    }

    func validatePassword(_ key: String) -> Bool {
        return key == getKeyCoverPassword()
    }

    func generateVerySecurePassword() -> String {
        // oh my god
        let length = 32
        let letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+"
        return String((0..<length).map { _ in letters.randomElement() ?? "." })
    }
}
