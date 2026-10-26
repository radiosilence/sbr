import Foundation
@testable import SbrKit
import XCTest

/// Runs against the login Keychain: an unsigned test process has no
/// entitlement for the data protection Keychain, so access groups and
/// accessibility are exercised only on a device.
final class SbrKeychainTests: XCTestCase {
    private var keychain: SbrKeychain!

    override func setUp() {
        keychain = SbrKeychain(accessGroup: nil, service: "cc.blit.sbr.tests.\(UUID().uuidString)")
        keychain.dataProtection = false
    }

    override func tearDown() {
        try? keychain.removeAll()
    }

    func testRoundTripAndUpdate() throws {
        let account = SbrProfileSecret.account(UUID().uuidString)
        XCTAssertNil(try keychain.value(SbrProfileSecret.self, account))
        let first = SbrProfileSecret(config: #"{"outbounds":[]}"#, url: URL(string: "https://example.com/p#name"))
        try keychain.set(value: first, for: account)
        XCTAssertEqual(try keychain.value(SbrProfileSecret.self, account), first)
        let second = SbrProfileSecret(config: nil, url: first.url)
        try keychain.set(value: second, for: account)
        XCTAssertEqual(try keychain.value(SbrProfileSecret.self, account), second)
        try keychain.remove(account)
        XCTAssertNil(try keychain.data(account))
        try keychain.remove(account)
    }

    /// Profiles with many servers and inline rule-sets run to hundreds of KB.
    func testLargeConfig() throws {
        let outbounds = (0..<4000).map { i in
            #"{"type":"vless","tag":"node-\#(i)","server":"10.0.\#(i / 256).\#(i % 256)","server_port":443,"uuid":"\#(UUID().uuidString)"}"#
        }
        let config = #"{"outbounds":[\#(outbounds.joined(separator: ","))]}"#
        XCTAssertGreaterThan(config.utf8.count, 400_000)
        try keychain.set(value: SbrProfileSecret(config: config, url: nil), for: "large")
        XCTAssertEqual(try keychain.value(SbrProfileSecret.self, "large")?.config, config)
    }

    func testRemoveAll() throws {
        for i in 0..<3 { try keychain.set(Data("\(i)".utf8), for: "item.\(i)") }
        XCTAssertEqual(Set(try keychain.accounts()), ["item.0", "item.1", "item.2"])
        try keychain.removeAll()
        XCTAssertEqual(try keychain.accounts(), [])
    }
}
