import Foundation
import Testing
@testable import TwotbitKit

struct P2PFixture: Decodable {
    struct MessageV: Decodable { let name: String; let command: String; let hex: String }
    struct Host: Decodable { let host: String; let onion: Bool; let i2p: Bool; let network: String }
    struct OnionV: Decodable { let key: String; let address: String }
    struct Seed: Decodable { let host: String; let port: UInt16 }
    let messages: [MessageV]
    let hosts: [Host]
    let onions: [OnionV]
    let onionSeeds: [Seed]
    let i2pSeeds: [Seed]
}

@Suite struct WireTests {
    static let fixture = Fixtures.load("p2p", as: P2PFixture.self)

    func vector(_ name: String) -> Data {
        Data(h: Self.fixture.messages.first { $0.name == name }!.hex)
    }

    /// Every message btcd wrote decodes and encodes back to the same bytes.
    @Test func roundTrips() throws {
        for v in Self.fixture.messages where v.name != "tx base" {
            let frame = Data(h: v.hex)
            let header = try Wire.parseHeader(frame.prefix(Wire.headerSize))
            #expect(header.command == v.command)
            let payload = frame.dropFirst(Wire.headerSize)
            #expect(header.length == payload.count)
            #expect(header.checksumMatches(payload: Data(payload)))
            let message = try Message.decode(command: header.command, payload: Data(payload))
            #expect(Wire.frame(message, magic: header.magic) == frame, "\(v.name)")
        }
    }

    @Test func versionMessages() {
        let mappedZero = [UInt8](repeating: 0, count: 10) + [0xff, 0xff, 0, 0, 0, 0]
        func version(_ host: String, _ port: UInt16, nonce: UInt64, time: Int64, relay: Bool) -> Message {
            .version(VersionMessage(protocolVersion: 70016, services: [], timestamp: time,
                                    addrRecv: NetAddress(host: host, port: port), addrFrom: NetAddress(ip: mappedZero, port: 0),
                                    nonce: nonce, userAgent: "/twotbit:0.1.0/", startHeight: 0, relay: relay))
        }
        #expect(Wire.frame(version("203.0.113.7", 8333, nonce: 0x0123_4567_89ab_cdef, time: 1_760_000_000, relay: true), magic: Network.mainnet.magic) == vector("version relay"))
        #expect(Wire.frame(version("2001:db8::1", 18333, nonce: 42, time: 1_760_000_123, relay: false), magic: Network.testnet3.magic) == vector("version norelay testnet ipv6"))
        #expect(Wire.frame(version("::", 8333, nonce: 7, time: 1_760_000_456, relay: true), magic: Network.mainnet.magic) == vector("version onion"))
    }

    @Test func remoteVersion() throws {
        let frame = vector("version remote")
        guard case .version(let v) = try Message.decode(command: "version", payload: frame.dropFirst(24)) else {
            Issue.record("not a version message")
            return
        }
        #expect(v.userAgent == "/Satoshi:28.1.0/")
        #expect(v.startHeight == 912_345)
        #expect(v.services.contains(.compactFilters))
        #expect(v.services.contains(.bloom))
        #expect(v.services.description == "SFNodeNetwork|SFNodeBloom|SFNodeWitness|SFNodeCF|SFNodeNetworkLimited")
        #expect(v.addrRecv.host == "0.0.0.0" || v.addrRecv.host == "::")
    }

    @Test func requests() throws {
        #expect(Wire.frame(.verack, magic: Network.mainnet.magic) == vector("verack"))
        #expect(Wire.frame(.sendAddrV2, magic: Network.mainnet.magic) == vector("sendaddrv2"))
        #expect(Wire.frame(.getAddr, magic: Network.mainnet.magic) == vector("getaddr"))
        #expect(Wire.frame(.memPool, magic: Network.mainnet.magic) == vector("mempool"))
        #expect(Wire.frame(.ping(0xdead_beef_cafe_babe), magic: Network.mainnet.magic) == vector("ping"))
        #expect(Wire.frame(.pong(0x1122_3344_5566_7788), magic: Network.mainnet.magic) == vector("pong"))
        guard case let .getCFHeaders(start, stop) = try Message.decode(command: "getcfheaders", payload: vector("getcfheaders").dropFirst(24)) else {
            Issue.record("not getcfheaders")
            return
        }
        #expect(start == 840_000)
        #expect(Wire.frame(.getCFHeaders(startHeight: 840_000, stop: stop), magic: Network.mainnet.magic) == vector("getcfheaders"))
        #expect(Wire.frame(.getCFilters(startHeight: 840_100, stop: stop), magic: Network.mainnet.magic) == vector("getcfilters"))
        let txFrame = vector("tx witness")
        guard case .tx(let tx) = try Message.decode(command: "tx", payload: txFrame.dropFirst(24)) else {
            Issue.record("not a tx")
            return
        }
        #expect(Wire.frame(command: "tx", payload: tx.serialized(witness: false), magic: Network.mainnet.magic) == vector("tx base"))
        #expect(tx.inputs[0].sequence == SpendPlanner.sequenceRBF)
    }

    @Test func addresses() throws {
        guard case .addrV2(let list) = try Message.decode(command: "addrv2", payload: vector("addrv2").dropFirst(24)) else {
            Issue.record("not addrv2")
            return
        }
        #expect(list.map(\.host) == ["192.0.2.1", "2001:db8::7", list[2].host])
        #expect((list[2].host ?? "").isOnion)
        guard case .addr(let legacy) = try Message.decode(command: "addr", payload: vector("addr").dropFirst(24)) else {
            Issue.record("not addr")
            return
        }
        #expect(legacy.map(\.host) == ["198.51.100.23", "2001:db8::abcd"])
        #expect(legacy.map(\.port) == [8333, 18333])
    }

    @Test func hostsAndOnions() {
        for v in Self.fixture.hosts {
            #expect(v.host.isOnion == v.onion, "\(v.host)")
            #expect(v.host.isI2P == v.i2p, "\(v.host)")
            #expect(OverlayNetwork.of(v.host).description == v.network)
        }
        for v in Self.fixture.onions {
            #expect(Data(h: v.key).onionAddress == v.address)
            #expect(v.address.onionKey?.hex == v.key)
        }
        #expect(Seeds.onion.map(\.host) == Self.fixture.onionSeeds.map(\.host))
        #expect(Seeds.i2p.map(\.host) == Self.fixture.i2pSeeds.map(\.host))
        #expect(Seeds.onion.allSatisfy { ($0.host).isOnion })
        #expect(Seeds.i2p.allSatisfy { ($0.host).isI2P })
    }

    @Test func hostPorts() throws {
        #expect(try "1.2.3.4:8333".splitHostPort() == ("1.2.3.4", 8333))
        #expect(try "[2001:db8::1]:18333".splitHostPort() == ("2001:db8::1", 18333))
        #expect(try "seed.example:1".splitHostPort() == ("seed.example", 1))
        for bad in ["1.2.3.4", "2001:db8::1:8333", "[::1]", "[::1]x:1", "host:", "host:99999", "host:-1", "host:+1"] {
            #expect(throws: HostPortError.self, "\(bad)") { try bad.splitHostPort() }
        }
        #expect("2001:db8::1".withPort(8333) == "[2001:db8::1]:8333")
        #expect("1.2.3.4".withPort(8333) == "1.2.3.4:8333")
        #expect(PeerAddress(host: "x.onion", port: 8333).description == "x.onion:8333")
    }

    @Test func ipAddresses() {
        #expect("1.2.3.4".canonicalIP == "1.2.3.4")
        #expect("::ffff:1.2.3.4".canonicalIP == "1.2.3.4")
        #expect("2001:0db8:0000:0000:0000:0000:0000:0001".canonicalIP == "2001:db8::1")
        #expect("2001:db8:0:1:0:0:0:1".canonicalIP == "2001:db8:0:1::1")
        #expect("2001:db8:0:1:1:1:1:1".canonicalIP == "2001:db8:0:1:1:1:1:1")
        #expect("::".canonicalIP == "::")
        #expect("::1".canonicalIP == "::1")
        #expect("1.2.3".canonicalIP == nil)
        #expect("example.com".canonicalIP == nil)
        #expect("1.2.3.256".canonicalIP == nil)
    }
}
