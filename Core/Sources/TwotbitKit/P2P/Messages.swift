import Foundation

/// Service flags a node advertises in its version message.
public struct ServiceFlags: OptionSet, Sendable, Hashable, CustomStringConvertible {
    public let rawValue: UInt64
    public init(rawValue: UInt64) { self.rawValue = rawValue }

    public static let network = ServiceFlags(rawValue: 1 << 0)
    public static let getUTXO = ServiceFlags(rawValue: 1 << 1)
    public static let bloom = ServiceFlags(rawValue: 1 << 2)
    public static let witness = ServiceFlags(rawValue: 1 << 3)
    public static let xthin = ServiceFlags(rawValue: 1 << 4)
    public static let bitcoinCash = ServiceFlags(rawValue: 1 << 5)
    public static let compactFilters = ServiceFlags(rawValue: 1 << 6)
    public static let segwit2x = ServiceFlags(rawValue: 1 << 7)
    public static let networkLimited = ServiceFlags(rawValue: 1 << 10)
    public static let p2pV2 = ServiceFlags(rawValue: 1 << 11)

    private static let names: [(ServiceFlags, String)] = [
        (.network, "SFNodeNetwork"), (.getUTXO, "SFNodeGetUTXO"), (.bloom, "SFNodeBloom"), (.witness, "SFNodeWitness"),
        (.xthin, "SFNodeXthin"), (.bitcoinCash, "SFNodeBit5"), (.compactFilters, "SFNodeCF"), (.segwit2x, "SFNode2X"),
        (.networkLimited, "SFNodeNetworkLimited"), (.p2pV2, "SFNodeP2PV2"),
    ]

    /// The flag names joined by "|", as btcd writes them.
    public var description: String {
        if rawValue == 0 { return "0x0" }
        var parts = [String]()
        var rest = rawValue
        for (flag, name) in ServiceFlags.names where contains(flag) {
            parts.append(name)
            rest &= ~flag.rawValue
        }
        if rest != 0 { parts.append("0x" + String(rest, radix: 16)) }
        return parts.joined(separator: "|")
    }
}

/// InvType is the kind of object an inventory vector names.
public enum InvType: UInt32, Sendable {
    case error = 0
    case tx = 1
    case block = 2
    case filteredBlock = 3
    case compactBlock = 4
    case wtx = 5
    case witnessTx = 0x4000_0001
    case witnessBlock = 0x4000_0002
    case filteredWitnessBlock = 0x4000_0003
}

public struct InvVect: Sendable, Hashable {
    public var type: UInt32
    public var hash: Hash256

    public init(_ type: InvType, _ hash: Hash256) {
        self.type = type.rawValue
        self.hash = hash
    }

    init(rawType: UInt32, hash: Hash256) {
        type = rawType
        self.hash = hash
    }

    public var kind: InvType? { InvType(rawValue: type) }
}

/// NetAddress is a peer address as version and addr messages carry it: an
/// IPv6 or IPv4-mapped address and a port, with the advertised services.
public struct NetAddress: Sendable, Hashable {
    public var time: UInt32
    public var services: ServiceFlags
    public var ip: [UInt8]
    public var port: UInt16

    public init(time: UInt32 = 0, services: ServiceFlags = [], ip: [UInt8] = [UInt8](repeating: 0, count: 16), port: UInt16 = 0) {
        self.time = time
        self.services = services
        self.ip = ip
        self.port = port
    }

    /// The address of a host: its IP, or the unspecified address for an
    /// onion or I2P name, which the legacy encoding cannot carry.
    public init(host: String, port: UInt16, services: ServiceFlags = []) {
        self.init(services: services, ip: IPAddress.bytes(host) ?? [UInt8](repeating: 0, count: 16), port: port)
    }

    public var host: String { IPAddress.string(ip) }

    func write(to w: inout ByteWriter, withTime: Bool) {
        if withTime { w.writeUInt32(time) }
        w.writeUInt64(services.rawValue)
        w.write(ip)
        w.writeUInt16BE(port)
    }

    static func read(from r: inout ByteReader, withTime: Bool) throws -> NetAddress {
        let time = withTime ? try r.readUInt32() : 0
        let services = ServiceFlags(rawValue: try r.readUInt64())
        let ip = try r.readByteArray(16)
        let port = try r.readUInt16BE()
        return NetAddress(time: time, services: services, ip: ip, port: port)
    }
}

/// NetAddressV2 is a BIP155 addrv2 peer address, which can also carry onion
/// and I2P addresses. Host is nil for networks the wallet does not dial.
public struct NetAddressV2: Sendable, Hashable {
    public var time: UInt32
    public var services: ServiceFlags
    public var networkID: UInt8
    public var address: Data
    public var port: UInt16

    public static let ipv4: UInt8 = 1
    public static let ipv6: UInt8 = 2
    public static let torV3: UInt8 = 4
    public static let i2p: UInt8 = 5

    public var host: String? {
        switch networkID {
        case NetAddressV2.ipv4 where address.count == 4: return IPAddress.string([UInt8](address))
        case NetAddressV2.ipv6 where address.count == 16: return IPAddress.string([UInt8](address))
        case NetAddressV2.torV3 where address.count == 32: return Onion.address(key: address)
        case NetAddressV2.i2p where address.count == 32: return Base32.encode(address) + ".b32.i2p"
        default: return nil
        }
    }
}

public struct VersionMessage: Sendable, Hashable {
    public var protocolVersion: Int32
    public var services: ServiceFlags
    public var timestamp: Int64
    public var addrRecv: NetAddress
    public var addrFrom: NetAddress
    public var nonce: UInt64
    public var userAgent: String
    public var startHeight: Int32
    public var relay: Bool
}

public struct CFHeaders: Sendable, Hashable {
    public var filterType: UInt8
    public var stopHash: Hash256
    public var prevFilterHeader: Hash256
    public var filterHashes: [Hash256]
}

public struct CFilter: Sendable, Hashable {
    public var filterType: UInt8
    public var blockHash: Hash256
    public var data: Data
}

/// Message is one P2P protocol message the wallet sends or handles. Others
/// are read as unknown and ignored.
public enum Message: Sendable {
    case version(VersionMessage)
    case verack
    case sendAddrV2
    case wtxidRelay
    case ping(UInt64)
    case pong(UInt64)
    case getAddr
    case addr([NetAddress])
    case addrV2([NetAddressV2])
    case getHeaders(locator: [Hash256], stop: Hash256)
    case headers([BlockHeader])
    case getCFHeaders(startHeight: UInt32, stop: Hash256)
    case cfHeaders(CFHeaders)
    case getCFilters(startHeight: UInt32, stop: Hash256)
    case cfilter(CFilter)
    case getData([InvVect])
    case inv([InvVect])
    case notFound([InvVect])
    case block(Block)
    case tx(Transaction)
    case filterLoad(BloomFilter)
    case memPool
    case unknown(String)

    /// The protocol version the wallet speaks: BIP155 addrv2.
    public static let protocolVersion: Int32 = 70016
    /// The BIP158 basic filter type.
    public static let basicFilter: UInt8 = 0
    /// The most entries a getdata, inv or notfound may list.
    static let maxInv = 50_000

    public var command: String {
        switch self {
        case .version: return "version"
        case .verack: return "verack"
        case .sendAddrV2: return "sendaddrv2"
        case .wtxidRelay: return "wtxidrelay"
        case .ping: return "ping"
        case .pong: return "pong"
        case .getAddr: return "getaddr"
        case .addr: return "addr"
        case .addrV2: return "addrv2"
        case .getHeaders: return "getheaders"
        case .headers: return "headers"
        case .getCFHeaders: return "getcfheaders"
        case .cfHeaders: return "cfheaders"
        case .getCFilters: return "getcfilters"
        case .cfilter: return "cfilter"
        case .getData: return "getdata"
        case .inv: return "inv"
        case .notFound: return "notfound"
        case .block: return "block"
        case .tx: return "tx"
        case .filterLoad: return "filterload"
        case .memPool: return "mempool"
        case .unknown(let command): return command
        }
    }

    /// The serialized payload. Transactions and blocks are written with
    /// their witness data.
    public var payload: Data {
        var w = ByteWriter()
        switch self {
        case .version(let v):
            w.writeInt32(v.protocolVersion)
            w.writeUInt64(v.services.rawValue)
            w.writeInt64(v.timestamp)
            v.addrRecv.write(to: &w, withTime: false)
            v.addrFrom.write(to: &w, withTime: false)
            w.writeUInt64(v.nonce)
            w.writeVarBytes(Data(v.userAgent.utf8))
            w.writeInt32(v.startHeight)
            w.writeBool(v.relay)
        case .verack, .sendAddrV2, .wtxidRelay, .getAddr, .memPool, .unknown:
            break
        case .ping(let nonce), .pong(let nonce):
            w.writeUInt64(nonce)
        case .addr(let list):
            w.writeVarInt(UInt64(list.count))
            for a in list { a.write(to: &w, withTime: true) }
        case .addrV2(let list):
            w.writeVarInt(UInt64(list.count))
            for a in list {
                w.writeUInt32(a.time)
                w.writeVarInt(a.services.rawValue)
                w.writeUInt8(a.networkID)
                w.writeVarBytes(a.address)
                w.writeUInt16BE(a.port)
            }
        case let .getHeaders(locator, stop):
            w.writeUInt32(UInt32(Message.protocolVersion))
            w.writeVarInt(UInt64(locator.count))
            for h in locator { w.write(h) }
            w.write(stop)
        case .headers(let headers):
            w.writeVarInt(UInt64(headers.count))
            for h in headers {
                h.write(to: &w)
                w.writeVarInt(0)
            }
        case let .getCFHeaders(start, stop), let .getCFilters(start, stop):
            w.writeUInt8(Message.basicFilter)
            w.writeUInt32(start)
            w.write(stop)
        case .cfHeaders(let m):
            w.writeUInt8(m.filterType)
            w.write(m.stopHash)
            w.write(m.prevFilterHeader)
            w.writeVarInt(UInt64(m.filterHashes.count))
            for h in m.filterHashes { w.write(h) }
        case .cfilter(let m):
            w.writeUInt8(m.filterType)
            w.write(m.blockHash)
            w.writeVarBytes(m.data)
        case .getData(let list), .inv(let list), .notFound(let list):
            w.writeVarInt(UInt64(list.count))
            for iv in list {
                w.writeUInt32(iv.type)
                w.write(iv.hash)
            }
        case .block(let block):
            return block.serialized
        case .tx(let tx):
            return tx.serialized(witness: true)
        case .filterLoad(let f):
            w.writeVarBytes(Data(f.data))
            w.writeUInt32(f.hashFuncs)
            w.writeUInt32(f.tweak)
            w.writeUInt8(f.flags)
        }
        return w.data
    }

    /// Decodes the payload of a command. Commands the wallet does not
    /// handle give .unknown.
    public static func decode(command: String, payload: Data) throws -> Message {
        var r = ByteReader(payload)
        switch command {
        case "version":
            let protocolVersion = try r.readInt32()
            let services = ServiceFlags(rawValue: try r.readUInt64())
            let timestamp = try r.readInt64()
            let recv = try NetAddress.read(from: &r, withTime: false)
            var from = NetAddress()
            var nonce: UInt64 = 0
            var agent = ""
            var height: Int32 = 0
            var relay = true
            if r.remaining > 0 {
                from = try NetAddress.read(from: &r, withTime: false)
                nonce = try r.readUInt64()
            }
            if r.remaining > 0 {
                let raw = try r.readVarBytes(limit: 256)
                agent = String(decoding: raw, as: UTF8.self)
            }
            if r.remaining > 0 { height = try r.readInt32() }
            if r.remaining > 0 { relay = try r.readBool() }
            return .version(VersionMessage(protocolVersion: protocolVersion, services: services, timestamp: timestamp, addrRecv: recv,
                                           addrFrom: from, nonce: nonce, userAgent: agent, startHeight: height, relay: relay))
        case "verack": return .verack
        case "sendaddrv2": return .sendAddrV2
        case "wtxidrelay": return .wtxidRelay
        case "getaddr": return .getAddr
        case "mempool": return .memPool
        case "ping": return .ping(r.remaining >= 8 ? try r.readUInt64() : 0)
        case "pong": return .pong(try r.readUInt64())
        case "addr":
            let count = try r.readCount(limit: 1000)
            return .addr(try (0..<count).map { _ in try NetAddress.read(from: &r, withTime: true) })
        case "addrv2":
            let count = try r.readCount(limit: 1000)
            var list = [NetAddressV2]()
            for _ in 0..<count {
                let time = try r.readUInt32()
                let services = ServiceFlags(rawValue: try r.readVarInt())
                let id = try r.readUInt8()
                let address = try r.readVarBytes(limit: 512)
                let port = try r.readUInt16BE()
                list.append(NetAddressV2(time: time, services: services, networkID: id, address: address, port: port))
            }
            return .addrV2(list)
        case "getheaders":
            _ = try r.readUInt32()
            let count = try r.readCount(limit: 2000)
            let locator = try (0..<count).map { _ in try r.readHash() }
            return .getHeaders(locator: locator, stop: try r.readHash())
        case "headers":
            let count = try r.readCount(limit: 2000)
            var headers = [BlockHeader]()
            headers.reserveCapacity(count)
            for _ in 0..<count {
                headers.append(try BlockHeader(from: &r))
                guard try r.readVarInt() == 0 else { throw DecodeError.invalid("block headers may not contain transactions") }
            }
            return .headers(headers)
        case "getcfheaders", "getcfilters":
            _ = try r.readUInt8()
            let start = try r.readUInt32()
            let stop = try r.readHash()
            return command == "getcfheaders" ? .getCFHeaders(startHeight: start, stop: stop) : .getCFilters(startHeight: start, stop: stop)
        case "cfheaders":
            let type = try r.readUInt8()
            let stop = try r.readHash()
            let prev = try r.readHash()
            let count = try r.readCount(limit: 2000)
            let hashes = try (0..<count).map { _ in try r.readHash() }
            return .cfHeaders(CFHeaders(filterType: type, stopHash: stop, prevFilterHeader: prev, filterHashes: hashes))
        case "cfilter":
            let type = try r.readUInt8()
            let hash = try r.readHash()
            return .cfilter(CFilter(filterType: type, blockHash: hash, data: try r.readVarBytes(limit: 4_000_000)))
        case "getdata", "inv", "notfound":
            let count = try r.readCount(limit: maxInv)
            let list = try (0..<count).map { _ in InvVect(rawType: try r.readUInt32(), hash: try r.readHash()) }
            switch command {
            case "getdata": return .getData(list)
            case "inv": return .inv(list)
            default: return .notFound(list)
            }
        case "block":
            return .block(try Block(from: &r))
        case "tx":
            return .tx(try Transaction(from: &r))
        case "filterload":
            let data = try r.readVarBytes(limit: BloomFilter.maxFilterSize)
            let funcs = try r.readUInt32()
            let tweak = try r.readUInt32()
            let flags = try r.readUInt8()
            return .filterLoad(BloomFilter(raw: [UInt8](data), hashFuncs: funcs, tweak: tweak, flags: flags))
        default:
            return .unknown(command)
        }
    }
}

/// Wire frames messages: the network magic, the command, the payload length
/// and its checksum, then the payload.
public enum Wire {
    public static let headerSize = 24
    /// The largest payload accepted, as btcd's MaxMessagePayload.
    public static let maxPayload = 32 * 1024 * 1024

    public static func frame(_ message: Message, magic: UInt32) -> Data {
        frame(command: message.command, payload: message.payload, magic: magic)
    }

    public static func frame(command: String, payload: Data, magic: UInt32) -> Data {
        var w = ByteWriter(capacity: headerSize + payload.count)
        w.writeUInt32(magic)
        var name = [UInt8](command.utf8.prefix(12))
        name += [UInt8](repeating: 0, count: 12 - name.count)
        w.write(name)
        w.writeUInt32(UInt32(payload.count))
        w.write(Hashes.sha256d(payload).data.prefix(4))
        w.write(payload)
        return w.data
    }

    public struct Header: Sendable {
        public let magic: UInt32
        public let command: String
        public let length: Int
        public let checksum: Data
    }

    public static func parseHeader(_ data: Data) throws -> Header {
        var r = ByteReader(data)
        let magic = try r.readUInt32()
        let raw = try r.readByteArray(12)
        let end = raw.firstIndex(of: 0) ?? 12
        guard raw[end...].allSatisfy({ $0 == 0 }) else { throw DecodeError.invalid("malformed command") }
        let command = String(decoding: raw[..<end], as: UTF8.self)
        let length = Int(try r.readUInt32())
        guard length <= maxPayload else { throw DecodeError.invalid("payload of \(length) bytes exceeds the limit") }
        let checksum = try r.readBytes(4)
        return Header(magic: magic, command: command, length: length, checksum: checksum)
    }

    public static func checksumMatches(_ header: Header, payload: Data) -> Bool {
        Hashes.sha256d(payload).data.prefix(4) == header.checksum
    }
}
