import Foundation

/// Coin is one spendable wallet output with the derivation path of the key
/// that controls it, and the unix time it appeared: the time of its block,
/// or when its unconfirmed transaction was first seen. Time is 0 when
/// unknown.
public struct Coin: Sendable, Hashable, Identifiable {
    public var outPoint: OutPoint
    public var value: Int64
    public var pkScript: Data
    public var address: String
    public var path: String
    public var confirmed: Bool
    public var time: Int64

    public init(outPoint: OutPoint, value: Int64, pkScript: Data, address: String, path: String, confirmed: Bool, time: Int64) {
        self.outPoint = outPoint
        self.value = value
        self.pkScript = pkScript
        self.address = address
        self.path = path
        self.confirmed = confirmed
        self.time = time
    }

    public var id: OutPoint { outPoint }
}

/// Spend is a planned transaction: the coins it spends, the amount paid,
/// the fee and the change returned to the wallet, all in satoshis. Change
/// is zero when it would be dust; the remainder then goes to the fee.
public struct Spend: Sendable, Equatable {
    public var inputs: [Coin]
    public var amount: Int64
    public var fee: Int64
    public var change: Int64
}

public enum SpendError: Error, Equatable, Sendable, CustomStringConvertible {
    case insufficientFunds
    case dustAmount(amount: Int64, limit: Int64)
    case feeRateTooLow
    case signing(String)

    public var description: String {
        switch self {
        case .insufficientFunds: return "insufficient funds"
        case let .dustAmount(amount, limit): return "amount \(amount) sat is below the \(limit) sat dust limit"
        case .feeRateTooLow: return "fee rate must be at least 1 sat/vB"
        case .signing(let what): return what
        }
    }
}

/// SpendPlanner sizes and plans payments from wallet coins: the virtual
/// size estimate, the dust limit, coin selection and the maximum amount.
public enum SpendPlanner {
    /// Transaction weights in weight units: the fixed part of a segwit
    /// transaction, and one P2WPKH input with a worst-case 72-byte
    /// signature.
    static let txOverheadWeight = (4 + 4 + 1 + 1) * 4 + 2
    static let p2wpkhInputWeight = (32 + 4 + 1 + 4) * 4 + 1 + 1 + 72 + 1 + 33

    /// The sequence of every input: BIP125 replaceable, so a stuck payment
    /// can be bumped later.
    public static let sequenceRBF: UInt32 = 0xffff_ffff - 2

    /// The virtual size in vbytes of a transaction spending that many
    /// P2WPKH inputs to the output scripts. It never underestimates:
    /// signatures are counted at their maximum length.
    public static func estimateVSize(inputs: Int, outputs: [Data]) -> Int64 {
        var weight = Int64(txOverheadWeight + inputs * p2wpkhInputWeight)
        for script in outputs {
            weight += Int64(8 + varIntSize(UInt64(script.count)) + script.count) * 4
        }
        return (weight + 3) / 4
    }

    /// Plans paying the amount to the destination script at the fee rate in
    /// sat/vB. With useAll every given coin is spent, as when the user
    /// picked them; otherwise coins are added largest first, confirmed ones
    /// before unconfirmed, until they cover the amount and the fee. Change
    /// goes to the change script unless it would be dust.
    public static func plan(coins: [Coin], useAll: Bool, dest: Data, amount: Int64, feeRate: Int64, change: Data) throws -> Spend {
        guard amount >= dest.dustLimit else { throw SpendError.dustAmount(amount: amount, limit: dest.dustLimit) }
        guard feeRate >= 1 else { throw SpendError.feeRateTooLow }
        var candidates = coins
        if !useAll {
            candidates = candidates.stableSorted { a, b in
                if a.confirmed != b.confirmed { return a.confirmed }
                return a.value > b.value
            }
        }
        var n = useAll ? candidates.count : 1
        while n <= candidates.count {
            let inputs = Array(candidates[0..<n])
            let sum = inputs.reduce(Int64(0)) { $0 + $1.value }
            let withChange = estimateVSize(inputs: n, outputs: [dest, change]) * feeRate
            let rest = sum - amount - withChange
            if rest >= change.dustLimit {
                return Spend(inputs: inputs, amount: amount, fee: withChange, change: rest)
            }
            let noChange = estimateVSize(inputs: n, outputs: [dest]) * feeRate
            if sum - amount >= noChange {
                return Spend(inputs: inputs, amount: amount, fee: sum - amount, change: 0)
            }
            n += 1
        }
        throw SpendError.insufficientFunds
    }

    /// The most the coins can pay to the destination at the fee rate, with
    /// no change: their value minus the fee, or 0 when that is dust.
    public static func maxAmount(coins: [Coin], dest: Data, feeRate: Int64) -> Int64 {
        let sum = coins.reduce(Int64(0)) { $0 + $1.value }
        let amount = sum - estimateVSize(inputs: coins.count, outputs: [dest]) * feeRate
        return amount < dest.dustLimit ? 0 : amount
    }
}

extension Data {
    /// The smallest value Bitcoin Core relays an output paying the script
    /// with at its default dust relay fee of 3 sat/vB: the cost of creating
    /// and later spending the output.
    public var dustLimit: Int64 {
        var spend = Int64(32 + 4 + 1 + 107 + 4)
        if isWitnessProgram {
            spend = 32 + 4 + 1 + 107 / 4 + 4
        }
        return (Int64(8 + varIntSize(UInt64(count)) + count) + spend) * 3
    }
}
