import Foundation
import Synchronization

/// TimeoutError is a wait that ran out of time.
public struct TimeoutError: Error, CustomStringConvertible, Sendable {
    public let description: String
    public init(_ description: String = "timed out") { self.description = description }
}

/// Runs the operation, failing with a TimeoutError when it takes longer
/// than the duration. The operation is cancelled then, and must give up on
/// cancellation.
func withTimeout<T: Sendable>(_ duration: Duration, _ what: @autoclosure () -> String = "operation",
                              _ operation: @escaping @Sendable () async throws -> T) async throws -> T {
    let message = what()
    return try await withThrowingTaskGroup(of: T.self) { group in
        group.addTask { try await operation() }
        group.addTask {
            try await Task.sleep(for: duration)
            throw TimeoutError("\(message) timed out after \(duration.formatted)")
        }
        defer { group.cancelAll() }
        return try await group.next()!
    }
}

extension Duration {
    /// The whole milliseconds of the duration.
    var milliseconds: Int64 {
        components.seconds * 1000 + components.attoseconds / 1_000_000_000_000_000
    }

    /// The duration as Go prints one: "5s", "1m30s", "250ms".
    var formatted: String {
        let ms = components.seconds * 1000 + components.attoseconds / 1_000_000_000_000_000
        if ms < 1000 { return "\(ms)ms" }
        let seconds = Double(ms) / 1000
        if seconds < 60 { return seconds == seconds.rounded() ? "\(Int(seconds))s" : String(format: "%.3gs", seconds) }
        let whole = Int(seconds)
        return whole % 60 == 0 ? "\(whole / 60)m0s" : "\(whole / 60)m\(whole % 60)s"
    }
}

/// Locked is a Mutex shared by reference, for a local value the child tasks
/// of a task group update together: the Swift of Xcode 16 and 26 refuses a
/// local Mutex captured by a task group's addTask closure.
final class Locked<Value: Sendable>: Sendable {
    private let mutex: Mutex<Value>

    init(_ value: Value) { mutex = Mutex(value) }

    func withLock<R, E: Error>(_ body: (inout sending Value) throws(E) -> sending R) throws(E) -> sending R {
        try mutex.withLock(body)
    }
}

/// Mailbox hands the messages a peer delivers to the request waiting for
/// them, buffering those that arrive first, like a Go channel.
final class Mailbox<T: Sendable>: Sendable {
    private struct Waiter {
        let id: UInt64
        let continuation: CheckedContinuation<T, Error>
    }

    private struct State {
        var items: [T] = []
        var waiters: [Waiter] = []
        var closed: Error?
        var nextID: UInt64 = 0
    }

    private enum Outcome {
        case item(T)
        case error(Error)
        case waiting
    }

    private let state = Mutex(State())
    /// The most items kept for a later request; unsolicited ones beyond it
    /// are dropped.
    private let capacity: Int

    init(capacity: Int = 1024) {
        self.capacity = capacity
    }

    /// Hands the item to the oldest waiter, or keeps it for the next one.
    func deliver(_ item: T) {
        let waiter = state.withLock { s -> Waiter? in
            if s.closed != nil { return nil }
            if s.waiters.isEmpty {
                if s.items.count < capacity { s.items.append(item) }
                return nil
            }
            return s.waiters.removeFirst()
        }
        waiter?.continuation.resume(returning: item)
    }

    /// Discards the items left by an earlier request.
    func drain() {
        state.withLock { $0.items.removeAll() }
    }

    /// Fails every waiter, and every later receive, with the error.
    func close(_ error: Error) {
        let waiters = state.withLock { s -> [Waiter] in
            s.closed = error
            defer { s.waiters = [] }
            return s.waiters
        }
        for w in waiters { w.continuation.resume(throwing: error) }
    }

    /// The next item, waiting until one arrives, the mailbox is closed or
    /// the task is cancelled.
    func receive() async throws -> T {
        let id = state.withLock { s -> UInt64 in
            s.nextID += 1
            return s.nextID
        }
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<T, Error>) in
                let outcome = state.withLock { s -> Outcome in
                    if !s.items.isEmpty { return .item(s.items.removeFirst()) }
                    if let error = s.closed { return .error(error) }
                    if Task.isCancelled { return .error(CancellationError()) }
                    s.waiters.append(Waiter(id: id, continuation: continuation))
                    return .waiting
                }
                switch outcome {
                case .item(let item): continuation.resume(returning: item)
                case .error(let error): continuation.resume(throwing: error)
                case .waiting: break
                }
            }
        } onCancel: {
            let waiter = state.withLock { s -> Waiter? in
                guard let i = s.waiters.firstIndex(where: { $0.id == id }) else { return nil }
                return s.waiters.remove(at: i)
            }
            waiter?.continuation.resume(throwing: CancellationError())
        }
    }

    /// The next item within the timeout.
    func receive(timeout: Duration, what: String) async throws -> T {
        do {
            return try await withTimeout(timeout, what) { try await self.receive() }
        } catch is TimeoutError {
            throw TimeoutError("no \(what) response within \(timeout.formatted)")
        }
    }
}

/// Signal is a one-shot event: it fires once, as a closed Go channel, and
/// wakes every waiter.
final class Signal: Sendable {
    private struct State {
        var fired = false
        var waiters: [UInt64: CheckedContinuation<Void, Never>] = [:]
        var nextID: UInt64 = 0
    }

    private let state = Mutex(State())

    init() {}

    var isFired: Bool { state.withLock { $0.fired } }

    func fire() {
        let waiters = state.withLock { s -> [CheckedContinuation<Void, Never>] in
            guard !s.fired else { return [] }
            s.fired = true
            defer { s.waiters = [:] }
            return Array(s.waiters.values)
        }
        for w in waiters { w.resume() }
    }

    /// Waits until the signal fires or the task is cancelled.
    func wait() async {
        let id = state.withLock { s -> UInt64 in
            s.nextID += 1
            return s.nextID
        }
        await withTaskCancellationHandler {
            await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                let resumeNow = state.withLock { s -> Bool in
                    if s.fired || Task.isCancelled { return true }
                    s.waiters[id] = continuation
                    return false
                }
                if resumeNow { continuation.resume() }
            }
        } onCancel: {
            let waiter = state.withLock { $0.waiters.removeValue(forKey: id) }
            waiter?.resume()
        }
    }
}

/// Pulse wakes one waiting loop, as a Go channel with a buffer of one: a
/// signal sent while nobody waits is kept, and further ones merge into it.
final class Pulse: Sendable {
    private struct State {
        var pending = false
        var waiter: (id: UInt64, continuation: CheckedContinuation<Bool, Never>)?
        var nextID: UInt64 = 0
    }

    private let state = Mutex(State())

    init() {}

    func signal() {
        let waiter = state.withLock { s -> CheckedContinuation<Bool, Never>? in
            if let w = s.waiter {
                s.waiter = nil
                return w.continuation
            }
            s.pending = true
            return nil
        }
        waiter?.resume(returning: true)
    }

    /// Waits for a signal, at most the timeout when one is given. It reports
    /// whether a signal came, false on timeout or cancellation.
    func wait(timeout: Duration? = nil) async -> Bool {
        if let timeout {
            let woken = Locked(false)
            await withTaskGroup(of: Void.self) { group in
                group.addTask {
                    let got = await self.wait(timeout: nil)
                    woken.withLock { $0 = got }
                }
                group.addTask { try? await Task.sleep(for: timeout) }
                await group.next()
                group.cancelAll()
            }
            return woken.withLock { $0 }
        }
        let id = state.withLock { s -> UInt64 in
            s.nextID += 1
            return s.nextID
        }
        return await withTaskCancellationHandler {
            await withCheckedContinuation { (continuation: CheckedContinuation<Bool, Never>) in
                let now = state.withLock { s -> Bool? in
                    if s.pending {
                        s.pending = false
                        return true
                    }
                    if Task.isCancelled { return false }
                    let previous = s.waiter
                    s.waiter = (id, continuation)
                    if let previous { previous.continuation.resume(returning: false) }
                    return nil
                }
                if let now { continuation.resume(returning: now) }
            }
        } onCancel: {
            let waiter = state.withLock { s -> CheckedContinuation<Bool, Never>? in
                guard let w = s.waiter, w.id == id else { return nil }
                s.waiter = nil
                return w.continuation
            }
            waiter?.resume(returning: false)
        }
    }
}

/// Sleeps for the duration and reports whether it slept through, false
/// when the task was cancelled.
func pause(_ duration: Duration) async -> Bool {
    do {
        try await Task.sleep(for: duration)
        return true
    } catch {
        return false
    }
}
