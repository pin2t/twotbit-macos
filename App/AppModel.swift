import AppKit
import LocalAuthentication
import Observation
import SwiftUI
import TwotbitKit

/// LaunchOptions are the command line options, as bitfyn's flags: -net,
/// -datadir, -peer, -i2psam and -torproxy, read through the argument domain
/// of the user defaults, where -net also persists the network chosen in the
/// settings.
struct LaunchOptions {
    var network: Network
    var dataDirectory: URL
    var peer: String
    var i2pSAM: String
    var torProxy: String

    static func load() -> LaunchOptions {
        let defaults = UserDefaults.standard
        let network = defaults.string(forKey: "net").flatMap(Network.named) ?? .mainnet
        let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("Twotbit")
        let dataDirectory = defaults.string(forKey: "datadir").map { URL(fileURLWithPath: ($0 as NSString).expandingTildeInPath) } ?? support
        return LaunchOptions(network: network, dataDirectory: dataDirectory, peer: defaults.string(forKey: "peer") ?? "",
                             i2pSAM: defaults.string(forKey: "i2psam") ?? I2PClient.defaultSAM, torProxy: defaults.string(forKey: "torproxy") ?? "")
    }
}

/// Section is a part of the main window, picked in the sidebar.
enum Section: String, CaseIterable, Identifiable {
    case home, coins, transactions, settings

    var id: String { rawValue }

    var title: String {
        switch self {
        case .home: return "Home"
        case .coins: return "Coins"
        case .transactions: return "Transactions"
        case .settings: return "Settings"
        }
    }

    var icon: String {
        switch self {
        case .home: return "house"
        case .coins: return "circle.circle"
        case .transactions: return "clock.arrow.circlepath"
        case .settings: return "gearshape"
        }
    }
}

/// ToastMessage is a short note shown at the bottom of the window.
struct ToastMessage: Equatable {
    let text: String
    let error: Bool
}

/// OverlaySwitch is the Tor or I2P switch of the settings with the state of
/// its network's client.
struct OverlaySwitch {
    var on = false
    var state: OverlayState = .starting
}

/// AppModel is the wallet as the window shows it: it opens the wallet,
/// runs the sync, the rates and the anonymity network clients, and keeps
/// what the views show up to date.
@MainActor @Observable
final class AppModel {
    enum Phase: Equatable {
        case loading
        case ready
        case failed(String)
        case missingPhrase
    }

    let options = LaunchOptions.load()
    var phase = Phase.loading
    var selection: Section = .home

    var status = SyncStatus()
    var address = ""
    var coins: [Coin] = []
    var history: [WalletTransaction] = []
    var stats = WalletStats()
    var rate: Int64 = 0
    var createdAt: Int64 = 0
    var now = Date()
    var toast: ToastMessage?
    /// The coins chosen in the Coins section, which the Send sheet starts
    /// with.
    var selectedCoins = Set<OutPoint>()
    var showReceive = false
    var showSend = false
    var sendPreselection = Set<OutPoint>()

    // Settings
    var peerText = ""
    var peerStatus = ""
    var peerConnected = false
    var tor = OverlaySwitch()
    var i2p = OverlaySwitch()

    @ObservationIgnored private(set) var wallet: HDWallet?
    @ObservationIgnored private(set) var store: Store?
    @ObservationIgnored private(set) var engine: SyncEngine?
    @ObservationIgnored private var rates: RateService?
    @ObservationIgnored private var index: UInt32 = 0
    @ObservationIgnored private var torClient: TorClient?
    @ObservationIgnored private var i2pClient: I2PClient?
    @ObservationIgnored private var overlayStarts = 0
    @ObservationIgnored private var peerInUse = ""
    @ObservationIgnored private var peerCheck: Task<Void, Never>?
    @ObservationIgnored private var peerEdits = 0
    @ObservationIgnored private var ticker: Task<Void, Never>?
    @ObservationIgnored private var toastTask: Task<Void, Never>?
    @ObservationIgnored private var stopped = false
    @ObservationIgnored private var starting = false
    /// Whether the wallet was shut down and the app may quit.
    @ObservationIgnored private(set) var isShutDown = false

    nonisolated static let secrets = KeychainSecretStore(service: "com.pin2t.twotbit")
    /// How long the pinned peer field waits after an edit before it connects
    /// to the typed peer, so typing does not dial every partial address.
    static let peerCheckDelay: Duration = .milliseconds(700)

    var network: Network { options.network }

    /// Opens the wallet, creating it on first run, and starts the clients of
    /// the networks on, the sync, the rates and the minute ticker. The
    /// database and the stored header chain, over 900 000 headers on
    /// mainnet, load off the main thread while the window shows progress.
    func start() {
        guard phase == .loading, !starting, !stopped else { return }
        starting = true
        let options = self.options
        Task {
            let result = await Task.detached(priority: .userInitiated) { () -> Result<(OpenedWallet, SyncEngine), Error> in
                try? FileManager.default.createDirectory(at: options.dataDirectory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
                Log.configure(fileURL: options.dataDirectory.appendingPathComponent("twotbit.log"))
                Log.info("twotbit started on \(options.network.displayName), pid \(ProcessInfo.processInfo.processIdentifier)")
                let opened: OpenedWallet
                do {
                    opened = try WalletLoader.open(dataDirectory: options.dataDirectory, network: options.network, secrets: AppModel.secrets)
                } catch {
                    return .failure(error)
                }
                do {
                    try RateService.seed(opened.store)
                } catch {
                    Log.info("rates: \(error)")
                }
                do {
                    return .success((opened, try SyncEngine(network: options.network, store: opened.store)))
                } catch {
                    opened.store.close()
                    return .failure(error)
                }
            }.value
            starting = false
            switch result {
            case .success(let (opened, engine)):
                run(opened, engine)
            case .failure(WalletError.missingRecoveryPhrase):
                phase = .missingPhrase
            case .failure(let error):
                Log.info("startup failed: \(error)")
                phase = .failed("\(error)")
            }
        }
    }

    /// Shows the opened wallet and starts its sync, rates and clients.
    private func run(_ opened: OpenedWallet, _ engine: SyncEngine) {
        guard !stopped else {
            opened.store.close()
            return
        }
        store = opened.store
        wallet = opened.wallet
        createdAt = opened.meta.createdAt
        index = opened.meta.nextIndex
        rate = (try? opened.store.latestRate()?.cents) ?? 0
        self.engine = engine
        refreshAddress()
        showWallet()
        loadSettings()
        startOverlays()
        var peer = pinnedPeer
        if !peer.isEmpty && options.peer.isEmpty { Log.info("pinned peer \(peer) from the settings") }
        if overlayOn {
            if !peer.isEmpty { Log.info("pinned peer \(peer) not used while Tor or I2P is on") }
            peer = ""
        }
        do {
            try engine.start(pinned: peer) { [weak self] status in
                DispatchQueue.main.async { self?.apply(status) }
            }
        } catch {
            Log.info("sync failed to start: \(error)")
            show("Sync failed: \(error)", error: true)
        }
        let rates = RateService(store: opened.store)
        rates.start { [weak self] rate in
            DispatchQueue.main.async { self?.rate = rate.cents }
        }
        self.rates = rates
        ticker = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(60))
                self?.now = Date()
            }
        }
        phase = .ready
    }

    /// Stops everything as the app quits: the sync, the network clients,
    /// the rates, and closes the database.
    func shutdown() async {
        guard !stopped else {
            while !isShutDown { try? await Task.sleep(for: .milliseconds(50)) }
            return
        }
        stopped = true
        while starting { try? await Task.sleep(for: .milliseconds(50)) }
        ticker?.cancel()
        peerCheck?.cancel()
        await engine?.stop()
        torClient?.close()
        i2pClient?.close()
        await rates?.stop()
        store?.close()
        Log.info("twotbit stopped")
        isShutDown = true
    }

    /// Restores the recovery phrase the Keychain lost, then opens the
    /// wallet.
    func restore(phrase: String) throws {
        try WalletLoader.restore(mnemonic: phrase, dataDirectory: options.dataDirectory, network: network, secrets: AppModel.secrets)
        phase = .loading
        start()
    }

    /// Shows a new sync status: the connectivity, the balance and the wallet
    /// as of now, moving on to the next address once the shown one was paid.
    private func apply(_ s: SyncStatus) {
        guard !stopped else { return }
        status = s
        showWallet()
        rotateIfUsed()
    }

    /// Shows the coins, transactions and statistics from one snapshot of
    /// the sync state.
    private func showWallet() {
        guard let engine else { return }
        coins = engine.coins()
        history = engine.history()
        stats = WalletStats(history, unspent: coins.count)
        let listed = Set(coins.map(\.outPoint))
        selectedCoins.formIntersection(listed)
        if status == SyncStatus() { status = engine.status() }
    }

    /// Derives the current receive address, stores it and has the sync
    /// watch it.
    private func refreshAddress() {
        guard let wallet, let store else { return }
        do {
            let derived = try wallet.receiveAddress(index)
            try store.addAddress(derived)
            address = derived.address
            engine?.watch(derived)
        } catch {
            show("Address \(index): \(error)", error: true)
        }
    }

    /// Moves on to the next address once the displayed one received a
    /// payment, confirmed or pending, so every payment goes to a fresh
    /// address.
    private func rotateIfUsed() {
        guard let engine, let store else { return }
        while !address.isEmpty && engine.isUsed(address) {
            let used = address
            index += 1
            do {
                try store.updateNextIndex(index)
            } catch {
                show("Save next address index: \(error)", error: true)
                return
            }
            refreshAddress()
            Log.info("address \(used) received a payment, showing next address \(address) (index \(index))")
        }
    }

    /// The balance in US dollars at the latest rate, nil while no rate is
    /// known.
    var usdBalance: String? {
        rate > 0 ? Format.usd(Format.usdValue(status.balance + status.pending, centsPerBTC: rate)) : nil
    }

    /// Puts the text on the clipboard and says what was copied.
    func copy(_ text: String, _ what: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
        show("\(what) copied")
    }

    /// Copies a secret like copy, then clears the clipboard after a minute
    /// unless something else was copied over it meanwhile.
    func copySecret(_ text: String, _ what: String) {
        copy(text, what)
        let change = NSPasteboard.general.changeCount
        Task {
            try? await Task.sleep(for: .seconds(60))
            if NSPasteboard.general.changeCount == change { NSPasteboard.general.clearContents() }
        }
    }

    /// Shows a short note at the bottom of the window for a while: what
    /// was done, or an error, which stays longer.
    func show(_ message: String, error: Bool = false) {
        toast = ToastMessage(text: message, error: error)
        toastTask?.cancel()
        toastTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(error ? 6 : 2))
            if !Task.isCancelled { self?.toast = nil }
        }
    }

    func openSend(with coins: Set<OutPoint> = []) {
        sendPreselection = coins
        showSend = true
    }

    // MARK: Settings

    /// The peer the sync is pinned to: the -peer option when given, the
    /// peer saved in the settings otherwise.
    var pinnedPeer: String {
        if !options.peer.isEmpty { return options.peer }
        do {
            return try store?.setting(Store.settingPinnedPeer) ?? ""
        } catch {
            Log.info("settings: read pinned peer: \(error)")
            return ""
        }
    }

    var peerFromFlag: Bool { !options.peer.isEmpty }

    var overlayOn: Bool { tor.on || i2p.on }

    /// The networks on, as "Tor and I2P".
    var overlayNames: String { [(tor.on, "Tor"), (i2p.on, "I2P")].filter(\.0).map(\.1).joined(separator: " and ") }

    private func loadSettings() {
        peerInUse = pinnedPeer
        peerText = peerInUse
        tor.on = (try? store?.setting(Store.settingTor)) == "on"
        i2p.on = (try? store?.setting(Store.settingI2P)) == "on"
    }

    /// Starts the clients of the networks on before the sync starts, so it
    /// dials peers on them only from the first.
    private func startOverlays() {
        if tor.on { beginOverlay(.tor) }
        if i2p.on { beginOverlay(.i2p) }
    }

    /// The SOCKS proxies the Tor client looks for: the -torproxy option or
    /// the saved one, or the tor daemon's and Tor Browser's.
    var torProxies: [String] {
        if !options.torProxy.isEmpty { return [options.torProxy] }
        let saved = (try? store?.setting(Store.settingTorProxy)) ?? ""
        return saved.isEmpty ? TorClient.defaultProxies : [saved]
    }

    /// Turns the network on for the sync and starts its client; the sync
    /// dials through the client once it is ready.
    private func beginOverlay(_ network: OverlayNetwork) {
        overlayStarts += 1
        let start = overlayStarts
        engine?.setOverlay(network, on: true, dialer: nil)
        let onState: @Sendable (OverlayState) -> Void = { [weak self] state in
            DispatchQueue.main.async { self?.overlayChanged(network, start: start, state: state) }
        }
        switch network {
        case .tor:
            tor.state = .starting
            torClient = TorClient.start(proxies: torProxies, onState: onState)
        case .i2p:
            i2p.state = .starting
            i2pClient = I2PClient.start(sam: options.i2pSAM, onState: onState)
        case .direct:
            break
        }
    }

    /// Shows the state of a client, unless its switch was flipped since,
    /// and hands the client to the sync once it is ready.
    private func overlayChanged(_ network: OverlayNetwork, start: Int, state: OverlayState) {
        guard start == overlayStarts, !stopped else { return }
        switch network {
        case .tor:
            guard let client = torClient else { return }
            tor.state = state
            if state == .ready { engine?.setOverlay(.tor, on: true, dialer: client) }
        case .i2p:
            guard let client = i2pClient else { return }
            i2p.state = state
            if state == .ready { engine?.setOverlay(.i2p, on: true, dialer: client) }
        case .direct:
            break
        }
    }

    /// Turns the network off for the sync and closes its client.
    private func endOverlay(_ network: OverlayNetwork) {
        overlayStarts += 1
        engine?.setOverlay(network, on: false, dialer: nil)
        switch network {
        case .tor:
            torClient?.close()
            torClient = nil
            tor.state = .starting
        case .i2p:
            i2pClient?.close()
            i2pClient = nil
            i2p.state = .starting
        case .direct:
            break
        }
    }

    /// Saves a flipped Tor or I2P switch and applies it at once. On, the
    /// network's client starts, and the sync is unpinned if it is the first
    /// network on; off, the client closes, and once both are off the sync is
    /// pinned to the pinned peer again.
    func setOverlay(_ network: OverlayNetwork, _ on: Bool) {
        let others = network == .tor ? i2p.on : tor.on
        if network == .tor { tor.on = on } else { i2p.on = on }
        do {
            try store?.setSetting(network == .tor ? Store.settingTor : Store.settingI2P, on ? "on" : "")
        } catch {
            show("Settings: \(error)", error: true)
        }
        if on {
            stopPeerCheck()
            if !others { try? engine?.setPinned("") }
            beginOverlay(network)
        } else {
            endOverlay(network)
            if !others {
                do { try engine?.setPinned(peerInUse) } catch { show("\(error)", error: true) }
            }
        }
        Log.info("settings: \(network) \(on ? "on" : "off")")
        if !overlayOn { recheckPeer() }
    }

    /// What the switch's status line says: what it does while off, how far
    /// its client got while on.
    func overlayText(_ network: OverlayNetwork) -> (String, Bool) {
        let s = network == .tor ? tor : i2p
        guard s.on else {
            return network == .tor ? ("Only .onion peers, through a local Tor proxy (\(torProxies.joined(separator: " or "))).", false)
                                   : ("Only .b32.i2p peers, through a local I2P router.", false)
        }
        switch (network, s.state) {
        case (_, .ready): return ("\(network) ready", true)
        case (.tor, .failed): return ("No Tor proxy at \(torProxies.joined(separator: " or ")), retrying", false)
        case (_, .failed(let why)) where why.contains("no I2P router"): return ("No I2P router at \(options.i2pSAM), retrying", false)
        case (_, .failed): return ("I2P session failed, retrying", false)
        case (.tor, _): return ("Looking for Tor...", false)
        default: return ("Connecting to the I2P router...", false)
        }
    }

    /// The notes under the pinned peer field.
    var peerNote: [String] {
        if overlayOn { return ["Not used while \(overlayNames) \(tor.on && i2p.on ? "are" : "is") on."] }
        if peerFromFlag { return ["Set by the -peer flag for this run.", "A peer confirmed here takes over; the flag wins at the next start."] }
        return ["Headers and filters are synced from this peer.", "Leave it empty to choose peers automatically."]
    }

    /// Checks the peer in the field again, unless Tor or I2P is on, as the
    /// settings open.
    func recheckPeer() {
        guard !overlayOn, phase == .ready else { return }
        peerEdited(peerText)
    }

    /// Checks the typed peer: an empty field unpins the sync, an address that
    /// is not an IP, with or without a port, is only reported, and an IP is
    /// connected to after peerCheckDelay. A newer edit abandons the check.
    func peerEdited(_ text: String) {
        stopPeerCheck()
        let trimmed = text.trimmingCharacters(in: .whitespaces)
        peerConnected = false
        if trimmed.isEmpty {
            peerStatus = ""
            usePeer("")
            return
        }
        guard let addr = trimmed.peerAddress(defaultPort: network.defaultPort) else {
            peerStatus = "Not connected: not an IP address or IP:port"
            return
        }
        let edit = peerEdits
        peerStatus = "Connecting to \(addr)…"
        let network = self.network
        peerCheck = Task { [weak self] in
            guard await (try? Task.sleep(for: AppModel.peerCheckDelay)) != nil else { return }
            var failure: Error?
            do {
                try await PeerProbe.probe(network: network, address: addr)
            } catch {
                failure = error
            }
            if Task.isCancelled { return }
            self?.peerProbed(edit, addr, failure)
        }
    }

    private func peerProbed(_ edit: Int, _ addr: String, _ failure: Error?) {
        guard edit == peerEdits else { return }
        peerCheck = nil
        if let failure {
            Log.info("settings: pinned peer \(addr): \(failure)")
            peerStatus = "Not connected: \(PeerProbe.reason(failure))"
        } else {
            peerStatus = "Connected"
            peerConnected = true
            usePeer(addr)
        }
    }

    private func stopPeerCheck() {
        peerEdits += 1
        peerCheck?.cancel()
        peerCheck = nil
    }

    /// Saves the pinned peer, an empty one removing it, and pins the sync to
    /// it right away, unless it is the peer in use already.
    private func usePeer(_ addr: String) {
        guard addr != peerInUse else { return }
        do {
            try store?.setSetting(Store.settingPinnedPeer, addr)
            try engine?.setPinned(addr)
        } catch {
            show("\(error)", error: true)
            return
        }
        peerInUse = addr
        Log.info(addr.isEmpty ? "settings: pinned peer removed" : "settings: pinned peer \(addr) saved and in use")
    }

    /// Asks to confirm the owner of the Mac, with Touch ID or the login
    /// password, before the recovery phrase is shown.
    func authenticate(reason: String) async -> Bool {
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else { return true }
        return (try? await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)) ?? false
    }

    /// Switches the wallet to another network: the choice is saved and the
    /// app relaunches on it, each network keeping its own wallet.
    func switchNetwork(_ next: Network) {
        UserDefaults.standard.set(next.displayName, forKey: "net")
        let config = NSWorkspace.OpenConfiguration()
        config.createsNewApplicationInstance = true
        let url = Bundle.main.bundleURL
        Task {
            await shutdown()
            _ = try? await NSWorkspace.shared.openApplication(at: url, configuration: config)
            NSApp.terminate(nil)
        }
    }

    // MARK: Send

    /// ChangeAddress is the change address a payment would use; stored is
    /// whether it is in the database already.
    struct ChangeAddress {
        let derived: DerivedAddress
        let stored: Bool
    }

    /// PlannedSend is a checked payment ready to sign.
    struct PlannedSend {
        let address: String
        let dest: Data
        let spend: Spend
        let feeRate: Int64
        let change: ChangeAddress
    }

    struct SendError: Error, CustomStringConvertible {
        let description: String
    }

    /// The first stored change address that has not received anything, or
    /// else the next one, derived without storing it: planning a payment
    /// must not leave addresses behind.
    func nextChange() throws -> ChangeAddress {
        guard let wallet, let store, let engine else { throw SendError(description: "wallet not open") }
        let stored = try store.changeAddresses()
        for a in stored where !engine.isUsed(a.address) {
            let derived = try wallet.changeAddress(a.index)
            return ChangeAddress(derived: derived, stored: true)
        }
        return ChangeAddress(derived: try wallet.changeAddress(UInt32(stored.count)), stored: false)
    }

    /// Checks a payment and plans its transaction: exactly the given coins,
    /// or coins picked from the wallet's when none are given.
    func planSend(address: String, amount: Int64, feeRate: Int64, coins chosen: [Coin]) throws -> PlannedSend {
        guard let wallet, let engine else { throw SendError(description: "wallet not open") }
        let trimmed = address.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw SendError(description: "enter the destination address") }
        let dest = try wallet.addressScript(trimmed)
        guard amount > 0 else { throw SendError(description: "enter an amount") }
        let change = try nextChange()
        let useAll = !chosen.isEmpty
        do {
            let spend = try SpendPlanner.plan(coins: useAll ? chosen : engine.coins(), useAll: useAll, dest: dest, amount: amount,
                                              feeRate: feeRate, change: change.derived.script)
            return PlannedSend(address: trimmed, dest: dest, spend: spend, feeRate: feeRate, change: change)
        } catch SpendError.insufficientFunds where useAll {
            throw SendError(description: "the selected coins do not cover the amount and the fee")
        }
    }

    /// Stores and watches the change address, signs the transaction and
    /// broadcasts it, returning its id and how many peers it went to.
    func sendPlanned(_ p: PlannedSend) throws -> (Hash256, Int) {
        guard let wallet, let store, let engine else { throw SendError(description: "wallet not open") }
        if p.spend.change > 0 {
            if !p.change.stored { try store.addChangeAddress(p.change.derived) }
            engine.watch(p.change.derived)
        }
        let tx = try wallet.sign(p.spend, dest: p.dest, change: p.change.derived.script)
        let peers = try engine.broadcast(tx)
        return (tx.txid, peers)
    }

    /// The fee of a planned payment with its size and rate.
    static func feeText(_ p: PlannedSend) -> String {
        var outputs = [p.dest]
        if p.spend.change > 0 { outputs.append(p.change.derived.script) }
        let vsize = SpendPlanner.estimateVSize(inputs: p.spend.inputs.count, outputs: outputs)
        return "\(Format.amount(p.spend.fee)) (\(vsize) vB at \(p.feeRate) sat/vB)"
    }

    /// The summary shown before a payment is signed.
    static func confirmText(_ p: PlannedSend) -> String {
        let coins = p.spend.inputs.count == 1 ? "1 coin" : "\(p.spend.inputs.count) coins"
        var text = "Pay \(Format.amount(p.spend.amount)) to\n\(p.address)\n\nFee: \(feeText(p))\nTotal: \(Format.amount(p.spend.amount + p.spend.fee))\nSpending \(coins)"
        if p.spend.change > 0 { text += ", \(Format.amount(p.spend.change)) back as change" }
        return text
    }

    /// The most the coins, or all coins, can pay to the address at the fee
    /// rate.
    func maxAmount(address: String, feeRate: Int64, coins chosen: [Coin]) -> Int64 {
        let coins = chosen.isEmpty ? (engine?.coins() ?? []) : chosen
        let dest = (try? wallet?.addressScript(address)) ?? Data(count: 22)
        return SpendPlanner.maxAmount(coins: coins, dest: dest, feeRate: max(feeRate, 1))
    }
}
