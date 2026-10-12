import Foundation
import os
import Synchronization

/// Log records what the wallet does, as bitfyn's log.Printf lines: to the
/// unified log, where addresses and ids stay private, and to twotbit.log in
/// the data directory once a file is set.
public enum Log {
    private static let logger = Logger(subsystem: "com.pin2t.twotbit", category: "wallet")
    private static let file = Mutex<FileHandle?>(nil)
    /// The size from which the log file is set aside at startup as
    /// twotbit.log.old.
    private static let maxFileSize: UInt64 = 20 * 1024 * 1024

    /// Appends the log from now on to the file, setting an old one aside
    /// once it grew past maxFileSize.
    public static func configure(fileURL: URL) {
        let fm = FileManager.default
        if let size = try? fm.attributesOfItem(atPath: fileURL.path)[.size] as? UInt64, size > maxFileSize {
            let old = fileURL.appendingPathExtension("old")
            try? fm.removeItem(at: old)
            try? fm.moveItem(at: fileURL, to: old)
        }
        if !fm.fileExists(atPath: fileURL.path) {
            fm.createFile(atPath: fileURL.path, contents: nil, attributes: [.posixPermissions: 0o600])
        }
        guard let handle = try? FileHandle(forWritingTo: fileURL) else { return }
        handle.seekToEndOfFile()
        file.withLock { $0 = handle }
    }

    /// Whether log lines are echoed to standard error, as when the
    /// TWOTBIT_LOG_STDERR environment variable is set.
    private static let echo = ProcessInfo.processInfo.environment["TWOTBIT_LOG_STDERR"] != nil

    public static func info(_ message: String) {
        logger.info("\(message)")
        let stamp = timestamp()
        if echo { FileHandle.standardError.write(Data("\(stamp) \(message)\n".utf8)) }
        file.withLock { handle in
            handle?.write(Data("\(stamp) \(message)\n".utf8))
        }
    }

    private static func timestamp() -> String {
        var t = time(nil)
        var parts = tm()
        localtime_r(&t, &parts)
        return String(format: "%04d/%02d/%02d %02d:%02d:%02d", parts.tm_year + 1900, parts.tm_mon + 1, parts.tm_mday, parts.tm_hour, parts.tm_min, parts.tm_sec)
    }
}
