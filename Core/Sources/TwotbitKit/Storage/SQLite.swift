import Foundation
import SQLite3

public struct SQLiteError: Error, CustomStringConvertible, Sendable {
    public let code: Int32
    public let message: String
    public var description: String { "\(message) (SQLite error \(code))" }
}

/// SQLValue is one value bound to a statement parameter.
enum SQLValue {
    case int(Int64)
    case text(String)
    case blob(Data)
    case null
}

/// SQLiteDatabase is one connection to an SQLite database file. It is not
/// thread safe itself: the Store holds it in a mutex and serializes every
/// use of it, which is what makes it safe to share.
final class SQLiteDatabase: @unchecked Sendable {
    private var handle: OpaquePointer?
    private var statements: [String: OpaquePointer] = [:]

    private static let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

    /// Opens the database file. An immutable database is only read, and
    /// SQLite touches nothing of the file then, not even its locks.
    init(path: String, immutable: Bool = false) throws {
        var flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOMUTEX
        var name = path
        if immutable {
            flags = SQLITE_OPEN_READONLY | SQLITE_OPEN_URI | SQLITE_OPEN_NOMUTEX
            name = "file:" + (path.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? path) + "?immutable=1"
        }
        let rc = sqlite3_open_v2(name, &handle, flags, nil)
        guard rc == SQLITE_OK else {
            let message = handle.map { String(cString: sqlite3_errmsg($0)) } ?? "cannot open database"
            sqlite3_close_v2(handle)
            throw SQLiteError(code: rc, message: message)
        }
        sqlite3_busy_timeout(handle, 5000)
    }

    deinit { close() }

    func close() {
        for stmt in statements.values { sqlite3_finalize(stmt) }
        statements = [:]
        if let handle { sqlite3_close_v2(handle) }
        handle = nil
    }

    private func error(_ rc: Int32) -> SQLiteError {
        SQLiteError(code: rc, message: handle.map { String(cString: sqlite3_errmsg($0)) } ?? "database closed")
    }

    /// Runs SQL statements that return no rows.
    func execute(_ sql: String) throws {
        let rc = sqlite3_exec(handle, sql, nil, nil, nil)
        guard rc == SQLITE_OK else { throw error(rc) }
    }

    /// Runs one statement with the values bound. The prepared statement is
    /// cached for the next call.
    func run(_ sql: String, _ values: [SQLValue] = []) throws {
        try run(sql, values) { _ in }
    }

    /// Runs one statement with the values bound and calls row for every
    /// result row. The prepared statement is cached for the next call.
    func run(_ sql: String, _ values: [SQLValue] = [], row: (Row) throws -> Void) throws {
        let stmt = try prepare(sql)
        defer {
            sqlite3_reset(stmt)
            sqlite3_clear_bindings(stmt)
        }
        for (i, value) in values.enumerated() {
            let index = Int32(i + 1)
            let rc: Int32
            switch value {
            case .int(let v): rc = sqlite3_bind_int64(stmt, index, v)
            case .text(let v): rc = sqlite3_bind_text(stmt, index, v, -1, SQLiteDatabase.transient)
            case .blob(let v):
                rc = v.withUnsafeBytes { raw in
                    sqlite3_bind_blob(stmt, index, raw.baseAddress ?? UnsafeRawPointer(bitPattern: 1), Int32(raw.count), SQLiteDatabase.transient)
                }
            case .null: rc = sqlite3_bind_null(stmt, index)
            }
            guard rc == SQLITE_OK else { throw error(rc) }
        }
        while true {
            let rc = sqlite3_step(stmt)
            if rc == SQLITE_DONE { return }
            guard rc == SQLITE_ROW else { throw error(rc) }
            try row(Row(stmt: stmt))
        }
    }

    /// The single integer the query returns, or nil without a row or for
    /// NULL.
    func scalar(_ sql: String, _ values: [SQLValue] = []) throws -> Int64? {
        var result: Int64?
        try run(sql, values) { row in result = row.isNull(0) ? nil : row.int(0) }
        return result
    }

    /// The number of rows the last statement changed.
    var changes: Int { Int(sqlite3_changes(handle)) }

    /// Runs the body in a transaction, committed when it returns and rolled
    /// back when it throws.
    func transaction<T>(_ body: () throws -> T) throws -> T {
        try execute("BEGIN IMMEDIATE")
        do {
            let result = try body()
            try execute("COMMIT")
            return result
        } catch {
            try? execute("ROLLBACK")
            throw error
        }
    }

    private func prepare(_ sql: String) throws -> OpaquePointer {
        if let stmt = statements[sql] { return stmt }
        var stmt: OpaquePointer?
        let rc = sqlite3_prepare_v2(handle, sql, -1, &stmt, nil)
        guard rc == SQLITE_OK, let stmt else { throw error(rc) }
        statements[sql] = stmt
        return stmt
    }

    /// Row reads the columns of the current result row.
    struct Row {
        let stmt: OpaquePointer

        func int(_ column: Int32) -> Int64 { sqlite3_column_int64(stmt, column) }

        func text(_ column: Int32) -> String {
            guard let raw = sqlite3_column_text(stmt, column) else { return "" }
            return String(cString: raw)
        }

        func blob(_ column: Int32) -> Data? {
            guard sqlite3_column_type(stmt, column) != SQLITE_NULL else { return nil }
            let count = Int(sqlite3_column_bytes(stmt, column))
            guard count > 0, let raw = sqlite3_column_blob(stmt, column) else { return Data() }
            return Data(bytes: raw, count: count)
        }

        func hash(_ column: Int32) -> Hash256 {
            Hash256(data: blob(column) ?? Data()) ?? .zero
        }

        func isNull(_ column: Int32) -> Bool { sqlite3_column_type(stmt, column) == SQLITE_NULL }
    }
}
