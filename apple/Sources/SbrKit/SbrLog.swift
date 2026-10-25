import Foundation
import os
import SbrCore

public enum SbrLogLevel: Int32, Sendable, Comparable {
    case trace = 0, debug, info, warn, error

    public static func < (a: Self, b: Self) -> Bool { a.rawValue < b.rawValue }
}

extension Sbr {
    /// Receive sbr's logs (process-wide). Called on sbr's threads, possibly
    /// concurrently. nil restores the default (stderr, which a Network
    /// Extension's unified log also captures). The level comes from the
    /// config's `log` section.
    public static func setLogHandler(_ handler: (@Sendable (SbrLogLevel, String) -> Void)?) {
        LogRegistry.shared.set(handler)
    }

    /// Forward sbr's logs to `Logger`. Messages carry destinations, so they
    /// are private (redacted in Console unless a debugger or profile allows
    /// it) unless `publicMessages` is set.
    public static func forwardLogs(to logger: Logger, publicMessages: Bool = false) {
        setLogHandler { level, message in
            SbrRecentLogs.shared.append(level, message)
            let type: OSLogType = switch level {
            case .trace, .debug: .debug
            case .info: .info
            case .warn: .default
            case .error: .error
            }
            if publicMessages {
                logger.log(level: type, "\(message, privacy: .public)")
            } else {
                logger.log(level: type, "\(message, privacy: .private)")
            }
        }
    }
}

private final class LogBox {
    let handler: @Sendable (SbrLogLevel, String) -> Void
    init(_ handler: @escaping @Sendable (SbrLogLevel, String) -> Void) { self.handler = handler }
}

/// Owns the retained context handed to C. sbr guarantees the old context is
/// unused once `sbr_set_log_callback` returns, so it is released right after.
private final class LogRegistry: @unchecked Sendable {
    static let shared = LogRegistry()
    private let lock = NSLock()
    private var box: Unmanaged<LogBox>?

    func set(_ handler: (@Sendable (SbrLogLevel, String) -> Void)?) {
        lock.lock()
        defer { lock.unlock() }
        let old = box
        if let handler {
            let new = Unmanaged.passRetained(LogBox(handler))
            sbr_set_log_callback({ level, message, context in
                guard let message, let context else { return }
                let box = Unmanaged<LogBox>.fromOpaque(context).takeUnretainedValue()
                box.handler(SbrLogLevel(rawValue: level) ?? .info, String(cString: message))
            }, new.toOpaque())
            box = new
        } else {
            sbr_set_log_callback(nil, nil)
            box = nil
        }
        old?.release()
    }
}

/// The last few hundred log lines, in memory only (never written to disk),
/// so the app can show what the tunnel is doing without a debugger.
public final class SbrRecentLogs: @unchecked Sendable {
    public static let shared = SbrRecentLogs()
    private let lock = NSLock()
    private var lines: [String] = []
    private let capacity = 1000
    private static let time: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        return f
    }()

    func append(_ level: SbrLogLevel, _ message: String) {
        let tag = switch level {
        case .error: "error"
        case .warn: "warn"
        default: "info"
        }
        let line = "\(Self.time.string(from: Date())) \(tag) \(message)"
        lock.lock()
        defer { lock.unlock() }
        lines.append(line)
        if lines.count > capacity { lines.removeFirst(lines.count - capacity) }
    }

    public func snapshot() -> [String] {
        lock.lock()
        defer { lock.unlock() }
        return lines
    }
}
