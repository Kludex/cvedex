import Foundation

/// MITRE's list of CWE weaknesses, from `CWEList.swift`. `macos/update-cwe.py` refreshes it.
public enum CWE {
    public struct Entry: Equatable, Hashable, Sendable {
        public let id: String
        public let name: String

        /// How a record names it, such as `CWE-22: Improper Limitation of a Pathname…`.
        public var label: String { "\(id): \(name)" }
    }

    public static let all = list.split(separator: "\n").map { line in
        let parts = line.split(separator: "\t", maxSplits: 1)
        return Entry(id: "CWE-\(parts[0])", name: String(parts[1]))
    }

    /// The 2024 CWE Top 25, offered before you search.
    public static let common: [Entry] = [
        79, 787, 89, 352, 22, 125, 78, 416, 862, 434, 94, 20, 77, 287, 269, 502, 200, 863, 918, 119, 476, 798, 190,
        400, 306,
    ].compactMap { id in byID["CWE-\(id)"] }

    public static func label(_ id: String) -> String? { byID[id]?.label }

    /// Weaknesses whose ID or name contains every word of `query`.
    public static func search(_ query: String) -> [Entry] {
        let words = query.lowercased().split(separator: " ")
        guard !words.isEmpty else { return common }
        let found = all.filter { entry in words.allSatisfy { entry.label.lowercased().contains($0) } }
        let exact = found.filter { ["cwe-\(words[0])", String(words[0])].contains($0.id.lowercased()) }
        return exact + found.filter { !exact.contains($0) }
    }

    private static let byID = Dictionary(uniqueKeysWithValues: all.map { ($0.id, $0) })
}
