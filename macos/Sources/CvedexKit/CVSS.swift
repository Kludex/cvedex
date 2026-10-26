import Foundation

/// One metric of a CVSS vector, such as attack vector, with the values it takes.
public struct CVSSMetric: Sendable {
    public let key: String
    public let name: String
    public let options: [(value: String, name: String)]
}

/// A CVSS score the form edits metric by metric.
public protocol CVSSScore: Equatable, Sendable {
    static var metrics: [CVSSMetric] { get }
    var values: [String: String] { get set }
    var vector: String { get }
    var score: Double { get }
    var severity: String { get }
    init()
}

/// A CVSS 3.1 base score, computed from its metrics as the specification does.
public struct CVSS31: CVSSScore {
    public typealias Metric = CVSSMetric

    public static let metrics = [
        Metric(
            key: "AV", name: "Attack vector",
            options: [("N", "Network"), ("A", "Adjacent"), ("L", "Local"), ("P", "Physical")]),
        Metric(key: "AC", name: "Attack complexity", options: [("L", "Low"), ("H", "High")]),
        Metric(key: "PR", name: "Privileges required", options: [("N", "None"), ("L", "Low"), ("H", "High")]),
        Metric(key: "UI", name: "User interaction", options: [("N", "None"), ("R", "Required")]),
        Metric(key: "S", name: "Scope", options: [("U", "Unchanged"), ("C", "Changed")]),
        Metric(key: "C", name: "Confidentiality", options: [("N", "None"), ("L", "Low"), ("H", "High")]),
        Metric(key: "I", name: "Integrity", options: [("N", "None"), ("L", "Low"), ("H", "High")]),
        Metric(key: "A", name: "Availability", options: [("N", "None"), ("L", "Low"), ("H", "High")]),
    ]

    /// The value of each metric, such as `["AV": "N"]`.
    public var values: [String: String]

    /// Reachable over the network with no privileges or interaction, and no impact yet.
    public init() {
        values = ["AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "N", "I": "N", "A": "N"]
    }

    /// Parses a vector such as `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`, or fails on anything else.
    public init?(vector: String) {
        guard vector.hasPrefix("CVSS:3.1/") else { return nil }
        let pairs = vector.dropFirst(9).split(separator: "/").map { $0.split(separator: ":").map(String.init) }
        values = Dictionary(pairs.filter { $0.count == 2 }.map { ($0[0], $0[1]) }) { first, _ in first }
        let valid = Self.metrics.allSatisfy { metric in metric.options.contains { $0.value == values[metric.key] } }
        guard valid && values.count == Self.metrics.count else { return nil }
    }

    public var vector: String {
        "CVSS:3.1/" + Self.metrics.map { "\($0.key):\(values[$0.key] ?? "")" }.joined(separator: "/")
    }

    public var score: Double {
        let changed = values["S"] == "C"
        let impact = ["C", "I", "A"].map { Self.impact[values[$0] ?? ""] ?? 0 }
        let iss = 1 - impact.reduce(1) { $0 * (1 - $1) }
        let impactScore = changed ? 7.52 * (iss - 0.029) - 3.25 * pow(iss - 0.02, 15) : 6.42 * iss
        let privileges = changed ? Self.privilegesChanged : Self.privileges
        let vector = Self.attackVector[values["AV"] ?? ""] ?? 0
        let complexity = values["AC"] == "H" ? 0.44 : 0.77
        let interaction = values["UI"] == "R" ? 0.62 : 0.85
        let exploitability = 8.22 * vector * complexity * (privileges[values["PR"] ?? ""] ?? 0) * interaction
        guard impactScore > 0 else { return 0 }
        return Self.roundUp(min((impactScore + exploitability) * (changed ? 1.08 : 1), 10))
    }

    public var severity: String {
        switch score {
        case 9...: "CRITICAL"
        case 7...: "HIGH"
        case 4...: "MEDIUM"
        case 0.1...: "LOW"
        default: "NONE"
        }
    }

    private static let impact: [String: Double] = ["H": 0.56, "L": 0.22]
    private static let attackVector: [String: Double] = ["N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2]
    private static let privileges: [String: Double] = ["N": 0.85, "L": 0.62, "H": 0.27]
    private static let privilegesChanged: [String: Double] = ["N": 0.85, "L": 0.68, "H": 0.5]

    var json: JSONValue {
        .object([
            "version": .string("3.1"), "vectorString": .string(vector), "baseScore": .number(score),
            "baseSeverity": .string(severity),
        ])
    }

    /// The specification's round-up to one decimal, which avoids floating-point errors such as 4.000001 → 4.1.
    private static func roundUp(_ value: Double) -> Double {
        let scaled = Int((value * 100_000).rounded())
        return scaled % 10_000 == 0 ? Double(scaled) / 100_000 : Double(scaled / 10_000 + 1) / 10
    }
}
