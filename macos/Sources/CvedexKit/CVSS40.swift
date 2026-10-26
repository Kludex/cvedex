import Foundation

/// A CVSS 4.0 score, computed from its vector as FIRST's reference calculator does.
///
/// The form edits the base metrics. Threat, environmental and supplemental metrics in a vector you paste or
/// import are kept, and count toward the score as the specification says.
public struct CVSS40: CVSSScore {
    public static let metrics = [
        CVSSMetric(
            key: "AV", name: "Attack vector",
            options: [("N", "Network"), ("A", "Adjacent"), ("L", "Local"), ("P", "Physical")]),
        CVSSMetric(key: "AC", name: "Attack complexity", options: [("L", "Low"), ("H", "High")]),
        CVSSMetric(key: "AT", name: "Attack requirements", options: [("N", "None"), ("P", "Present")]),
        CVSSMetric(key: "PR", name: "Privileges required", options: [("N", "None"), ("L", "Low"), ("H", "High")]),
        CVSSMetric(key: "UI", name: "User interaction", options: [("N", "None"), ("P", "Passive"), ("A", "Active")]),
        CVSSMetric(key: "VC", name: "Confidentiality", options: impact),
        CVSSMetric(key: "VI", name: "Integrity", options: impact),
        CVSSMetric(key: "VA", name: "Availability", options: impact),
        CVSSMetric(key: "SC", name: "Confidentiality", options: impact),
        CVSSMetric(key: "SI", name: "Integrity", options: impact),
        CVSSMetric(key: "SA", name: "Availability", options: impact),
    ]

    /// Every metric in the order a vector lists them, with the values it may take.
    static let order: [(key: String, values: [String])] =
        metrics.map { ($0.key, $0.options.map(\.value)) } + optional

    private static let optional: [(key: String, values: [String])] = [
        ("E", ["X", "A", "P", "U"]),
        ("CR", ["X", "H", "M", "L"]), ("IR", ["X", "H", "M", "L"]), ("AR", ["X", "H", "M", "L"]),
        ("MAV", ["X", "N", "A", "L", "P"]), ("MAC", ["X", "L", "H"]), ("MAT", ["X", "N", "P"]),
        ("MPR", ["X", "N", "L", "H"]), ("MUI", ["X", "N", "P", "A"]),
        ("MVC", ["X", "H", "L", "N"]), ("MVI", ["X", "H", "L", "N"]), ("MVA", ["X", "H", "L", "N"]),
        ("MSC", ["X", "H", "L", "N"]), ("MSI", ["X", "S", "H", "L", "N"]), ("MSA", ["X", "S", "H", "L", "N"]),
        ("S", ["X", "N", "P"]), ("AU", ["X", "N", "Y"]), ("R", ["X", "A", "U", "I"]), ("V", ["X", "D", "C"]),
        ("RE", ["X", "L", "M", "H"]), ("U", ["X", "Clear", "Green", "Amber", "Red"]),
    ]

    /// The value of each metric in the vector, such as `["AV": "N"]`. Metrics left out are `X`, not defined.
    public var values: [String: String]

    /// Reachable over the network with no privileges or interaction, and no impact yet.
    public init() {
        values = Dictionary(uniqueKeysWithValues: Self.metrics.map { ($0.key, $0.options[0].value) })
    }

    /// Parses a vector such as `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`, with every base
    /// metric and the others in the specification's order, or fails.
    public init?(vector: String) {
        var parts = vector.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard parts.removeFirst() == "CVSS:4.0" else { return nil }
        var start = 0
        values = [:]
        for part in parts {
            let pair = part.split(separator: ":", maxSplits: 1).map(String.init)
            guard pair.count == 2, let i = Self.order[start...].firstIndex(where: { $0.key == pair[0] }),
                Self.order[i].values.contains(pair[1]), i == start || start >= Self.metrics.count
            else { return nil }
            values[pair[0]] = pair[1]
            start = i + 1
        }
        guard Self.metrics.allSatisfy({ values[$0.key] != nil }) else { return nil }
    }

    public var vector: String {
        (["CVSS:4.0"]
            + Self.order.compactMap { metric in
                values[metric.key].flatMap { $0 == "X" ? nil : "\(metric.key):\($0)" }
            }).joined(separator: "/")
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

    public var score: Double {
        guard ["VC", "VI", "VA", "SC", "SI", "SA"].contains(where: { effective($0) != "N" }) else { return 0 }
        let eq = equivalenceClasses
        // The table has every combination of classes a valid vector falls in.
        let value = Self.macroVectors[macro(eq)]!
        let lower36: Double? =
            switch (eq[2], eq[5]) {
            case (0, 0): [macro(eq, 5), macro(eq, 2)].compactMap { Self.macroVectors[$0] }.max()
            case (1, 0): Self.macroVectors[macro(eq, 5)]
            default: Self.macroVectors[macro(eq, 2)]
            }
        let lower = [
            Self.macroVectors[macro(eq, 0)], Self.macroVectors[macro(eq, 1)], lower36,
            Self.macroVectors[macro(eq, 3)], Self.macroVectors[macro(eq, 4)],
        ]

        let maxima = [
            Self.maxComposed[0][eq[0]], Self.maxComposed[1][eq[1]], Self.maxComposed36[eq[2]][eq[5]],
            Self.maxComposed[2][eq[3]], Self.maxComposed[3][eq[4]],
        ]
        var candidates: [String] = [""]
        for options in maxima {
            candidates = candidates.flatMap { prefix in options.map { prefix + $0 } }
        }
        var distances: [String: Double] = [:]
        for candidate in candidates {
            distances = self.distances(to: candidate)
            if distances.values.allSatisfy({ $0 >= 0 }) { break }
        }

        let current = [
            ["AV", "PR", "UI"], ["AC", "AT"], ["VC", "VI", "VA", "CR", "IR", "AR"], ["SC", "SI", "SA"],
        ].map { $0.reduce(0) { $0 + distances[$1]! } }
        let depths = [
            Self.maxSeverity[0][eq[0]], Self.maxSeverity[1][eq[1]], Self.maxSeverity36[eq[2]][eq[5]],
            Self.maxSeverity[2][eq[3]],
        ].map { $0 * 0.1 }
        var total = 0.0
        var count = 0
        for (k, next) in lower.enumerated() {
            guard let next else { continue }
            count += 1
            // EQ5 has no depth, so its share is always zero.
            if k < 4 { total += (value - next) * (current[k] / depths[k]) }
        }
        let score = min(10, max(0, value - (count == 0 ? 0 : total / Double(count))))
        return ((score + 1e-6) * 10).rounded(.toNearestOrAwayFromZero) / 10
    }

    var json: JSONValue {
        .object([
            "version": .string("4.0"), "vectorString": .string(vector), "baseScore": .number(score),
            "baseSeverity": .string(severity),
        ])
    }

    /// The value that counts: a modified environmental value when set, else the worst case for undefined ones.
    private func effective(_ metric: String) -> String {
        let value = values[metric] ?? "X"
        if value == "X", let worst = ["E": "A", "CR": "H", "IR": "H", "AR": "H"][metric] { return worst }
        if let modified = values["M" + metric], modified != "X" { return modified }
        return value
    }

    private var equivalenceClasses: [Int] {
        let (av, pr, ui) = (effective("AV"), effective("PR"), effective("UI"))
        let (vc, vi, va) = (effective("VC"), effective("VI"), effective("VA"))
        let eq1 =
            av == "N" && pr == "N" && ui == "N" ? 0 : (av == "N" || pr == "N" || ui == "N") && av != "P" ? 1 : 2
        let eq2 = effective("AC") == "L" && effective("AT") == "N" ? 0 : 1
        let eq3 = vc == "H" && vi == "H" ? 0 : vc == "H" || vi == "H" || va == "H" ? 1 : 2
        let eq4 =
            effective("MSI") == "S" || effective("MSA") == "S"
            ? 0 : effective("SC") == "H" || effective("SI") == "H" || effective("SA") == "H" ? 1 : 2
        let eq5 = ["A": 0, "P": 1, "U": 2][effective("E")]!
        let high = [("CR", vc), ("IR", vi), ("AR", va)].contains { effective($0.0) == "H" && $0.1 == "H" }
        return [eq1, eq2, eq3, eq4, eq5, high ? 0 : 1]
    }

    /// The MacroVector key, with the class at `lower` one step less severe.
    private func macro(_ eq: [Int], _ lower: Int? = nil) -> String {
        eq.indices.map { String(eq[$0] + ($0 == lower ? 1 : 0)) }.joined()
    }

    private func distances(to candidate: String) -> [String: Double] {
        let maximum = Dictionary(
            uniqueKeysWithValues: candidate.split(separator: "/").map { $0.split(separator: ":").map(String.init) }
                .map { ($0[0], $0[1]) })
        // Every candidate names each metric with a level, and effective values are always ones with a level.
        return Dictionary(
            uniqueKeysWithValues: Self.levels.map { metric, levels in
                (metric, levels[effective(metric)]! - levels[maximum[metric]!]!)
            })
    }

    private static let impact = [("N", "None"), ("L", "Low"), ("H", "High")]

    private static let levels: [String: [String: Double]] = [
        "AV": ["N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3], "PR": ["N": 0.0, "L": 0.1, "H": 0.2],
        "UI": ["N": 0.0, "P": 0.1, "A": 0.2], "AC": ["L": 0.0, "H": 0.1], "AT": ["N": 0.0, "P": 0.1],
        "VC": ["H": 0.0, "L": 0.1, "N": 0.2], "VI": ["H": 0.0, "L": 0.1, "N": 0.2],
        "VA": ["H": 0.0, "L": 0.1, "N": 0.2], "SC": ["H": 0.1, "L": 0.2, "N": 0.3],
        "SI": ["S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3], "SA": ["S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3],
        "CR": ["H": 0.0, "M": 0.1, "L": 0.2], "IR": ["H": 0.0, "M": 0.1, "L": 0.2],
        "AR": ["H": 0.0, "M": 0.1, "L": 0.2], "E": ["U": 0.2, "P": 0.1, "A": 0],
    ]

    /// The most severe vectors of each class of EQ1, EQ2, EQ4 and EQ5.
    private static let maxComposed = [
        [
            ["AV:N/PR:N/UI:N/"], ["AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"],
            ["AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"],
        ],
        [["AC:L/AT:N/"], ["AC:H/AT:N/", "AC:L/AT:P/"]],
        [["SC:H/SI:S/SA:S/"], ["SC:H/SI:H/SA:H/"], ["SC:L/SI:L/SA:L/"]],
        [["E:A/"], ["E:P/"], ["E:U/"]],
    ]

    /// The most severe vectors of EQ3 and EQ6 together, by EQ3 then EQ6.
    private static let maxComposed36 = [
        [["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"], ["VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"]],
        [
            ["VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"],
            [
                "VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/", "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/", "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/",
                "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/", "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/",
            ],
        ],
        [[], ["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"]],
    ]

    /// How deep each class of EQ1, EQ2 and EQ4 is, in steps of 0.1.
    private static let maxSeverity: [[Double]] = [[1, 4, 5], [1, 2], [6, 5, 4]]
    private static let maxSeverity36: [[Double]] = [[7, 6], [8, 8], [0, 10]]
}
