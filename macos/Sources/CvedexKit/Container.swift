import Foundation

/// A CNA container being built. Typed access to the fields the form edits, over the JSON it came from,
/// so everything else in the record is kept as it was.
public struct Container: Equatable, Sendable {
    public var fields: [String: JSONValue]

    public init(fields: [String: JSONValue]) {
        self.fields = fields
    }

    /// Parses a CNA container, failing on anything but a JSON object.
    public init(text: String) throws {
        guard case .object(let fields) = try JSONDecoder().decode(JSONValue.self, from: Data(text.utf8)) else {
            throw CLIError(code: "CVEDEX_ERROR", message: "A CNA container is a JSON object")
        }
        self.fields = fields
    }

    /// A container for a new record: one product with one version range, and one reference to fill in.
    public static let blank = Container(fields: [
        "descriptions": .array([.object(["lang": .string("en"), "value": .string("")])]),
        "affected": .array([.object(Product.blank.fields)]),
        "references": .array([.object(Reference.blank.fields)]),
    ])

    public var text: String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        return String(decoding: (try? encoder.encode(fields)) ?? Data(), as: UTF8.self) + "\n"
    }

    public var title: String {
        get { fields[optional: "title"] }
        set { fields[optional: "title"] = newValue }
    }

    /// The English description, which CVE Services requires.
    public var summary: String {
        get { descriptions[summaryIndex].object?[text: "value"] ?? "" }
        set {
            var list = descriptions
            var description = list[summaryIndex].object ?? [:]
            description[text: "value"] = newValue
            list[summaryIndex] = .object(description)
            fields["descriptions"] = .array(list)
        }
    }

    public var summaryPath: String { "/descriptions/\(summaryIndex)/value" }

    public var products: [Product] {
        get { fields.items("affected") }
        set { fields.setItems("affected", newValue) }
    }

    public var weaknesses: [Weakness] {
        get {
            (fields["problemTypes"]?.array ?? []).flatMap { $0.object?["descriptions"]?.array ?? [] }
                .map { Weakness(fields: $0.object ?? [:]) }
        }
        set {
            let descriptions = JSONValue.array(newValue.map { .object($0.fields) })
            fields["problemTypes"] = newValue.isEmpty ? nil : .array([.object(["descriptions": descriptions])])
        }
    }

    /// Where each weakness sits in the record, to match problems to it.
    public var weaknessPaths: [String] {
        (fields["problemTypes"]?.array ?? []).enumerated().flatMap { type, problemType in
            (problemType.object?["descriptions"]?.array ?? []).indices.map {
                "/problemTypes/\(type)/descriptions/\($0)"
            }
        }
    }

    public var references: [Reference] {
        get { fields.items("references") }
        set { fields.setItems("references", newValue) }
    }

    public var credits: [Credit] {
        get { fields.items("credits") }
        set { fields.setItems("credits", newValue, removeWhenEmpty: true) }
    }

    /// The CVSS 3.1 score, if the record has one.
    public var cvss: CVSS31? {
        get { score("cvssV3_1", CVSS31.init(vector:)) }
        set { setScore("cvssV3_1", newValue?.json) }
    }

    /// The CVSS 4.0 score, if the record has one.
    public var cvss4: CVSS40? {
        get { score("cvssV4_0", CVSS40.init(vector:)) }
        set { setScore("cvssV4_0", newValue?.json) }
    }

    /// The other scores in the record, such as SSVC, which the form shows but does not edit.
    public var otherScores: [String] {
        let edited = [cvss.map { _ in "cvssV3_1" }, cvss4.map { _ in "cvssV4_0" }]
        return metrics.compactMap(\.object).flatMap { metric in
            metric.filter { !edited.contains($0.key) }.sorted { $0.key < $1.key }.map { key, value in
                let score = value.object
                let name = score?["version"]?.string.map { "CVSS \($0)" } ?? key
                let parts = [score?["baseScore"]?.number.map { String($0) }, score?["vectorString"]?.string]
                return ([name] + parts.compactMap(\.self)).joined(separator: " ")
            }
        }
    }

    private func score<Score>(_ key: String, _ parse: (String) -> Score?) -> Score? {
        metrics.lazy.compactMap { $0.object?[key]?.object?["vectorString"]?.string }.compactMap(parse).first
    }

    private mutating func setScore(_ key: String, _ json: JSONValue?) {
        var list = metrics.filter { $0.object?[key] == nil }
        if let json {
            list.insert(.object([key: json]), at: 0)
        }
        fields["metrics"] = list.isEmpty ? nil : .array(list)
    }

    private var descriptions: [JSONValue] {
        let list = fields["descriptions"]?.array ?? []
        return list.isEmpty ? [.object(["lang": .string("en")])] : list
    }

    private var summaryIndex: Int {
        descriptions.firstIndex { $0.object?["lang"]?.string?.hasPrefix("en") == true } ?? 0
    }

    private var metrics: [JSONValue] { fields["metrics"]?.array ?? [] }
}

/// A part of a container that the form edits as one row or group.
public protocol ContainerItem: Equatable, Sendable {
    var fields: [String: JSONValue] { get set }
    init(fields: [String: JSONValue])
}

/// An affected product and its versions.
public struct Product: ContainerItem {
    public var fields: [String: JSONValue]

    public init(fields: [String: JSONValue]) {
        self.fields = fields
    }

    public static let blank = Product(fields: [
        "vendor": .string(""), "product": .string(""), "defaultStatus": .string("unaffected"),
        "versions": .array([.object(Version.blank.fields)]),
    ])

    public var vendor: String {
        get { fields[text: "vendor"] }
        set { fields[text: "vendor"] = newValue }
    }

    public var product: String {
        get { fields[text: "product"] }
        set { fields[text: "product"] = newValue }
    }

    public var repo: String {
        get { fields[optional: "repo"] }
        set { fields[optional: "repo"] = newValue }
    }

    /// The package registry, such as `https://pypi.org`, set with `packageName`.
    public var collectionURL: String {
        get { fields[optional: "collectionURL"] }
        set { fields[optional: "collectionURL"] = newValue }
    }

    public var packageName: String {
        get { fields[optional: "packageName"] }
        set { fields[optional: "packageName"] = newValue }
    }

    /// The status of versions no range covers.
    public var defaultStatus: String {
        get { fields["defaultStatus"]?.string ?? "unknown" }
        set { fields["defaultStatus"] = .string(newValue) }
    }

    public var versions: [Version] {
        get { fields.items("versions") }
        set { fields.setItems("versions", newValue, removeWhenEmpty: true) }
    }

    /// How the product's versions compare, such as `semver`. Setting it sets it on every version.
    public var versionType: String {
        get { versions.lazy.map(\.versionType).first { !$0.isEmpty } ?? "" }
        set {
            versions = versions.map {
                var version = $0
                version.versionType = newValue
                return version
            }
        }
    }

    /// Adds a version range, compared the way the product's other versions are.
    public mutating func addVersion() {
        var version = Version.blank
        if !versionType.isEmpty { version.versionType = versionType }
        versions.append(version)
    }

    public static let registries: [(name: String, url: String)] = [
        ("PyPI", "https://pypi.org"), ("npm", "https://www.npmjs.com"), ("crates.io", "https://crates.io"),
        ("Go", "https://pkg.go.dev"), ("Maven Central", "https://repo.maven.apache.org/maven2"),
        ("RubyGems", "https://rubygems.org"), ("NuGet", "https://www.nuget.org"),
        ("Packagist", "https://packagist.org"),
    ]
}

/// A version, or a range of versions, and whether it is affected.
public struct Version: ContainerItem {
    public var fields: [String: JSONValue]

    public init(fields: [String: JSONValue]) {
        self.fields = fields
    }

    /// Where a range ends. `single` is the version alone.
    public enum Range: String, CaseIterable, Sendable {
        case single
        case below = "lessThan"
        case through = "lessThanOrEqual"
    }

    public static let blank = Version(fields: [
        "version": .string("0"), "lessThan": .string(""), "status": .string("affected"),
        "versionType": .string("semver"),
    ])

    public static let types = ["semver", "python", "maven", "git", "custom"]

    public var version: String {
        get { fields[text: "version"] }
        set { fields[text: "version"] = newValue }
    }

    public var status: String {
        get { fields[text: "status"] }
        set { fields[text: "status"] = newValue }
    }

    public var versionType: String {
        get { fields[optional: "versionType"] }
        set { fields[optional: "versionType"] = newValue }
    }

    public var range: Range {
        get { Range.allCases.dropFirst().first { fields[$0.rawValue] != nil } ?? .single }
        set {
            let limit = self.limit
            fields[Range.below.rawValue] = nil
            fields[Range.through.rawValue] = nil
            if newValue != .single {
                fields[newValue.rawValue] = .string(limit)
                if versionType.isEmpty { versionType = "semver" }
            }
        }
    }

    /// The end of the range, empty for a single version.
    public var limit: String {
        get { range == .single ? "" : fields[text: range.rawValue] }
        set { if range != .single { fields[text: range.rawValue] = newValue } }
    }
}

/// A CWE weakness.
public struct Weakness: ContainerItem {
    public var fields: [String: JSONValue]

    public init(fields: [String: JSONValue]) {
        self.fields = fields
    }

    public static let blank = Weakness(fields: [
        "lang": .string("en"), "type": .string("CWE"), "cweId": .string(""), "description": .string(""),
    ])

    /// The CWE ID, such as `CWE-22`. Setting a known one names the weakness, unless you wrote your own name.
    public var cweId: String {
        get { fields[text: "cweId"] }
        set {
            let named = description.isEmpty || description == CWE.label(cweId)
            fields[text: "cweId"] = newValue
            if named, let label = CWE.label(newValue) { description = label }
        }
    }

    public var description: String {
        get { fields[text: "description"] }
        set { fields[text: "description"] = newValue }
    }
}

/// A link with what it points to.
public struct Reference: ContainerItem {
    public var fields: [String: JSONValue]

    public init(fields: [String: JSONValue]) {
        self.fields = fields
    }

    public static let blank = Reference(fields: ["url": .string("")])

    public static let tags = [
        "vendor-advisory", "patch", "release-notes", "issue-tracking", "exploit", "mitigation",
        "technical-description", "third-party-advisory", "related",
    ]

    public var url: String {
        get { fields[text: "url"] }
        set { fields[text: "url"] = newValue }
    }

    public var tags: [String] {
        get { fields["tags"]?.array?.compactMap(\.string) ?? [] }
        set { fields["tags"] = newValue.isEmpty ? nil : .array(newValue.map(JSONValue.string)) }
    }
}

/// Someone to thank.
public struct Credit: ContainerItem {
    public var fields: [String: JSONValue]

    public init(fields: [String: JSONValue]) {
        self.fields = fields
    }

    public static let blank = Credit(fields: [
        "lang": .string("en"), "value": .string(""), "type": .string("finder"),
    ])

    public static let types = [
        "finder", "reporter", "analyst", "coordinator", "remediation developer", "remediation reviewer",
        "remediation verifier", "tool", "sponsor", "other",
    ]

    public var name: String {
        get { fields[text: "value"] }
        set { fields[text: "value"] = newValue }
    }

    public var type: String {
        get { fields[text: "type"] }
        set { fields[text: "type"] = newValue }
    }
}

extension [String: JSONValue] {
    /// A required string, kept when empty so the schema check names it.
    fileprivate subscript(text key: String) -> String {
        get { self[key]?.string ?? "" }
        set { self[key] = .string(newValue) }
    }

    /// An optional string, removed when empty.
    fileprivate subscript(optional key: String) -> String {
        get { self[key]?.string ?? "" }
        set { self[key] = newValue.isEmpty ? nil : .string(newValue) }
    }

    fileprivate func items<Item: ContainerItem>(_ key: String) -> [Item] {
        (self[key]?.array ?? []).map { Item(fields: $0.object ?? [:]) }
    }

    fileprivate mutating func setItems(_ key: String, _ items: [some ContainerItem], removeWhenEmpty: Bool = false) {
        self[key] = removeWhenEmpty && items.isEmpty ? nil : .array(items.map { .object($0.fields) })
    }
}
