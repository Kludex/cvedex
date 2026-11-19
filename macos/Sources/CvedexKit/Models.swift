import Foundation

/// What `cvedex status` reports: the server, and who is logged in, if anyone.
public struct Status: Decodable, Equatable, Sendable {
    public let url: String
    public let server: String
    public let version: String?
    public let user: User?
    public let org: Org?
    /// Set when the user is a cvedexd submitter.
    public let submitter: String?

    public var loggedIn: Bool { user != nil || submitter != nil }
    public var isProduction: Bool { url == "https://cveawg.mitre.org" }

    public struct User: Decodable, Equatable, Sendable {
        public let username: String
    }

    public struct Org: Decodable, Equatable, Sendable {
        public let name: String
        public let shortName: String
    }
}

/// An account `cvedex` is logged in to, as `cvedex accounts` prints it.
public struct Account: Decodable, Equatable, Sendable {
    public let url: String
    public let user: String
    /// Whether it is the one in use.
    public let active: Bool
}

/// A CVE ID as `cvedex list` prints it.
public struct CVEID: Decodable, Equatable, Hashable, Identifiable, Sendable {
    public let cveId: String
    public let state: String
    public let reserved: String?
    public let cvedexd: Local?

    public var id: String { cveId }

    /// What cvedexd knows of an ID a submitter reserved through it.
    public struct Local: Decodable, Equatable, Hashable, Sendable {
        public let note: String?
    }
}

/// A record sent for review on cvedexd or a GitHub repository, as `cvedex review` prints it.
public struct Review: Decodable, Equatable, Sendable {
    public let cveId: String
    public let submitter: String
    /// `publish`, for a new or updated record, or `reject`.
    public let action: String
    /// What approving names, so a record that changed since you read it is never approved by mistake.
    public let revision: Int
    public let record: Record
    /// What the record changes in the published one. Empty for a first record.
    public let changes: [DiffLine]

    private enum Keys: String, CodingKey { case cveId, submitter, action, revision, record, published }

    public init(from decoder: any Decoder) throws {
        let fields = try decoder.container(keyedBy: Keys.self)
        cveId = try fields.decode(String.self, forKey: .cveId)
        submitter = try fields.decode(String.self, forKey: .submitter)
        action = try fields.decode(String.self, forKey: .action)
        revision = try fields.decode(Int.self, forKey: .revision)
        record = try fields.decode(Record.self, forKey: .record)
        let sent = Self.container(try fields.decode(JSONValue.self, forKey: .record))
        let published = Self.container(try fields.decodeIfPresent(JSONValue.self, forKey: .published))
        if let sent, let published {
            changes = DiffLine.lines(from: published, to: sent)
        } else {
            changes = []
        }
    }

    /// The CNA container of a record as cvedexd keeps it, `{"cnaContainer": ...}`, as text.
    private static func container(_ record: JSONValue?) -> String? {
        record?.object?["cnaContainer"]?.object.map { Container(fields: $0).text }
    }
}

/// The parts of a CVE record the app shows.
public struct Record: Decodable, Equatable, Sendable {
    public let state: String
    public let datePublished: String?
    public let title: String?
    public let descriptions: [String]
    public let affected: [Affected]
    public let cwes: [String]
    public let scores: [Score]
    public let references: [Link]
    public let credits: [String]
    public let rejectedReasons: [String]

    public struct Affected: Equatable, Sendable {
        public let name: String
        /// Each version or range, such as `0 to before 1.2.3`, and its status.
        public let versions: [(range: String, status: String)]

        public static func == (lhs: Self, rhs: Self) -> Bool {
            lhs.name == rhs.name && lhs.versions.elementsEqual(rhs.versions) { $0 == $1 }
        }
    }

    public struct Score: Equatable, Sendable {
        public let version: String
        public let score: Double
        public let severity: String
        public let vector: String
    }

    public struct Link: Equatable, Sendable {
        public let url: String
        public let tags: [String]
    }

    private enum Keys: String, CodingKey { case cveMetadata, containers, cnaContainer, cna }

    private struct Metadata: Decodable {
        let state: String?
        let datePublished: String?
    }

    private struct Container: Decodable {
        struct Text: Decodable { let value: String }
        struct Product: Decodable {
            struct Version: Decodable {
                let version: String
                let lessThan: String?
                let lessThanOrEqual: String?
                let status: String
            }
            let vendor: String?
            let product: String?
            let versions: [Version]?
        }
        struct ProblemType: Decodable {
            struct Description: Decodable { let description: String }
            let descriptions: [Description]
        }
        struct Reference: Decodable {
            let url: String
            let tags: [String]?
        }
        struct Credit: Decodable {
            let value: String
            let type: String?
        }

        let title: String?
        let descriptions: [Text]?
        let affected: [Product]?
        let problemTypes: [ProblemType]?
        let metrics: [JSONValue]?
        let references: [Reference]?
        let credits: [Credit]?
        let rejectedReasons: [Text]?
    }

    public init(from decoder: any Decoder) throws {
        let fields = try decoder.container(keyedBy: Keys.self)
        let metadata = try fields.decodeIfPresent(Metadata.self, forKey: .cveMetadata)
        let cna =
            try fields.decodeIfPresent(Container.self, forKey: .cnaContainer)
            ?? fields.nestedContainer(keyedBy: Keys.self, forKey: .containers).decode(Container.self, forKey: .cna)
        state = metadata?.state ?? "DRAFT"
        datePublished = metadata?.datePublished
        title = cna.title
        descriptions = (cna.descriptions ?? []).map(\.value)
        affected = (cna.affected ?? []).map { product in
            Affected(
                name: [product.vendor, product.product].compactMap(\.self).joined(separator: " "),
                versions: (product.versions ?? []).map { v in
                    if let limit = v.lessThan { return ("\(v.version) to before \(limit)", v.status) }
                    if let limit = v.lessThanOrEqual { return ("\(v.version) to \(limit)", v.status) }
                    return (v.version, v.status)
                })
        }
        cwes = (cna.problemTypes ?? []).flatMap(\.descriptions).map(\.description)
        scores = (cna.metrics ?? []).compactMap(\.object).flatMap(\.values).compactMap { metric in
            guard let score = metric.object, let version = score["version"]?.string,
                let base = score["baseScore"]?.number, let vector = score["vectorString"]?.string
            else { return nil }
            return Score(version: version, score: base, severity: score["baseSeverity"]?.string ?? "", vector: vector)
        }
        .sorted { $0.version > $1.version }
        references = (cna.references ?? []).map { Link(url: $0.url, tags: $0.tags ?? []) }
        credits = (cna.credits ?? []).map {
            [$0.value, $0.type.map { "(\($0))" }].compactMap(\.self).joined(separator: " ")
        }
        rejectedReasons = (cna.rejectedReasons ?? []).map(\.value)
    }
}
