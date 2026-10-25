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

    public struct User: Decodable, Equatable, Sendable {
        public let username: String
    }

    public struct Org: Decodable, Equatable, Sendable {
        public let name: String
        public let shortName: String
    }
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

/// The parts of a CVE record the app shows.
public struct Record: Decodable, Equatable, Sendable {
    public let state: String
    public let datePublished: String?
    public let title: String?
    public let descriptions: [String]
    public let affected: [String]
    public let cwes: [String]
    public let references: [String]
    public let rejectedReasons: [String]

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
        struct Reference: Decodable { let url: String }

        let title: String?
        let descriptions: [Text]?
        let affected: [Product]?
        let problemTypes: [ProblemType]?
        let references: [Reference]?
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
            let name = [product.vendor, product.product].compactMap(\.self).joined(separator: " ")
            let versions = (product.versions ?? []).map { v in
                if let limit = v.lessThan { return "\(v.version) to before \(limit): \(v.status)" }
                if let limit = v.lessThanOrEqual { return "\(v.version) to \(limit): \(v.status)" }
                return "\(v.version): \(v.status)"
            }
            return ([name] + versions).joined(separator: "\n")
        }
        cwes = (cna.problemTypes ?? []).flatMap(\.descriptions).map(\.description)
        references = (cna.references ?? []).map(\.url)
        rejectedReasons = (cna.rejectedReasons ?? []).map(\.value)
    }
}
