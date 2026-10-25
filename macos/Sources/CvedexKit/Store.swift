import Foundation
import Observation

/// The app's state, kept in sync with CVE Services through `cvedex`.
@Observable @MainActor
public final class Store {
    public private(set) var status: Status?
    public private(set) var ids: [CVEID] = []
    public private(set) var loading = false
    /// The last failure to load, shown over the list.
    public var error: CLIError?

    private let cli: CLI
    private let decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return decoder
    }()

    public init(cli: CLI) {
        self.cli = cli
    }

    /// Checks who is logged in, then loads their CVE IDs.
    public func refresh() async {
        loading = true
        defer { loading = false }
        do {
            let status = try decoder.decode(Status.self, from: await cli.run(["status"]))
            self.status = status
            ids = status.loggedIn ? try decoder.decode([CVEID]?.self, from: await cli.run(["list"])) ?? [] : []
            error = nil
        } catch {
            self.error = Self.cliError(error)
        }
    }

    /// Saves credentials after CVE Services accepts them. The key goes to the keychain.
    public func login(url: String, org: String, user: String, key: String) async throws {
        _ = try await cli.run(["login", "--url", url, "--org", org, "--user", user], input: Data((key + "\n").utf8))
        await refresh()
    }

    public func logout() async throws {
        _ = try await cli.run(["logout"])
        await refresh()
    }

    /// Reserves one CVE ID for this year.
    public func reserve() async throws -> String? {
        let reserved = try decoder.decode([CVEID].self, from: await cli.run(["reserve"]))
        await refresh()
        return reserved.first?.cveId
    }

    /// The record of `id`, or nil while it has none.
    public func record(_ id: String) async throws -> Record? {
        do {
            return try decoder.decode(Record.self, from: await cli.run(["show", id]))
        } catch let error as CLIError where error.code == "CVE_RECORD_DNE" {
            return nil
        }
    }

    /// The CNA container of `id` to edit, without the `providerMetadata` CVE Services fills in,
    /// or a template while it has no record.
    public func draft(_ id: String) async throws -> String {
        let data: Data
        do {
            data = try await cli.run(["show", id])
        } catch let error as CLIError where error.code == "CVE_RECORD_DNE" {
            return Self.template
        }
        let record = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        let containers = record?["containers"] as? [String: Any]
        guard var cna = record?["cnaContainer"] as? [String: Any] ?? containers?["cna"] as? [String: Any] else {
            throw CLIError(code: "CVEDEX_ERROR", message: "\(id) has no CNA container")
        }
        cna["providerMetadata"] = nil
        let text = try JSONSerialization.data(
            withJSONObject: cna, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
        return String(decoding: text, as: UTF8.self) + "\n"
    }

    /// What is wrong with a CNA container, one line each, or nothing when it is valid.
    public func check(_ container: String) async -> [String] {
        do {
            _ = try await cli.run(["record", "check", "-"], input: Data(container.utf8))
            return []
        } catch {
            let error = Self.cliError(error)
            return error.problems.isEmpty ? [error.message] : error.problems
        }
    }

    /// Publishes or updates the record of `id`, and says what happened.
    public func send(_ id: String, container: String, publish: Bool) async throws -> String {
        let written = try await cli.run(
            [publish ? "publish" : "update", id, "-", "--yes"], input: Data(container.utf8))
        await refresh()
        if (try? decoder.decode(Written.self, from: written))?.state == "in_review" {
            return "Sent \(id) for review"
        }
        return "\(publish ? "Published" : "Updated") \(id)"
    }

    public func reject(_ id: String, reason: String) async throws {
        _ = try await cli.run(["reject", id, "--reason", reason, "--yes"])
        await refresh()
    }

    /// A CNA container built from a GitHub repository advisory.
    public func fromAdvisory(_ url: String) async throws -> String {
        String(decoding: try await cli.run(["record", "from-advisory", url]), as: UTF8.self)
    }

    private struct Written: Decodable { let state: String? }

    private static func cliError(_ error: any Error) -> CLIError {
        error as? CLIError ?? CLIError(code: "CVEDEX_ERROR", message: error.localizedDescription)
    }

    static let template = """
        {
          "title": "",
          "descriptions": [{"lang": "en", "value": ""}],
          "affected": [
            {
              "vendor": "",
              "product": "",
              "versions": [{"version": "0", "lessThan": "", "status": "affected", "versionType": "semver"}]
            }
          ],
          "problemTypes": [{"descriptions": [{"lang": "en", "type": "CWE", "cweId": "CWE-", "description": ""}]}],
          "references": [{"url": ""}]
        }

        """
}
