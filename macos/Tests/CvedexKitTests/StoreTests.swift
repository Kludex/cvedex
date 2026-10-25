import Foundation
import Testing

@testable import CvedexKit

/// A `cvedex` that answers each call with the next scripted reply, and records what it was given.
struct Fake {
    let dir: URL
    var executable: URL { dir.appending(path: "cvedex") }

    init(_ replies: [(stdout: String, stderr: String, code: Int32)]) throws {
        dir = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        for (n, reply) in replies.enumerated() {
            try reply.stdout.write(to: dir.appending(path: "out.\(n + 1)"), atomically: true, encoding: .utf8)
            try reply.stderr.write(to: dir.appending(path: "err.\(n + 1)"), atomically: true, encoding: .utf8)
            try "\(reply.code)".write(to: dir.appending(path: "code.\(n + 1)"), atomically: true, encoding: .utf8)
        }
        try "0".write(to: dir.appending(path: "count"), atomically: true, encoding: .utf8)
        let script = """
            #!/bin/sh
            d=$(dirname "$0")
            n=$(($(cat "$d/count") + 1))
            echo $n > "$d/count"
            printf '%s\\n' "$@" > "$d/args.$n"
            cat > "$d/stdin.$n"
            cat "$d/out.$n"
            cat "$d/err.$n" >&2
            exit "$(cat "$d/code.$n")"
            """
        try script.write(to: executable, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: executable.path)
    }

    /// The arguments of every call so far, joined by spaces.
    var calls: [String] {
        let count = Int((try? String(contentsOf: dir.appending(path: "count"), encoding: .utf8))?.trimmed ?? "") ?? 0
        return (0..<count).map { argsOf($0 + 1).joined(separator: " ") }
    }

    func stdin(_ call: Int) -> String {
        (try? String(contentsOf: dir.appending(path: "stdin.\(call)"), encoding: .utf8)) ?? ""
    }

    private func argsOf(_ call: Int) -> [String] {
        ((try? String(contentsOf: dir.appending(path: "args.\(call)"), encoding: .utf8)) ?? "")
            .split(separator: "\n").map(String.init)
    }
}

extension String {
    fileprivate var trimmed: String { trimmingCharacters(in: .whitespacesAndNewlines) }
}

func ok(_ stdout: String) -> (stdout: String, stderr: String, code: Int32) { (stdout, "", 0) }
func fail(_ stderr: String) -> (stdout: String, stderr: String, code: Int32) { ("", stderr, 1) }

let alice = #"{"url":"https://cveawg-test.mitre.org","server":"CVE Services","user":{"username":"alice@acme.test"}}"#
let loggedOut = #"{"url":"https://cveawg-test.mitre.org","server":"CVE Services"}"#
let reserved = #"[{"cve_id":"CVE-2026-1100","cve_year":"2026","state":"RESERVED","reserved":"2026-01-02T03:04:05Z"}]"#
let notFound = #"{"error":"CVE_RECORD_DNE","message":"The cve record for the cve id does not exist."}"#
let published = """
    {"cveMetadata":{"cveId":"CVE-2026-1099","state":"PUBLISHED","datePublished":"2026-01-02T03:04:05Z"},
     "containers":{"cna":{"providerMetadata":{"orgId":"x"},"title":"widget: Path traversal",
      "descriptions":[{"lang":"en","value":"Widget serves files outside its root."}],
      "affected":[{"vendor":"acme","product":"widget","versions":[
        {"version":"0","lessThan":"1.2.3","status":"affected"},
        {"version":"2.0","lessThanOrEqual":"2.1","status":"affected"},
        {"version":"3.0","status":"unaffected"}]},{"product":"gadget"}],
      "problemTypes":[{"descriptions":[{"lang":"en","description":"CWE-22: Path Traversal"}]}],
      "references":[{"url":"https://github.com/acme/widget/security/advisories/GHSA-xxxx-xxxx-xxxx"}]}}}
    """

@MainActor
@Suite struct StoreTests {
    @Test func refreshLoggedIn() async throws {
        let fake = try Fake([ok(alice), ok(reserved)])
        let store = Store(cli: CLI(executable: fake.executable))
        await store.refresh()
        #expect(store.status?.user?.username == "alice@acme.test")
        #expect(store.ids.map(\.id) == ["CVE-2026-1100"])
        #expect(store.error == nil && !store.loading)
        #expect(fake.calls == ["status --json", "list --json"])
    }

    @Test func refreshLoggedOutOrEmpty() async throws {
        let fake = try Fake([ok(loggedOut), ok(#"{"url":"u","server":"cvedexd","submitter":"bob"}"#), ok("null")])
        let store = Store(cli: CLI(executable: fake.executable))
        await store.refresh()
        #expect(store.status?.loggedIn == false && store.ids.isEmpty)
        await store.refresh()
        #expect(store.status?.loggedIn == true && store.ids.isEmpty)
        #expect(fake.calls == ["status --json", "status --json", "list --json"])
    }

    @Test func refreshFails() async throws {
        let fake = try Fake([fail(#"{"error":"UNAUTHORIZED","message":"Unauthorized"}"#)])
        let store = Store(cli: CLI(executable: fake.executable))
        await store.refresh()
        #expect(store.error == CLIError(code: "UNAUTHORIZED", message: "Unauthorized"))
        let missing = Store(cli: CLI(executable: fake.dir.appending(path: "missing")))
        await missing.refresh()
        #expect(missing.error?.code == "CVEDEX_ERROR")
    }

    @Test func loginAndLogout() async throws {
        let fake = try Fake([ok(""), ok(alice), ok(reserved), ok(""), ok(loggedOut)])
        let store = Store(cli: CLI(executable: fake.executable))
        try await store.login(url: "https://cveawg-test.mitre.org", org: "acme", user: "alice@acme.test", key: "k")
        #expect(fake.stdin(1) == "k\n")
        #expect(store.status?.loggedIn == true)
        try await store.logout()
        #expect(store.status?.loggedIn == false)
        #expect(
            fake.calls == [
                "login --url https://cveawg-test.mitre.org --org acme --user alice@acme.test --json",
                "status --json", "list --json", "logout --json", "status --json",
            ])
    }

    @Test func reserve() async throws {
        let fake = try Fake([ok(reserved), ok(alice), ok(reserved)])
        let store = Store(cli: CLI(executable: fake.executable))
        #expect(try await store.reserve() == "CVE-2026-1100")
        #expect(fake.calls.first == "reserve --json")
    }

    @Test func record() async throws {
        let fake = try Fake([ok(published), fail(notFound), fail(#"{"error":"FORBIDDEN","message":"no"}"#)])
        let store = Store(cli: CLI(executable: fake.executable))
        let record = try #require(try await store.record("CVE-2026-1099"))
        #expect(record.state == "PUBLISHED")
        #expect(record.title == "widget: Path traversal")
        #expect(record.datePublished == "2026-01-02T03:04:05Z")
        #expect(record.descriptions == ["Widget serves files outside its root."])
        #expect(
            record.affected == [
                "acme widget\n0 to before 1.2.3: affected\n2.0 to 2.1: affected\n3.0: unaffected", "gadget",
            ])
        #expect(record.cwes == ["CWE-22: Path Traversal"])
        #expect(record.references == ["https://github.com/acme/widget/security/advisories/GHSA-xxxx-xxxx-xxxx"])
        #expect(try await store.record("CVE-2026-1100") == nil)
        await #expect(throws: CLIError(code: "FORBIDDEN", message: "no")) { try await store.record("CVE-2026-1101") }
    }

    @Test func draftRecord() async throws {
        let rejected = #"{"cnaContainer":{"rejectedReasons":[{"lang":"en","value":"Duplicate."}]}}"#
        let fake = try Fake([
            ok(published), ok(rejected), fail(notFound), ok(#"{"containers":{}}"#),
            fail(#"{"error":"X","message":"x"}"#),
        ])
        let store = Store(cli: CLI(executable: fake.executable))
        let text = try await store.draft("CVE-2026-1099")
        #expect(text.hasPrefix("{\n  \"affected\" : ["))
        #expect(!text.contains("providerMetadata") && text.contains("https://github.com/acme/"))
        #expect(try await store.draft("CVE-2026-1100").contains("\"Duplicate.\""))
        #expect(try await store.draft("CVE-2026-1101") == Store.template)
        await #expect(throws: CLIError(code: "CVEDEX_ERROR", message: "CVE-2026-1102 has no CNA container")) {
            try await store.draft("CVE-2026-1102")
        }
        await #expect(throws: CLIError(code: "X", message: "x")) { try await store.draft("CVE-2026-1103") }
        let decoded = try JSONDecoder().decode(Record.self, from: Data(rejected.utf8))
        #expect(decoded.state == "DRAFT" && decoded.rejectedReasons == ["Duplicate."])
    }

    @Test func check() async throws {
        let invalid = #"{"error":"INVALID_RECORD","message":"m","details":{"problems":["- missing properties"]}}"#
        let fake = try Fake([ok(#"{"valid":true}"#), fail(invalid), fail(#"{"error":"CVEDEX_ERROR","message":"bad"}"#)])
        let store = Store(cli: CLI(executable: fake.executable))
        #expect(await store.check("{}") == [])
        #expect(fake.stdin(1) == "{}")
        #expect(await store.check("{}") == ["- missing properties"])
        #expect(await store.check("[") == ["bad"])
        #expect(fake.calls.first == "record check - --json")
    }

    @Test func send() async throws {
        let fake = try Fake([
            ok("{}"), ok(loggedOut), ok(#"{"state":"in_review"}"#), ok(loggedOut), ok("{}"), ok(loggedOut),
        ])
        let store = Store(cli: CLI(executable: fake.executable))
        #expect(try await store.send("CVE-2026-1100", container: "{}", publish: true) == "Published CVE-2026-1100")
        #expect(
            try await store.send("CVE-2026-1100", container: "{}", publish: true) == "Sent CVE-2026-1100 for review")
        #expect(try await store.send("CVE-2026-1100", container: "{}", publish: false) == "Updated CVE-2026-1100")
        #expect(fake.calls[0] == "publish CVE-2026-1100 - --yes --json")
        #expect(fake.calls[4] == "update CVE-2026-1100 - --yes --json")
    }

    @Test func rejectAndImport() async throws {
        let fake = try Fake([ok("{}"), ok(loggedOut), ok("{\"title\":\"t\"}\n")])
        let store = Store(cli: CLI(executable: fake.executable))
        try await store.reject("CVE-2026-1100", reason: "Duplicate.")
        #expect(fake.calls[0] == "reject CVE-2026-1100 --reason Duplicate. --yes --json")
        #expect(
            try await store.fromAdvisory("https://github.com/a/b/security/advisories/GHSA-x") == "{\"title\":\"t\"}\n")
        #expect(fake.calls[2] == "record from-advisory https://github.com/a/b/security/advisories/GHSA-x --json")
    }
}

@Suite struct CLITests {
    @Test func find() throws {
        let fake = try Fake([])
        #expect(CLI.find(environment: ["PATH": "/nonexistent:\(fake.dir.path)"]) == fake.executable)
        #expect(CLI.find(environment: [:]) == nil)
        let app = fake.dir.appending(path: "cvedex.app/Contents/MacOS")
        try FileManager.default.createDirectory(at: app, withIntermediateDirectories: true)
        try FileManager.default.copyItem(at: fake.executable, to: app.appending(path: "cvedex"))
        let bundle = try #require(Bundle(url: fake.dir.appending(path: "cvedex.app")))
        #expect(CLI.find(bundle: bundle, environment: [:])?.lastPathComponent == "cvedex")
    }

    @Test(arguments: [
        ("", CLIError(code: "CVEDEX_ERROR", message: "cvedex failed")),
        ("panic: oops\n", CLIError(code: "CVEDEX_ERROR", message: "panic: oops")),
        ("{}", CLIError(code: "CVEDEX_ERROR", message: "cvedex failed")),
        (
            #"{"error":"BAD_INPUT","message":"m","details":{"errors":[{"instancePath":"/a","message":"x"},{}]}}"#,
            CLIError(code: "BAD_INPUT", message: "m", problems: ["/a: x", ""])
        ),
        (
            #"{"error":"BAD_INPUT","message":"m","details":[{"param":"amount","msg":"x"}]}"#,
            CLIError(code: "BAD_INPUT", message: "m", problems: ["amount: x"])
        ),
        (
            #"{"error":"PENDING_APPROVAL","message":"m","details":{"proposal_id":"p1"}}"#,
            CLIError(code: "PENDING_APPROVAL", message: "m")
        ),
        (#"{"error":"E","message":"m","details":"text"}"#, CLIError(code: "E", message: "m")),
    ])
    func errors(stderr: String, expected: CLIError) async throws {
        let fake = try Fake([fail(stderr)])
        await #expect(throws: expected) { try await CLI(executable: fake.executable).run(["show"]) }
        #expect(expected.localizedDescription == expected.message)
    }

    @Test func largeOutput() async throws {
        let big = String(repeating: "x", count: 1 << 20)
        let fake = try Fake([(big, big, 0)])
        #expect(try await CLI(executable: fake.executable).run([], input: Data(big.utf8)).count == big.utf8.count)
        #expect(fake.stdin(1).count == big.count)
    }
}
