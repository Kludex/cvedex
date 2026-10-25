import Foundation
import Testing

@testable import CvedexKit

@Suite struct BuilderTests {
    @Test func blankContainer() throws {
        let blank = Container.blank
        #expect(blank.title == "" && blank.summary == "" && blank.summaryPath == "/descriptions/0/value")
        #expect(blank.products == [.blank] && blank.references == [.blank])
        #expect(blank.weaknesses.isEmpty && blank.credits.isEmpty && blank.cvss == nil && blank.otherScores.isEmpty)
        #expect(try Container(text: blank.text) == blank)
        #expect(blank.text.hasSuffix("}\n") && blank.text.contains(#""lessThan" : """#))
        #expect(blank.weaknessPaths.isEmpty && blank.products[0].versions == [.blank] && Reference.blank.tags.isEmpty)
        #expect(Container(fields: ["score": .number(.nan)]).text == "\n")
        #expect(Container(fields: ["references": .array([.null])]).references == [Reference(fields: [:])])
    }

    @Test func parse() throws {
        #expect(throws: CLIError(code: "CVEDEX_ERROR", message: "A CNA container is a JSON object")) {
            try Container(text: "[]")
        }
        #expect(throws: DecodingError.self) { try Container(text: "{") }
        let text = #"{"x_kept":{"a":[null,true,1.5,"s"]},"title":"t"}"#
        let container = try Container(text: text)
        #expect(container.title == "t")
        #expect(try Container(text: container.text) == container)
        #expect(container.text.contains(#""x_kept" : {"#) && container.text.contains("1.5"))
        let value = try #require(container.fields["x_kept"])
        #expect(value.object?["a"]?.array?.count == 4 && value.string == nil && value.number == nil)
        #expect(value.array == nil && JSONValue.null.object == nil)
    }

    @Test func summaryAndTitle() {
        var container = Container(fields: [:])
        container.summary = "First."
        #expect(
            container.fields["descriptions"] == .array([.object(["lang": .string("en"), "value": .string("First.")])]))
        container.fields["descriptions"] = .array([
            .object(["lang": .string("es"), "value": .string("Hola.")]),
            .object(["lang": .string("en-US"), "value": .string("Hello.")]),
        ])
        #expect(container.summary == "Hello." && container.summaryPath == "/descriptions/1/value")
        container.summary = "Bye."
        #expect(container.fields["descriptions"]?.array?[1].object?["value"] == .string("Bye."))
        container.fields["descriptions"] = .array([.object(["lang": .string("es"), "value": .string("Hola.")])])
        #expect(container.summary == "Hola." && container.summaryPath == "/descriptions/0/value")
        container.fields["descriptions"] = .array([.string("odd")])
        #expect(container.summary == "")
        container.summary = "Fixed."
        #expect(container.fields["descriptions"] == .array([.object(["value": .string("Fixed.")])]))
        container.title = "widget: flaw"
        #expect(container.fields["title"] == .string("widget: flaw"))
        container.title = ""
        #expect(container.fields["title"] == nil)
    }

    @Test func products() {
        var product = Product.blank
        product.vendor = "acme"
        product.product = "widget"
        product.repo = "https://github.com/acme/widget"
        product.collectionURL = "https://pypi.org"
        product.packageName = "widget"
        product.defaultStatus = "affected"
        #expect(
            [product.vendor, product.product, product.repo, product.collectionURL, product.packageName]
                == ["acme", "widget", "https://github.com/acme/widget", "https://pypi.org", "widget"])
        #expect(product.defaultStatus == "affected")
        product.repo = ""
        #expect(product.fields["repo"] == nil)
        product.versions = []
        #expect(product.fields["versions"] == nil)
        #expect(Product(fields: [:]).defaultStatus == "unknown")
        var container = Container.blank
        container.products = [product, .blank]
        #expect(container.products.count == 2 && container.products[0].vendor == "acme")
        #expect(Product.registries.first?.url == "https://pypi.org")
    }

    @Test func versions() {
        var version = Version.blank
        #expect(version.version == "0" && version.status == "affected" && version.versionType == "semver")
        #expect(version.range == .below && version.limit == "")
        version.limit = "1.2.3"
        version.range = .through
        #expect(version.fields["lessThan"] == nil && version.fields["lessThanOrEqual"] == .string("1.2.3"))
        version.range = .single
        #expect(version.limit == "" && version.fields["lessThanOrEqual"] == nil)
        version.limit = "ignored"
        #expect(version.fields.count == 3)
        version.versionType = ""
        version.version = "2.0"
        version.status = "unaffected"
        version.range = .below
        #expect(version.versionType == "semver" && version.fields["lessThan"] == .string(""))
        version.versionType = "python"
        version.range = .through
        #expect(version.versionType == "python" && version.status == "unaffected" && version.version == "2.0")
        #expect(Version.types.contains("python"))
    }

    @Test func weaknesses() {
        var container = Container.blank
        var weakness = Weakness.blank
        weakness.cweId = "CWE-22"
        #expect(weakness.description.hasPrefix("CWE-22: Improper Limitation of a Pathname"))
        weakness.cweId = "CWE-770"
        #expect(weakness.description == "CWE-770: Allocation of Resources Without Limits or Throttling")
        weakness.description = "CWE-770: my own words"
        weakness.cweId = "CWE-400"
        #expect(weakness.description == "CWE-770: my own words")
        weakness.cweId = "CWE-99999999"
        #expect(weakness.cweId == "CWE-99999999")
        container.weaknesses = [weakness, .blank]
        #expect(
            container.weaknesses.count == 2
                && container.weaknessPaths == ["/problemTypes/0/descriptions/0", "/problemTypes/0/descriptions/1"])
        container.fields["problemTypes"] = .array([
            .object(["descriptions": .array([.object(["cweId": .string("CWE-1")])])]),
            .object(["descriptions": .array([.null])]), .null,
        ])
        #expect(container.weaknesses.map(\.cweId) == ["CWE-1", ""])
        #expect(container.weaknessPaths == ["/problemTypes/0/descriptions/0", "/problemTypes/1/descriptions/0"])
        container.weaknesses = []
        #expect(container.fields["problemTypes"] == nil)
    }

    @Test func referencesAndCredits() {
        var container = Container.blank
        var reference = Reference.blank
        reference.url = "https://github.com/acme/widget/pull/1"
        reference.tags = ["patch"]
        #expect(reference.url.hasSuffix("/1") && reference.tags == ["patch"])
        reference.tags = []
        #expect(reference.fields["tags"] == nil)
        container.references = [reference]
        #expect(container.references == [reference])
        var credit = Credit.blank
        credit.name = "bob"
        credit.type = "reporter"
        #expect(credit.name == "bob" && credit.type == "reporter")
        container.credits = [credit]
        #expect(container.credits == [credit])
        container.credits = []
        #expect(container.fields["credits"] == nil)
        container.references = []
        #expect(container.fields["references"] == .array([]))
        #expect(Reference.tags.contains("patch") && Credit.types.contains("finder"))
    }

    @Test func metrics() throws {
        var container = try Container(
            text: """
                {"metrics": [
                  {"cvssV4_0": {"version": "4.0", "baseScore": 8.7, "vectorString": "CVSS:4.0/AV:N"}},
                  {"cvssV3_1": {"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
                  {"other": {"content": {}}, "ssvc": {}}
                ]}
                """)
        #expect(container.cvss?.score == 9.8)
        #expect(container.otherScores == ["CVSS 4.0 8.7 CVSS:4.0/AV:N", "other", "ssvc"])
        var cvss = try #require(container.cvss)
        cvss.values["A"] = "N"
        container.cvss = cvss
        let metrics = try #require(container.fields["metrics"]?.array)
        #expect(metrics.count == 3)
        #expect(
            metrics[0]
                == .object([
                    "cvssV3_1": .object([
                        "version": .string("3.1"),
                        "vectorString": .string("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
                        "baseScore": .number(9.1), "baseSeverity": .string("CRITICAL"),
                    ])
                ]))
        container.cvss = nil
        #expect(container.fields["metrics"]?.array?.count == 2)
        container.fields["metrics"] = .array([.object(["cvssV3_1": .object([:])])])
        container.cvss = nil
        #expect(container.fields["metrics"] == nil)
    }

    @Test(arguments: [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "CRITICAL"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "CRITICAL"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", 5.4, "MEDIUM"),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5, "MEDIUM"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5, "HIGH"),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", 5.4, "MEDIUM"),
        ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6, "LOW"),
        ("CVSS:3.1/AV:A/AC:H/PR:H/UI:N/S:C/C:L/I:L/A:L", 5.1, "MEDIUM"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "NONE"),
    ])
    func cvssScores(vector: String, score: Double, severity: String) throws {
        let cvss = try #require(CVSS31(vector: vector))
        #expect(cvss.vector == vector)
        #expect(cvss.score == score)
        #expect(cvss.severity == severity)
    }

    @Test func cvssVectors() {
        #expect(CVSS31().vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
        #expect(CVSS31(vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == nil)
        #expect(CVSS31(vector: "CVSS:3.1/AV:N/AC:L") == nil)
        #expect(CVSS31(vector: "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == nil)
        #expect(CVSS31(vector: "CVSS:3.1/AV:N/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E")?.values["AV"] == "N")
        #expect(CVSS31(vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P") == nil)
        var unknown = CVSS31()
        unknown.values = [:]
        #expect(unknown.score == 0 && unknown.vector.hasPrefix("CVSS:3.1/AV:/"))
    }

    @Test func cwe() {
        #expect(CWE.all.count > 900)
        #expect(CWE.common.count == 25 && CWE.common.first?.id == "CWE-79")
        #expect(CWE.search("") == CWE.common)
        #expect(CWE.search("22").first?.id == "CWE-22")
        #expect(CWE.search("cwe-22").first?.id == "CWE-22")
        #expect(CWE.search("path traversal").contains { $0.id == "CWE-22" })
        #expect(CWE.search("zzzz nothing").isEmpty)
        #expect(CWE.label("CWE-79")?.hasPrefix("CWE-79: Improper Neutralization of Input") == true)
        #expect(CWE.label("CWE-0") == nil)
    }

    @Test func problems() {
        let parsed = Problem.parse([
            "- /title: minLength: got 0, want 1",
            "- /references/0/url: 'nope' is not valid uri: relative url",
            "- /affected/0/versions/0: 'oneOf' failed, none matched",
            "  - maxProperties: got 3, want 2",
            "  - missing property 'versionType'",
            "  - /affected/0/versions/0/lessThan: minLength: got 0, want 1",
            "- /problemTypes/0/descriptions/0/cweId: 'CWE-' does not match pattern '^CWE-[1-9][0-9]*$'",
            "- missing properties 'affected'",
            "the record on stdin is not a JSON object",
        ])
        #expect(
            parsed == [
                Problem(path: "/title", message: "Required"),
                Problem(path: "/references/0/url", message: "Needs a full URL, starting with https://"),
                Problem(path: "/affected/0/versions/0", message: "missing property 'versionType'"),
                Problem(path: "/affected/0/versions/0/lessThan", message: "Required"),
                Problem(path: "/problemTypes/0/descriptions/0/cweId", message: "Needs a CWE ID, such as CWE-22"),
                Problem(path: "", message: "missing properties 'affected'"),
                Problem(path: "", message: "the record on stdin is not a JSON object"),
            ])
    }
}
