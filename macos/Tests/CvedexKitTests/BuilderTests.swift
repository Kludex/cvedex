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
        let html = JSONValue.array([.object(["type": .string("text/html"), "value": .string("<p>Fixed.</p>")])])
        container.fields["descriptions"] = .array([.object(["value": .string("Fixed."), "supportingMedia": html])])
        container.summary = "Fixed."
        #expect(container.fields["descriptions"]?.array?[0].object?["supportingMedia"] == html)
        container.summary = "Fixed in 1.2."
        #expect(container.fields["descriptions"] == .array([.object(["value": .string("Fixed in 1.2.")])]))
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

        var product = Product(fields: [:])
        #expect(product.versionType == "")
        product.addVersion()
        product.versionType = "python"
        product.addVersion()
        #expect(product.versions.map(\.versionType) == ["python", "python"])
        product.versions[0].versionType = ""
        #expect(product.versionType == "python")
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
        #expect(container.cvss4 == nil)
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

    @Test func cvss4InTheRecord() throws {
        var container = Container.blank
        container.cvss4 = CVSS40()
        container.cvss = CVSS31()
        var cvss4 = try #require(container.cvss4)
        cvss4.values["VC"] = "H"
        container.cvss4 = cvss4
        let metrics = try #require(container.fields["metrics"]?.array)
        #expect(metrics.count == 2)
        #expect(
            metrics[0]
                == .object([
                    "cvssV4_0": .object([
                        "version": .string("4.0"),
                        "vectorString": .string("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"),
                        "baseScore": .number(8.7), "baseSeverity": .string("HIGH"),
                    ])
                ]))
        #expect(container.otherScores.isEmpty)
        container.cvss4 = nil
        #expect(container.fields["metrics"]?.array?.count == 1)
    }

    /// Scored by FIRST's reference calculator, one vector for each combination of classes the score depends on.
    @Test(arguments: [
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", 0.0, "NONE"),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N", 7.1, "HIGH"),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N", 8.6, "HIGH"),
        ("CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:N/VI:N/VA:N/SC:N/SI:N/SA:H", 4.1, "MEDIUM"),
        ("CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:N/VI:N/VA:H/SC:N/SI:N/SA:H", 6.7, "MEDIUM"),
        ("CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:N/SC:N/SI:N/SA:H", 8.2, "HIGH"),
        ("CVSS:4.0/AV:P/AC:L/AT:N/PR:L/UI:A/VC:H/VI:L/VA:N/SC:H/SI:N/SA:H/E:P/MAC:L/MAT:N/V:D", 5.2, "MEDIUM"),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:L/E:P/CR:M/MAC:L/MAT:N/MSC:N/S:N", 2.0, "LOW"),
        (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:H/SA:H/E:P/MAC:L/MPR:H/MUI:N/MVC:H/MVI:L/MSI:S/MSA:S/R:A/RE:H",
            8.6, "HIGH"
        ),
        (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:N/VI:L/VA:N/SC:L/SI:H/SA:H/MAT:N/MPR:N/MUI:N/MVC:H/MVI:H/MSI:S/MSA:S/AU:N",
            10.0, "CRITICAL"
        ),
        (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:H/E:U/IR:H/MVA:H/MSI:S/V:D/U:Clear", 9.5,
            "CRITICAL"
        ),
        (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:H/SC:H/SI:L/SA:N/E:U/MAV:N/MVC:N/MSA:S/AU:N/U:Clear", 7.4,
            "HIGH"
        ),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:H/VA:H/SC:N/SI:N/SA:H/E:U/CR:H/MVC:H/R:A", 7.4, "HIGH"),
        (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:H/VA:L/SC:L/SI:L/SA:L/E:U/IR:H/AR:L/MAC:L/MAT:N/MPR:N/MVI:L",
            1.2, "LOW"
        ),
        (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:L/SC:H/SI:H/SA:H/MAC:L/MAT:N/MVC:L/MVA:L/MSA:S/S:N/U:Clear",
            9.1, "CRITICAL"
        ),
        (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:H/SC:H/SI:L/SA:N/CR:H/MAT:N/MVA:L/MSC:L/MSI:S/MSA:S/RE:M",
            9.8, "CRITICAL"
        ),
        (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:A/VC:L/VI:H/VA:L/SC:N/SI:L/SA:H/E:P/IR:L/AR:M/MPR:N/MSC:L/MSI:S/MSA:S/V:D/U:Clear",
            7.5, "HIGH"
        ),
        (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:N/SC:L/SI:H/SA:N/E:U/CR:L/IR:M/MPR:H/MUI:N/MVC:H/MSI:S/MSA:S/S:N/AU:N/V:D",
            7.8, "HIGH"
        ),
        (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:L/SC:N/SI:N/SA:H/E:U/CR:L/AR:L/MAC:L/MUI:P/MVC:N/S:N/RE:H/U:Clear",
            5.6, "MEDIUM"
        ),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:A/VC:H/VI:L/VA:L/SC:L/SI:H/SA:H/E:U/CR:M/AR:H/R:U", 4.3, "MEDIUM"),
        (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:P/VC:H/VI:N/VA:N/SC:N/SI:H/SA:L/E:P/IR:L/MAV:N/MAC:L/MUI:P/MVI:N/MVA:L/AU:N/V:D",
            6.8, "MEDIUM"
        ),
        (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N/E:P/AR:L/MAV:N/MVC:L/MVI:L/MSC:N/MSA:S/S:N/AU:N/R:I",
            6.6, "MEDIUM"
        ),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:H/SC:H/SI:L/SA:N/E:P/MAT:N/MSA:S/S:N", 9.5, "CRITICAL"),
        (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:L/SA:H/E:P/IR:H/AR:M/MUI:A/MVC:L/MSC:H/S:N/U:Clear",
            5.4, "MEDIUM"
        ),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:A/VC:H/VI:H/VA:N/SC:H/SI:L/SA:L/E:U/MAV:N/MSC:N", 5.8, "MEDIUM"),
        (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:H/VA:N/SC:L/SI:H/SA:H/E:P/IR:L/MAT:N/R:I/V:D/U:Clear", 5.7,
            "MEDIUM"
        ),
        (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N/E:P/MAT:N/MUI:A/MSC:H/MSI:S/AU:N/RE:M",
            9.2, "CRITICAL"
        ),
        (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:L/SC:N/SI:N/SA:H/E:U/MAV:N/MAC:L/MUI:P/MVC:L/MVA:L/MSC:L/MSI:S/S:N/R:U/RE:M",
            4.8, "MEDIUM"
        ),
        (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P/IR:L/MAV:N/MVA:N/R:U/RE:H/U:Clear",
            8.3, "HIGH"
        ),
        (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:P/VC:H/VI:N/VA:N/SC:N/SI:L/SA:L/E:U/CR:L/AR:M/MAC:L/MSA:S/AU:N/V:D", 6.1,
            "MEDIUM"
        ),
        (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:H/SI:N/SA:H/E:U/CR:H/IR:L/AR:M/MPR:H/MUI:N/MSC:L/U:Clear",
            2.2, "LOW"
        ),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:L/E:U/MVI:L/R:I/RE:M", 5.1, "MEDIUM"),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:H/SC:N/SI:H/SA:N/E:U/MVC:H/MVI:N/MSA:S", 8.9, "HIGH"),
        (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:N/SC:H/SI:L/SA:H/E:U/IR:H/AR:H/MAT:N/MUI:N/MVA:H/MSA:S",
            9.0, "CRITICAL"
        ),
        (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:N/VA:H/SC:N/SI:N/SA:H/E:U/IR:H/MAV:N/MAT:N/MUI:N/MVI:L/MVA:L/MSC:L/S:N/R:A/V:D/RE:L",
            4.5, "MEDIUM"
        ),
        (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:L/SC:L/SI:L/SA:N/E:P/IR:M/MAC:L/MAT:N/MVC:H/MVI:L/AU:N",
            5.5, "MEDIUM"
        ),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:L/CR:L/IR:H/AR:L/MVC:H/MVA:H", 5.7, "MEDIUM"),
        (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:P/VC:H/VI:N/VA:N/SC:H/SI:N/SA:H/E:P/CR:M/IR:M/MPR:H/MVC:H/MVI:H/MVA:L/S:N",
            7.2, "HIGH"
        ),
        (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:L/E:P/IR:H/MAV:N/MAC:L/MVA:H/AU:N/V:D", 7.3,
            "HIGH"
        ),
        (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:P/VC:N/VI:H/VA:L/SC:H/SI:N/SA:L/E:U/CR:M/IR:L/AR:L/MAT:N/MUI:P/MVA:L/MSC:N/V:D/RE:L/U:Clear",
            2.0, "LOW"
        ),
        ("CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:L/SC:N/SI:N/SA:L/E:U/CR:L/IR:L/AR:L", 0.1, "LOW"),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", 0.0, "NONE"),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MSI:S", 10.0, "CRITICAL"),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.3, "CRITICAL"),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N/MVC:H", 8.7, "HIGH"),
    ])
    func cvss4Scores(vector: String, score: Double, severity: String) throws {
        let cvss = try #require(CVSS40(vector: vector))
        #expect(cvss.vector == vector)
        #expect(cvss.score == score)
        #expect(cvss.severity == severity)
    }

    @Test func cvss4Vectors() {
        let base = "AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        #expect(CVSS40().vector == "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N")
        #expect(CVSS40(vector: "CVSS:4.0/\(base)/E:X")?.vector == "CVSS:4.0/\(base)")
        for invalid in [
            "CVSS:3.1/\(base)", "CVSS:4.0", "CVSS:4.0/AV:N", "CVSS:4.0/\(base)/", "CVSS:4.0/\(base)/E:Z",
            "CVSS:4.0/AC:L/AV:N/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "CVSS:4.0/\(base)/U:Red/E:A",
            "CVSS:4.0/\(base)/E:A/E:P", "CVSS:4.0/\(base)/XX:1", "CVSS:4.0/AV:N/\(base)",
        ] {
            #expect(CVSS40(vector: invalid) == nil, "\(invalid)")
        }
    }

    @Test(
        arguments: [
            ("a\nb", "a\nb", []),
            ("a\nb\nc", "a\nB\nc", [.same("a"), .removed("b"), .added("B"), .same("c")]),
            (
                "1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n11", "0\n1\n2\n3\n4\n5\n6\n7\n8\n9\n10",
                [.added("0"), .same("1"), .same("2"), .skipped(6), .same("9"), .same("10"), .removed("11")]
            ),
            (
                "1\n2\n3\n4\n5\n6", "1\n2\n3\n4\n5\n6\n7",
                [.skipped(4), .same("5"), .same("6"), .added("7")]
            ),
        ] as [(String, String, [DiffLine])])
    func diff(old: String, new: String, lines: [DiffLine]) {
        #expect(DiffLine.lines(from: old, to: new) == lines)
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
