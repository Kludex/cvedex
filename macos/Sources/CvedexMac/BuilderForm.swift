import CvedexKit
import SwiftUI

/// The record as a form: what is affected, how badly, and where to read more.
struct BuilderForm: View {
    @Binding var container: Container
    let problems: [Problem]
    @State private var pickingWeakness = false

    var body: some View {
        Form {
            Section("Summary") {
                TextField("Title", text: $container.title, prompt: Text("widget: Path traversal in the file server"))
                    .issue(problems, "/title")
            }
            Section {
                TextEditor(text: $container.summary)
                    .font(.body)
                    .frame(minHeight: 110)
                    .scrollContentBackground(.hidden)
                    .issue(problems, container.summaryPath)
            } header: {
                Header("Description", hint: "What an attacker can do, how, and which version fixes it. Markdown works.")
            }

            ForEach(container.products.indices, id: \.self) { i in
                ProductSection(
                    product: $container.products.element(i, blank: .blank), path: "/affected/\(i)",
                    problems: problems,
                    remove: container.products.count > 1 ? { container.products.remove(at: i) } : nil)
            }
            Section {
                Button("Add Product", systemImage: "plus") { container.products.append(.blank) }
                    .buttonStyle(.borderless)
            }

            Section {
                ForEach(container.weaknesses.indices, id: \.self) { k in
                    let weakness = container.weaknesses[k]
                    HStack(alignment: .firstTextBaseline) {
                        Text(weakness.cweId.isEmpty ? "No CWE ID" : weakness.cweId)
                            .fontWeight(.medium).monospacedDigit()
                            .frame(width: 84, alignment: .leading)
                        Text(name(weakness)).foregroundStyle(.secondary).lineLimit(2)
                        Spacer()
                        RemoveButton { container.weaknesses.remove(at: k) }
                    }
                    .issue(problems, k < container.weaknessPaths.count ? container.weaknessPaths[k] + "/cweId" : "")
                }
                Button("Add Weakness…", systemImage: "plus") { pickingWeakness = true }
                    .buttonStyle(.borderless)
                    .popover(isPresented: $pickingWeakness, arrowEdge: .trailing) {
                        CWEPicker { entry in
                            var weakness = Weakness.blank
                            weakness.cweId = entry.id
                            container.weaknesses.append(weakness)
                            pickingWeakness = false
                        }
                    }
            } header: {
                Header("Weaknesses", hint: "The CWE that names the flaw. Search MITRE's list by number or by name.")
            }

            Section {
                ScoreRows(title: "CVSS 4.0 score", score: $container.cvss4)
            } header: {
                Header("Severity", hint: "CVSS 4.0 is the current version. Add 3.1 too if your users still rely on it.")
            }
            Section {
                ScoreRows(title: "CVSS 3.1 score", score: $container.cvss)
                ForEach(container.otherScores, id: \.self) { score in
                    LabeledContent("Also in the record") {
                        Text(score).font(.callout.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
                    }
                }
            }

            Section {
                ForEach(container.references.indices, id: \.self) { k in
                    ReferenceRow(reference: $container.references.element(k, blank: .blank)) {
                        container.references.remove(at: k)
                    }
                    .issue(problems, "/references/\(k)/url")
                }
                Button("Add Reference", systemImage: "plus") { container.references.append(.blank) }
                    .buttonStyle(.borderless)
                    .issue(problems, "/references")
            } header: {
                Header("References", hint: "Link the advisory, the fix, and the release that ships it.")
            }

            Section("Credits") {
                ForEach(container.credits.indices, id: \.self) { k in
                    CreditRow(credit: $container.credits.element(k, blank: .blank)) {
                        container.credits.remove(at: k)
                    }
                    .issue(problems, "/credits/\(k)/value")
                }
                Button("Add Credit", systemImage: "plus") { container.credits.append(.blank) }
                    .buttonStyle(.borderless)
            }
        }
        .formStyle(.grouped)
    }

    private func name(_ weakness: Weakness) -> String {
        let prefix = weakness.cweId + ": "
        return weakness.description.hasPrefix(prefix)
            ? String(weakness.description.dropFirst(prefix.count)) : weakness.description
    }
}

private struct ProductSection: View {
    @Binding var product: Product
    let path: String
    let problems: [Problem]
    let remove: (() -> Void)?

    var body: some View {
        Section {
            TextField("Vendor", text: $product.vendor, prompt: Text("acme"))
                .issue(problems, path + "/vendor")
            TextField("Product", text: $product.product, prompt: Text("widget"))
                .issue(problems, path + "/product")
            TextField("Repository", text: $product.repo, prompt: Text("https://github.com/acme/widget"))
                .issue(problems, path + "/repo")
            Picker("Package registry", selection: $product.collectionURL) {
                Text("None").tag("")
                ForEach(Product.registries, id: \.url) { Text($0.name).tag($0.url) }
                if !product.collectionURL.isEmpty,
                    !Product.registries.contains(where: { $0.url == product.collectionURL })
                {
                    Text(product.collectionURL).tag(product.collectionURL)
                }
            }
            if !product.collectionURL.isEmpty {
                TextField("Package name", text: $product.packageName, prompt: Text("widget"))
            }
            Picker("Versions not listed are", selection: $product.defaultStatus) {
                Text("Unaffected").tag("unaffected")
                Text("Affected").tag("affected")
                Text("Unknown").tag("unknown")
            }
            if !product.versions.isEmpty {
                Picker("Version scheme", selection: $product.versionType) {
                    if product.versions.allSatisfy({ $0.range == .single }) { Text("None").tag("") }
                    ForEach(Version.types, id: \.self) { Text($0).tag($0) }
                    if !product.versionType.isEmpty, !Version.types.contains(product.versionType) {
                        Text(product.versionType).tag(product.versionType)
                    }
                }
                .help("How versions compare: semver for 1.2.3, python for PEP 440, git for commits")
            }
            ForEach(product.versions.indices, id: \.self) { j in
                VersionRow(version: $product.versions.element(j, blank: .blank)) { product.versions.remove(at: j) }
                    .issue(
                        problems, "\(path)/versions/\(j)", "\(path)/versions/\(j)/\(product.versions[j].range.rawValue)"
                    )
            }
            Button("Add Versions", systemImage: "plus") { product.addVersion() }
                .buttonStyle(.borderless)
                .issue(problems, path)
        } header: {
            HStack {
                Text(title)
                Spacer()
                if let remove {
                    Button("Remove Product", role: .destructive, action: remove)
                        .buttonStyle(.borderless)
                        .font(.callout)
                }
            }
        }
    }

    private var title: String {
        let name = [product.vendor, product.product].filter { !$0.isEmpty }.joined(separator: " ")
        return name.isEmpty ? "Affected product" : name
    }
}

/// A CVSS score: a toggle to add it, a segmented picker per metric, and the vector and score they make.
private struct ScoreRows<Score: CVSSScore>: View {
    let title: String
    @Binding var score: Score?

    private static var groups: [String: String] {
        ["VC": "Impact on the vulnerable system", "SC": "Impact on subsequent systems"]
    }

    /// The 4.0 impact metrics share names, so VoiceOver gets which system each is about.
    private static func label(_ metric: CVSSMetric) -> String {
        switch metric.key {
        case "VC", "VI", "VA": "Vulnerable system \(metric.name.lowercased())"
        case "SC", "SI", "SA": "Subsequent system \(metric.name.lowercased())"
        default: metric.name
        }
    }

    var body: some View {
        Toggle(title, isOn: Binding(get: { score != nil }, set: { score = $0 ? Score() : nil }))
        if let score {
            ForEach(Score.metrics, id: \.key) { metric in
                if let group = Self.groups[metric.key] {
                    Text(group).font(.callout).foregroundStyle(.secondary).padding(.top, 4)
                }
                Picker(
                    metric.name,
                    selection: Binding(
                        get: { self.score?.values[metric.key] ?? "" }, set: { self.score?.values[metric.key] = $0 })
                ) {
                    ForEach(metric.options, id: \.value) { Text($0.name).tag($0.value) }
                }
                .pickerStyle(.segmented)
                .accessibilityLabel(Self.label(metric))
            }
            LabeledContent("Score") {
                HStack(spacing: 8) {
                    Text(score.vector).font(.callout.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
                        .lineLimit(2)
                    Badge(
                        text: "\(Style.score(score.score)) \(score.severity.capitalized)",
                        color: Style.severity(score.severity))
                }
            }
        }
    }
}

/// One version or range: "Affected from 0 before 1.2.3".
private struct VersionRow: View {
    @Binding var version: Version
    let remove: () -> Void

    var body: some View {
        HStack(spacing: 8) {
            Picker("Status", selection: $version.status) {
                Text("Affected").tag("affected")
                Text("Unaffected").tag("unaffected")
                Text("Unknown").tag("unknown")
            }
            .labelsHidden()
            .fixedSize()
            Text(version.range == .single ? "version" : "from").foregroundStyle(.secondary)
            TextField("Version", text: $version.version, prompt: Text("0"))
                .labelsHidden()
                .textFieldStyle(.roundedBorder)
                .frame(minWidth: 70, maxWidth: 140)
            Picker("Range", selection: $version.range) {
                Text("only").tag(Version.Range.single)
                Text("before").tag(Version.Range.below)
                Text("through").tag(Version.Range.through)
            }
            .labelsHidden()
            .fixedSize()
            if version.range != .single {
                TextField("Up to", text: $version.limit, prompt: Text("1.2.3"))
                    .labelsHidden()
                    .textFieldStyle(.roundedBorder)
                    .frame(minWidth: 70, maxWidth: 140)
            }
            Spacer(minLength: 0)
            RemoveButton(action: remove)
        }
    }
}

private struct ReferenceRow: View {
    @Binding var reference: Reference
    let remove: () -> Void

    var body: some View {
        HStack(spacing: 8) {
            TextField("URL", text: $reference.url, prompt: Text("https://github.com/acme/widget/releases/tag/1.2.3"))
                .labelsHidden()
                .textFieldStyle(.roundedBorder)
            Menu(reference.tags.isEmpty ? "Tags" : reference.tags.joined(separator: ", ")) {
                ForEach(Reference.tags, id: \.self) { tag in
                    Toggle(
                        tag,
                        isOn: Binding(
                            get: { reference.tags.contains(tag) },
                            set: { on in
                                reference.tags = on ? reference.tags + [tag] : reference.tags.filter { $0 != tag }
                            }
                        ))
                }
            }
            .frame(width: 190)
            RemoveButton(action: remove)
        }
    }
}

private struct CreditRow: View {
    @Binding var credit: Credit
    let remove: () -> Void

    var body: some View {
        HStack(spacing: 8) {
            TextField("Name", text: $credit.name, prompt: Text("Bob, or a GitHub handle"))
                .labelsHidden()
                .textFieldStyle(.roundedBorder)
            Picker("Role", selection: $credit.type) {
                ForEach(Credit.types, id: \.self) { Text($0.capitalized).tag($0) }
                if !Credit.types.contains(credit.type) { Text(credit.type).tag(credit.type) }
            }
            .labelsHidden()
            .fixedSize()
            .frame(width: 190, alignment: .trailing)
            RemoveButton(action: remove)
        }
    }
}

/// A section title with a line on what goes in it. Footers would be the native place for the hint, but grouped
/// forms misplace them next to dynamic rows.
private struct Header: View {
    let title: String
    let hint: String

    init(_ title: String, hint: String) {
        self.title = title
        self.hint = hint
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title)
            Text(hint).font(.callout).fontWeight(.regular).foregroundStyle(.secondary)
        }
    }
}

private struct RemoveButton: View {
    let action: () -> Void

    var body: some View {
        Button("Remove", systemImage: "minus.circle", role: .destructive, action: action)
            .labelStyle(.iconOnly)
            .buttonStyle(.borderless)
            .foregroundStyle(.secondary)
            .help("Remove")
    }
}

/// Search MITRE's CWE list by ID or by words in the name.
struct CWEPicker: View {
    let pick: (CWE.Entry) -> Void
    @State private var query = ""

    var body: some View {
        let results = CWE.search(query)
        VStack(spacing: 0) {
            TextField("Search", text: $query, prompt: Text("22, or path traversal"))
                .textFieldStyle(.roundedBorder)
                .padding(10)
            Divider()
            List {
                Section(query.isEmpty ? "CWE Top 25" : "\(results.count) weaknesses") {
                    ForEach(results.prefix(200), id: \.id) { entry in
                        Button {
                            pick(entry)
                        } label: {
                            HStack(alignment: .firstTextBaseline) {
                                Text(entry.id).monospacedDigit().frame(width: 76, alignment: .leading)
                                Text(entry.name).foregroundStyle(.primary)
                                Spacer(minLength: 0)
                            }
                            .contentShape(.rect)
                        }
                        .buttonStyle(.plain)
                    }
                }
            }
            .listStyle(.inset)
        }
        .frame(width: 520, height: 440)
    }
}
