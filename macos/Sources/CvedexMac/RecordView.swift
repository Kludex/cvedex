import AppKit
import CvedexKit
import SwiftUI

/// A CVE ID's record, read as a document, or its editor.
struct RecordView: View {
    let id: CVEID
    @Environment(Store.self) private var store
    @State private var record: Record?
    @State private var loaded = false
    @State private var failure: String?
    @State private var editing: Bool
    @State private var rejecting = false
    @State private var importing = false

    init(id: CVEID, editing: Bool = false) {
        self.id = id
        _editing = State(initialValue: editing)
    }

    var body: some View {
        Group {
            if editing {
                EditorView(id: id.cveId, publish: record == nil) {
                    editing = false
                    Task { await load() }
                }
            } else {
                document
            }
        }
        .navigationTitle(id.cveId)
        .navigationSubtitle(shown?.title ?? "")
        .task { await load() }
        .sheet(isPresented: $rejecting) { RejectView(id: id.cveId) }
        .sheet(isPresented: $importing) {
            AdvisoryForm(
                title: "Import a GitHub Advisory",
                message: "Fills in the record of \(id.cveId) from a repository security advisory. "
                    + "You can edit everything before you publish.",
                action: "Import",
                cancel: { importing = false }
            ) { url in
                store.saveDraft(id.cveId, container: try await store.fromAdvisory(url))
                importing = false
                editing = true
            }
        }
    }

    /// The review this ID waits for, if it does and you may review.
    private var review: Review? { store.reviews.first { $0.cveId == id.cveId } }

    /// The record to read: the one in review, exactly as approving sends it, else the one `cvedex show` gave.
    private var shown: Record? { review?.record ?? record }

    private var document: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                header
                if let review {
                    ReviewCallout(review: review) { Task { await load() } }
                }
                if let note = id.cvedexd?.note {
                    Callout(symbol: "exclamationmark.bubble", color: .orange, title: "Changes requested") {
                        Text(note).textSelection(.enabled)
                    }
                }
                if store.drafts.contains(id.cveId) {
                    Callout(symbol: "pencil.line", color: .blue, title: "You have an unsent draft") {
                        HStack {
                            Button("Continue Editing") { editing = true }
                            Button("Discard Draft", role: .destructive) { store.discardDraft(id.cveId) }
                        }
                    }
                }
                if let failure {
                    Label(failure, systemImage: "exclamationmark.triangle").foregroundStyle(.red)
                } else if let shown {
                    RecordBody(record: shown)
                }
            }
            .padding(32)
            .frame(maxWidth: 820, alignment: .leading)
            .frame(maxWidth: .infinity)
        }
        // Centered in the whole pane, not the document column, which is off-center in a wide window.
        .overlay {
            if failure == nil && shown == nil {
                if !loaded {
                    ProgressView()
                } else if !store.drafts.contains(id.cveId) && id.state == "RESERVED" {
                    ContentUnavailableView {
                        Label("No Record Yet", systemImage: "doc.badge.plus")
                    } description: {
                        Text(
                            "Write the record to publish \(id.cveId). Start from scratch, or from a GitHub security advisory."
                        )
                    } actions: {
                        Button("Write Record") { editing = true }.buttonStyle(.borderedProminent)
                        Button("Import Advisory…") { importing = true }
                    }
                }
            }
        }
        .toolbar {
            ToolbarItemGroup(placement: .primaryAction) {
                Button(record == nil ? "Write Record" : "Edit Record", systemImage: "square.and.pencil") {
                    editing = true
                }
                .disabled(!loaded || failure != nil || id.state == "REJECTED")
                Menu("More", systemImage: "ellipsis.circle") {
                    Button("Copy ID") {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(id.cveId, forType: .string)
                    }
                    if store.status?.isProduction == true, id.state == "PUBLISHED",
                        let url = URL(string: "https://www.cve.org/CVERecord?id=\(id.cveId)")
                    {
                        Link("Open on cve.org", destination: url)
                    }
                    Divider()
                    Button("Reject…", role: .destructive) { rejecting = true }
                        .disabled(id.state == "REJECTED")
                }
            }
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline, spacing: 10) {
                Text(id.cveId).font(.largeTitle.weight(.semibold)).monospacedDigit().textSelection(.enabled)
                Badge(
                    text: review == nil ? (record?.state ?? id.state).capitalized : "In Review",
                    color: Style.color(record?.state ?? id.state))
                if let score = shown?.scores.first {
                    Badge(
                        text: "\(Style.score(score.score)) \(score.severity.capitalized)",
                        color: Style.severity(score.severity))
                }
            }
            if let title = shown?.title {
                Text(title).font(.title2).textSelection(.enabled)
            }
            Text(dates).foregroundStyle(.secondary)
        }
    }

    private var dates: String {
        let reserved = id.reserved.map { "Reserved \(Style.day($0))" }
        let published = record?.datePublished.map { "Published \(Style.day($0))" }
        return [reserved, published].compactMap(\.self).joined(separator: "  ·  ")
    }

    private func load() async {
        do {
            record = try await store.record(id.cveId)
            failure = nil
        } catch {
            failure = error.localizedDescription
        }
        loaded = true
    }
}

private struct RecordBody: View {
    let record: Record

    var body: some View {
        if !record.rejectedReasons.isEmpty {
            Part("Rejected") { ForEach(record.rejectedReasons, id: \.self) { Prose(text: $0) } }
        }
        if !record.descriptions.isEmpty {
            Part("Description") { ForEach(record.descriptions, id: \.self) { Prose(text: $0) } }
        }
        if !record.affected.isEmpty {
            Part("Affected") {
                ForEach(record.affected.indices, id: \.self) { i in
                    let product = record.affected[i]
                    VStack(alignment: .leading, spacing: 6) {
                        Text(product.name).fontWeight(.medium)
                        Grid(alignment: .leading, horizontalSpacing: 10, verticalSpacing: 4) {
                            ForEach(product.versions.indices, id: \.self) { j in
                                let version = product.versions[j]
                                GridRow {
                                    Circle().fill(version.status == "affected" ? Color.red : .green)
                                        .frame(width: 7, height: 7)
                                    Text(version.range).monospacedDigit()
                                    Text(version.status).foregroundStyle(.secondary)
                                }
                            }
                        }
                    }
                }
            }
        }
        if !record.scores.isEmpty {
            Part("Severity") {
                ForEach(record.scores, id: \.vector) { score in
                    HStack(spacing: 10) {
                        Badge(text: Style.score(score.score), color: Style.severity(score.severity))
                        Text("CVSS \(score.version)")
                        Text(score.vector).font(.callout.monospaced()).foregroundStyle(.secondary)
                            .textSelection(.enabled)
                    }
                }
            }
        }
        if !record.cwes.isEmpty {
            Part("Weaknesses") { ForEach(record.cwes, id: \.self) { Text($0).textSelection(.enabled) } }
        }
        if !record.references.isEmpty {
            Part("References") {
                ForEach(record.references, id: \.url) { reference in
                    VStack(alignment: .leading, spacing: 2) {
                        if let url = URL(string: reference.url) {
                            Link(reference.url, destination: url).lineLimit(1).truncationMode(.middle)
                        } else {
                            Text(reference.url)
                        }
                        if !reference.tags.isEmpty {
                            Text(reference.tags.joined(separator: " · ")).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
            }
        }
        if !record.credits.isEmpty {
            Part("Credits") { ForEach(record.credits, id: \.self) { Text($0) } }
        }
    }
}

/// A titled part of the record.
private struct Part<Content: View>: View {
    let title: String
    @ViewBuilder let content: Content

    init(_ title: String, @ViewBuilder content: () -> Content) {
        self.title = title
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(title).font(.headline)
            content
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// A description, as typed: it is plain text, so `__init__` is not Markdown for a bold "init".
private struct Prose: View {
    let text: String

    var body: some View {
        Text(verbatim: text)
            .lineSpacing(3)
            .frame(maxWidth: 680, alignment: .leading)
            .textSelection(.enabled)
    }
}

/// A tinted note above the record.
struct Callout<Content: View>: View {
    let symbol: String
    let color: Color
    let title: String
    @ViewBuilder let content: Content

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Image(systemName: symbol).foregroundStyle(color)
            VStack(alignment: .leading, spacing: 8) {
                Text(title).fontWeight(.semibold)
                content
            }
            Spacer(minLength: 0)
        }
        .padding(14)
        .background(color.opacity(0.08), in: .rect(cornerRadius: 10))
    }
}
