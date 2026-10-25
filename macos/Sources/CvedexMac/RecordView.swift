import CvedexKit
import SwiftUI

struct RecordView: View {
    let id: CVEID
    @Environment(Store.self) private var store
    @State private var record: Record?
    @State private var loaded = false
    @State private var failure: String?
    @State private var editing = false
    @State private var rejecting = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                HStack(alignment: .firstTextBaseline) {
                    Text(id.cveId).font(.title.monospaced())
                    Text(record?.state ?? id.state).font(.caption.bold()).padding(.horizontal, 6)
                        .background(.quaternary, in: .capsule)
                }
                if let note = id.cvedexd?.note {
                    GroupBox("Changes requested") { Text(note).frame(maxWidth: .infinity, alignment: .leading) }
                }
                if let failure {
                    Label(failure, systemImage: "exclamationmark.triangle").foregroundStyle(.red)
                } else if let record {
                    RecordSummary(record: record)
                } else if loaded {
                    ContentUnavailableView(
                        "No record yet", systemImage: "doc",
                        description: Text("Write a record, or import a GitHub advisory, to publish this ID."))
                }
            }
            .padding()
            .frame(maxWidth: .infinity, alignment: .leading)
            .textSelection(.enabled)
        }
        .toolbar {
            ToolbarItemGroup {
                Button(record == nil ? "Write Record" : "Edit Record", systemImage: "pencil") { editing = true }
                    .disabled(!loaded || failure != nil || id.state == "REJECTED")
                Button("Reject", systemImage: "xmark.octagon") { rejecting = true }
                    .disabled(id.state == "REJECTED")
            }
        }
        .task { await load() }
        .sheet(isPresented: $editing) {
            EditorView(id: id.cveId, publish: record == nil)
        }
        .sheet(isPresented: $rejecting) { RejectView(id: id.cveId) }
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

private struct RecordSummary: View {
    let record: Record

    var body: some View {
        if let title = record.title {
            Text(title).font(.title2)
        }
        if let date = record.datePublished {
            Text("Published \(date.prefix(10))").foregroundStyle(.secondary)
        }
        section("Rejected", record.rejectedReasons)
        section("Description", record.descriptions)
        section("Affected", record.affected)
        section("Weaknesses", record.cwes)
        if !record.references.isEmpty {
            Text("References").font(.headline)
            ForEach(record.references, id: \.self) { url in
                if let link = URL(string: url) { Link(url, destination: link) } else { Text(url) }
            }
        }
    }

    @ViewBuilder
    private func section(_ name: String, _ lines: [String]) -> some View {
        if !lines.isEmpty {
            Text(name).font(.headline)
            ForEach(lines, id: \.self, content: Text.init)
        }
    }
}
