import CvedexKit
import SwiftUI

/// A record waiting for a review, above the record itself, with what a reviewer can do about it.
struct ReviewCallout: View {
    let review: Review
    /// Runs once the record is published or rejected.
    let approved: () -> Void
    @State private var approving = false
    @State private var requesting = false

    var body: some View {
        Callout(symbol: "checkmark.seal", color: .purple, title: "Waiting for review") {
            Text("Revision \(review.revision) from \(review.submitter), asking to \(review.action).")
                .foregroundStyle(.secondary)
            HStack {
                Button(review.action == "reject" ? "Reject…" : "Approve…") { approving = true }
                    .buttonStyle(.borderedProminent)
                Button("Request Changes…") { requesting = true }
            }
        }
        .sheet(isPresented: $approving) { ApproveView(review: review, approved: approved) }
        .sheet(isPresented: $requesting) { RequestChangesView(review: review) }
    }
}

/// Asks before a record in review goes out, showing what it changes in the published one.
private struct ApproveView: View {
    let review: Review
    let approved: () -> Void
    @Environment(Store.self) private var store
    @Environment(\.dismiss) private var dismiss
    @State private var busy = false
    @State private var failure: String?

    private var verb: String { review.action == "reject" ? "Reject" : "Publish" }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("\(verb) \(review.cveId)?").font(.headline)
            Text(
                review.changes.isEmpty
                    ? "Revision \(review.revision) from \(review.submitter) becomes public."
                    : "These changes to the published record, revision \(review.revision) from \(review.submitter), "
                        + "become public."
            )
            .foregroundStyle(.secondary)
            if !review.changes.isEmpty {
                DiffList(changes: review.changes)
            }
            if let failure {
                Label(failure, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red)
            }
            HStack {
                if busy {
                    ProgressView().controlSize(.small)
                    Text("A GitHub repository takes a moment: its workflow does the publishing.")
                        .foregroundStyle(.secondary)
                        .footnote()
                }
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button(verb) { Task { await approve() } }
                    .keyboardShortcut(.defaultAction)
                    .disabled(busy)
            }
        }
        .padding(20)
        .frame(width: 680, height: review.changes.isEmpty ? nil : 460)
    }

    private func approve() async {
        busy = true
        defer { busy = false }
        do {
            try await store.approve(review)
            approved()
            dismiss()
        } catch {
            failure = error.localizedDescription
        }
    }
}

private struct RequestChangesView: View {
    let review: Review
    @Environment(Store.self) private var store
    @Environment(\.dismiss) private var dismiss
    @State private var note = ""
    @State private var busy = false
    @State private var failure: String?

    var body: some View {
        Form {
            Section {
                TextField("Note", text: $note, prompt: Text("Add the CWE."), axis: .vertical)
                    .lineLimit(3...6)
            } header: {
                Text("Request changes to \(review.cveId)")
            } footer: {
                Text("\(review.submitter) sees your note until they send the record again.")
                    .foregroundStyle(.secondary)
                    .footnote()
            }
            if let failure {
                Label(failure, systemImage: "exclamationmark.triangle").foregroundStyle(.red)
            }
        }
        .formStyle(.grouped)
        .frame(width: 460)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
            ToolbarItem(placement: .confirmationAction) {
                Button("Send") {
                    Task {
                        busy = true
                        defer { busy = false }
                        do {
                            try await store.requestChanges(review, note: note)
                            dismiss()
                        } catch {
                            failure = error.localizedDescription
                        }
                    }
                }
                .disabled(note.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || busy)
            }
        }
    }
}

/// The lines a record changes in another, as a diff.
struct DiffList: View {
    let changes: [DiffLine]

    var body: some View {
        ScrollView([.vertical, .horizontal]) {
            VStack(alignment: .leading, spacing: 0) {
                ForEach(changes.indices, id: \.self) { row($0) }
            }
            .font(.callout.monospaced())
            .textSelection(.enabled)
            .padding(.vertical, 6)
        }
        .background(.background.secondary, in: .rect(cornerRadius: 6))
        .overlay(RoundedRectangle(cornerRadius: 6).strokeBorder(.separator))
    }

    private func row(_ index: Int) -> some View {
        let (mark, text, color): (String, String, Color?) =
            switch changes[index] {
            case .same(let line): (" ", line, nil)
            case .removed(let line): ("-", line, .red)
            case .added(let line): ("+", line, .green)
            case .skipped(let count): ("", count == 1 ? "1 unchanged line" : "\(count) unchanged lines", nil)
            }
        return HStack(spacing: 8) {
            Text(mark).foregroundStyle(color ?? .secondary).frame(width: 10)
            Text(text).foregroundStyle(mark.isEmpty ? .secondary : .primary).italic(mark.isEmpty)
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 1)
        .background(color?.opacity(0.15) ?? .clear)
    }
}
