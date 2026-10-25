import AppKit
import CvedexKit
import SwiftUI

/// Edits a CNA container as JSON, checked against the CVE schema as you type.
struct EditorView: View {
    let id: String
    let publish: Bool
    @Environment(Store.self) private var store
    @Environment(\.dismiss) private var dismiss
    @State private var text = ""
    @State private var problems: [String]?
    @State private var advisory = ""
    @State private var busy = false
    @State private var confirming = false
    @State private var failure: String?

    private var verb: String { publish ? "Publish" : "Update" }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                TextField("GitHub advisory URL", text: $advisory, prompt: Text(advisoryHint))
                    .onSubmit(importAdvisory)
                Button("Import", action: importAdvisory).disabled(advisory.isEmpty || busy)
            }
            .padding()
            JSONEditor(text: $text)
            Divider()
            VStack(alignment: .leading, spacing: 4) {
                switch problems {
                case nil:
                    Label("Checking…", systemImage: "hourglass").foregroundStyle(.secondary)
                case let problems? where problems.isEmpty:
                    Label("Valid CNA container", systemImage: "checkmark.circle").foregroundStyle(.green)
                case let problems?:
                    Label("Not a valid CNA container", systemImage: "xmark.circle").foregroundStyle(.red)
                    ScrollView {
                        Text(problems.joined(separator: "\n")).font(.callout.monospaced())
                            .frame(maxWidth: .infinity, alignment: .leading).textSelection(.enabled)
                    }
                    .frame(maxHeight: 120)
                }
                if let failure {
                    Label(failure, systemImage: "exclamationmark.triangle").foregroundStyle(.red)
                }
            }
            .padding()
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction)
                Button("\(verb)…") { confirming = true }
                    .keyboardShortcut(.defaultAction)
                    .disabled(problems != [] || busy)
            }
            .padding([.horizontal, .bottom])
        }
        .frame(minWidth: 720, minHeight: 560)
        .task {
            do {
                text = try await store.draft(id)
            } catch {
                failure = error.localizedDescription
            }
        }
        .task(id: text) {
            problems = nil
            try? await Task.sleep(for: .milliseconds(300))
            guard !Task.isCancelled else { return }
            problems = await store.check(text)
        }
        .confirmationDialog("\(verb) \(id)? It will be public.", isPresented: $confirming) {
            Button(verb) { Task { await send() } }
        }
    }

    private let advisoryHint = "https://github.com/OWNER/REPO/security/advisories/GHSA-..."

    private func importAdvisory() {
        busy = true
        Task {
            defer { busy = false }
            do {
                text = try await store.fromAdvisory(advisory.trimmingCharacters(in: .whitespaces))
                failure = nil
            } catch {
                failure = error.localizedDescription
            }
        }
    }

    private func send() async {
        busy = true
        defer { busy = false }
        do {
            _ = try await store.send(id, container: text, publish: publish)
            dismiss()
        } catch let error as CLIError {
            failure = error.message
            if !error.problems.isEmpty { problems = error.problems }
        } catch {
            failure = error.localizedDescription
        }
    }
}

/// A plain-text editor for JSON: no smart quotes, dashes or spelling fixes, which would break it.
private struct JSONEditor: NSViewRepresentable {
    @Binding var text: String

    func makeNSView(context: Context) -> NSScrollView {
        let scroll = NSTextView.scrollableTextView()
        guard let view = scroll.documentView as? NSTextView else { return scroll }
        view.font = .monospacedSystemFont(ofSize: NSFont.systemFontSize, weight: .regular)
        view.isRichText = false
        view.allowsUndo = true
        view.isAutomaticQuoteSubstitutionEnabled = false
        view.isAutomaticDashSubstitutionEnabled = false
        view.isAutomaticTextReplacementEnabled = false
        view.isAutomaticSpellingCorrectionEnabled = false
        view.isContinuousSpellCheckingEnabled = false
        view.textContainerInset = NSSize(width: 8, height: 8)
        view.delegate = context.coordinator
        return scroll
    }

    func updateNSView(_ scroll: NSScrollView, context: Context) {
        if let view = scroll.documentView as? NSTextView, view.string != text {
            view.string = text
        }
    }

    func makeCoordinator() -> Coordinator { Coordinator(text: $text) }

    final class Coordinator: NSObject, NSTextViewDelegate {
        let text: Binding<String>

        init(text: Binding<String>) {
            self.text = text
        }

        func textDidChange(_ notification: Notification) {
            if let view = notification.object as? NSTextView {
                text.wrappedValue = view.string
            }
        }
    }
}
