import AppKit
import CvedexKit
import SwiftUI

/// Builds a record with a form, or edits it as JSON. Both edit the same container, checked as you go.
struct EditorView: View {
    let id: String
    let publish: Bool
    let close: () -> Void
    @Environment(Store.self) private var store
    @State private var mode = Mode.form
    @State private var text = ""
    @State private var loadedText: String?
    @State private var container = Container.blank
    @State private var parseError: String?
    @State private var problems: [Problem]?
    @State private var showingProblems = false
    @State private var revealed = false
    @State private var importing = false
    @State private var busy = false
    @State private var confirming = false
    @State private var changes: [DiffLine]?
    @State private var failure: String?

    enum Mode: String, CaseIterable {
        case form = "Form"
        case json = "JSON"
    }

    private var verb: String { publish ? "Publish" : "Update" }

    var body: some View {
        VStack(spacing: 0) {
            if loadedText == nil {
                ProgressView().frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if mode == .json {
                JSONEditor(text: $text)
            } else if let parseError {
                ContentUnavailableView {
                    Label("The JSON Has an Error", systemImage: "curlybraces")
                } description: {
                    Text(parseError)
                } actions: {
                    Button("Show JSON") { mode = .json }
                }
            } else {
                BuilderForm(
                    container: $container,
                    problems: (problems ?? []).filter { revealed || $0.message != Problem.required })
            }
            Divider()
            statusBar
        }
        .toolbar {
            ToolbarItem(placement: .principal) {
                Picker("Editor", selection: $mode) {
                    ForEach(Mode.allCases, id: \.self) { Text($0.rawValue) }
                }
                .pickerStyle(.segmented)
                .fixedSize()
            }
            ToolbarItemGroup(placement: .primaryAction) {
                Button("Import Advisory", systemImage: "square.and.arrow.down") { importing = true }
                    .help("Fill the record from a GitHub security advisory")
                    .popover(isPresented: $importing, arrowEdge: .bottom) {
                        AdvisoryForm(
                            title: "Import a GitHub Advisory",
                            message: "Fills in the record from a repository security advisory, replacing what is here. "
                                + "You can edit everything after.",
                            action: "Import"
                        ) { url in
                            text = try await store.fromAdvisory(url)
                            importing = false
                        }
                    }
                Button("Close Editor", systemImage: "xmark") { close() }
                    .help("Close the editor. Your draft is kept.")
                Button("\(verb)…") {
                    if publish {
                        confirming = true
                    } else {
                        Task { await review() }
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(problems != [] || parseError != nil || busy)
            }
        }
        .task {
            do {
                let draft = try await store.draft(id)
                // In the form's own layout, so switching to the form does not count as an edit.
                let normalized = (try? Container(text: draft))?.text ?? draft
                text = normalized
                loadedText = normalized
            } catch {
                failure = error.localizedDescription
                loadedText = ""
            }
        }
        .onChange(of: text) {
            do {
                let parsed = try Container(text: text)
                if parsed != container { container = parsed }
                parseError = nil
            } catch {
                parseError = (error as? DecodingError).map(describe) ?? error.localizedDescription
            }
            if let loadedText, text != loadedText { store.saveDraft(id, container: text) }
        }
        .onChange(of: container) {
            if mode == .form, container.text != text { text = container.text }
        }
        .task(id: text) {
            problems = nil
            try? await Task.sleep(for: .milliseconds(300))
            guard !Task.isCancelled else { return }
            problems = Problem.parse(await store.check(text))
        }
        .confirmationDialog(
            store.status?.isProduction == true ? "\(verb) \(id) on MITRE production?" : "\(verb) \(id)?",
            isPresented: $confirming
        ) {
            Button(verb) { Task { await send() } }
        } message: {
            Text("The record becomes public.")
        }
        .sheet(isPresented: Binding(get: { changes != nil }, set: { if !$0 { changes = nil } })) {
            UpdateReview(
                id: id, production: store.status?.isProduction == true, changes: changes ?? [],
                cancel: { changes = nil },
                update: {
                    changes = nil
                    Task { await send() }
                })
        }
    }

    /// Shows what the update changes in the published record before it goes out.
    private func review() async {
        do {
            let published = try await store.published(id) ?? ""
            changes = DiffLine.lines(from: published, to: (try? Container(text: text))?.text ?? text)
        } catch {
            failure = error.localizedDescription
        }
    }

    private var statusBar: some View {
        HStack(spacing: 8) {
            switch problems {
            case nil:
                ProgressView().controlSize(.small)
                Text("Checking…").foregroundStyle(.secondary)
            case let problems? where problems.isEmpty:
                Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
                Text("Ready to \(verb.lowercased())")
            case let problems?:
                Button {
                    revealed = true
                    showingProblems = true
                } label: {
                    Label(
                        problems.count == 1 ? "1 problem" : "\(problems.count) problems",
                        systemImage: "exclamationmark.triangle.fill")
                }
                .buttonStyle(.link)
                .foregroundStyle(.orange)
                .popover(isPresented: $showingProblems, arrowEdge: .top) { ProblemList(problems: problems) }
            }
            if let failure {
                Text(failure).foregroundStyle(.red).lineLimit(1).help(failure)
            }
            Spacer()
            if store.drafts.contains(id) {
                Text("Draft saved").foregroundStyle(.secondary)
                Button("Discard", role: .destructive) {
                    store.discardDraft(id)
                    close()
                }
                .buttonStyle(.link)
            }
        }
        .font(.callout)
        .padding(.horizontal, 14)
        .padding(.vertical, 8)
        .background(.bar)
    }

    private func send() async {
        busy = true
        defer { busy = false }
        do {
            _ = try await store.send(id, container: text, publish: publish)
            close()
        } catch let error as CLIError {
            failure = error.message
            if !error.problems.isEmpty { problems = Problem.parse(error.problems) }
        } catch {
            failure = error.localizedDescription
        }
    }

    private func describe(_ error: DecodingError) -> String {
        switch error {
        case .dataCorrupted(let context):
            let reason = (context.underlyingError as NSError?)?.userInfo[NSDebugDescriptionErrorKey] as? String
            return reason ?? context.debugDescription
        default:
            return error.localizedDescription
        }
    }
}

/// What an update changes in the published record, line by line, with Update and Cancel.
private struct UpdateReview: View {
    let id: String
    let production: Bool
    let changes: [DiffLine]
    let cancel: () -> Void
    let update: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(production ? "Update \(id) on MITRE production?" : "Update \(id)?").font(.headline)
            Text(
                changes.isEmpty
                    ? "Your record is the same as the published one, so there is nothing to update."
                    : "These changes to the published record become public."
            )
            .foregroundStyle(.secondary)
            if !changes.isEmpty {
                DiffList(changes: changes)
            }
            HStack {
                Spacer()
                Button("Cancel", action: cancel).keyboardShortcut(.cancelAction)
                Button("Update", action: update)
                    .keyboardShortcut(.defaultAction)
                    .disabled(changes.isEmpty)
            }
        }
        .padding(20)
        .frame(width: 680, height: changes.isEmpty ? nil : 460)
    }
}

private struct ProblemList: View {
    let problems: [Problem]

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 8) {
                ForEach(problems, id: \.self) { problem in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(problem.message)
                        Text(problem.path.isEmpty ? "the record" : problem.path)
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .padding()
            .frame(maxWidth: .infinity, alignment: .leading)
            .textSelection(.enabled)
        }
        .frame(width: 420, height: min(CGFloat(problems.count) * 44 + 24, 360))
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
        view.textContainerInset = NSSize(width: 12, height: 12)
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
