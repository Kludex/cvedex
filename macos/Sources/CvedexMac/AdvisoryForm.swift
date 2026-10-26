import SwiftUI

/// Asks for a GitHub advisory URL and runs `run` with it, showing why it failed if it throws.
struct AdvisoryForm: View {
    let title: String
    let message: String
    let action: String
    var cancel: (() -> Void)?
    let run: (String) async throws -> Void
    @State private var url = ""
    @State private var busy = false
    @State private var failure: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(title).font(.headline)
            Text(message)
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            TextField(
                "Advisory URL", text: $url,
                prompt: Text("https://github.com/acme/widget/security/advisories/GHSA-…")
            )
            .textFieldStyle(.roundedBorder)
            .onSubmit(submit)
            if let failure {
                Label(failure, systemImage: "exclamationmark.triangle.fill")
                    .font(.callout)
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                if busy { ProgressView().controlSize(.small) }
                Spacer()
                if let cancel {
                    Button("Cancel", action: cancel).keyboardShortcut(.cancelAction)
                }
                Button(action, action: submit)
                    .keyboardShortcut(.defaultAction)
                    .disabled(trimmed.isEmpty || busy)
            }
        }
        .padding()
        .frame(width: 460)
    }

    private var trimmed: String { url.trimmingCharacters(in: .whitespacesAndNewlines) }

    private func submit() {
        guard !trimmed.isEmpty, !busy else { return }
        busy = true
        Task {
            defer { busy = false }
            do {
                try await run(trimmed)
                failure = nil
            } catch {
                failure = error.localizedDescription
            }
        }
    }
}
