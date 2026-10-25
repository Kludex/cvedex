import CvedexKit
import SwiftUI

struct RejectView: View {
    let id: String
    @Environment(Store.self) private var store
    @Environment(\.dismiss) private var dismiss
    @State private var reason = ""
    @State private var confirming = false
    @State private var busy = false
    @State private var failure: String?

    var body: some View {
        Form {
            Section {
                TextField("Reason", text: $reason, prompt: Text("Duplicate of CVE-2026-1200."), axis: .vertical)
                    .lineLimit(3...6)
            } header: {
                Text("Reject \(id)")
            } footer: {
                Text("A published ID gets a rejected record in place of its record. In English.")
                    .foregroundStyle(.secondary)
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
                Button("Reject…") { confirming = true }
                    .disabled(reason.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || busy)
            }
        }
        .confirmationDialog("Reject \(id)? It will be public.", isPresented: $confirming) {
            Button("Reject", role: .destructive) {
                Task {
                    busy = true
                    defer { busy = false }
                    do {
                        try await store.reject(id, reason: reason)
                        dismiss()
                    } catch {
                        failure = error.localizedDescription
                    }
                }
            }
        }
    }
}
