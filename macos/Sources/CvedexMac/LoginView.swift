import CvedexKit
import SwiftUI

struct LoginView: View {
    @Environment(Store.self) private var store
    @Environment(\.dismiss) private var dismiss
    @State private var server = Server.test
    @State private var url = ""
    @State private var org = ""
    @State private var user = ""
    @State private var key = ""
    @State private var busy = false
    @State private var failure: String?

    enum Server: String, CaseIterable, Identifiable {
        case test = "https://cveawg-test.mitre.org"
        case production = "https://cveawg.mitre.org"
        case other = ""

        var id: Self { self }
        var name: String {
            switch self {
            case .test: "MITRE test instance"
            case .production: "MITRE production"
            case .other: "cvedexd or another server"
            }
        }
    }

    var body: some View {
        Form {
            Section {
                Picker("Server", selection: $server) {
                    ForEach(Server.allCases) { Text($0.name).tag($0) }
                }
                if server == .other {
                    TextField("URL", text: $url, prompt: Text("https://cve.acme.org"))
                }
            } footer: {
                Text("Start on the test instance, where nothing you publish is real.").foregroundStyle(.secondary)
            }
            Section {
                TextField("CNA short name", text: $org, prompt: Text("acme"))
                TextField("Username", text: $user, prompt: Text("alice@acme.org"))
                SecureField("API key", text: $key)
            } footer: {
                Text("The key is saved in your keychain, shared with the cvedex command.").foregroundStyle(.secondary)
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
                Button("Log In") { Task { await logIn() } }
                    .disabled(org.isEmpty || user.isEmpty || key.isEmpty || busy)
            }
        }
    }

    private func logIn() async {
        busy = true
        defer { busy = false }
        do {
            try await store.login(url: server == .other ? url : server.rawValue, org: org, user: user, key: key)
            dismiss()
        } catch {
            failure = error.localizedDescription
        }
    }
}
