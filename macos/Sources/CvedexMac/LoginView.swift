import CvedexKit
import SwiftUI

/// The first thing you see, until you log in.
struct WelcomeView: View {
    var body: some View {
        VStack(spacing: 18) {
            Image(systemName: "checkmark.shield.fill")
                .font(.system(size: 56))
                .foregroundStyle(.tint)
            VStack(spacing: 6) {
                Text("Welcome to cvedex").font(.largeTitle.weight(.semibold))
                Text("Reserve CVE IDs and publish their records for your CNA.")
                    .foregroundStyle(.secondary)
            }
            LoginForm().frame(width: 480)
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

struct LoginForm: View {
    var cancel: (() -> Void)?
    var done: () -> Void = {}
    @Environment(Store.self) private var store
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
        VStack(alignment: .trailing, spacing: 12) {
            Form {
                Section {
                    Picker("Server", selection: $server) {
                        ForEach(Server.allCases) { Text($0.name).tag($0) }
                    }
                    if server == .other {
                        TextField("URL", text: $url, prompt: Text("https://cve.acme.org"))
                    }
                } footer: {
                    Text(
                        server == .production
                            ? "Records you publish here are public."
                            : "Start on the test instance, where nothing you publish is real."
                    )
                    .foregroundStyle(.secondary)
                    .footnote()
                }
                Section {
                    TextField("CNA short name", text: $org, prompt: Text("acme"))
                    TextField("Username", text: $user, prompt: Text("alice@acme.org"))
                    SecureField("API key", text: $key)
                } footer: {
                    Group {
                        if let failure {
                            Label(failure, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red)
                        } else {
                            Text("Your key goes to the keychain, shared with the cvedex command.")
                                .foregroundStyle(.secondary)
                        }
                    }
                    .footnote()
                }
            }
            .formStyle(.grouped)
            .scrollDisabled(true)
            .frame(height: server == .other ? 330 : 290)
            HStack {
                if busy { ProgressView().controlSize(.small) }
                if let cancel { Button("Cancel", action: cancel).keyboardShortcut(.cancelAction) }
                Button("Log In") { Task { await logIn() } }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
                    .disabled(org.isEmpty || user.isEmpty || key.isEmpty || (server == .other && url.isEmpty) || busy)
            }
            .padding(.horizontal, 20)
        }
    }

    private func logIn() async {
        busy = true
        defer { busy = false }
        do {
            try await store.login(url: server == .other ? url : server.rawValue, org: org, user: user, key: key)
            failure = nil
            done()
        } catch {
            failure = error.localizedDescription
        }
    }
}
