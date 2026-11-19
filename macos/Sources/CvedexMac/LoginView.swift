import CvedexKit
import SwiftUI

/// The first thing you see, until you log in.
struct WelcomeView: View {
    @Environment(Store.self) private var store

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
            if !store.accounts.isEmpty {
                Menu("Use Another Account") { AccountPicker() }.fixedSize()
            }
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
    @State private var repository = ""
    @State private var org = ""
    @State private var user = ""
    @State private var key = ""
    @State private var busy = false
    @State private var failure: String?

    enum Server: String, CaseIterable, Identifiable {
        case test = "https://cveawg-test.mitre.org"
        case production = "https://cveawg.mitre.org"
        case repository = "https://github.com/"
        case other = ""

        var id: Self { self }
        var name: String {
            switch self {
            case .test: "MITRE test instance"
            case .production: "MITRE production"
            case .repository: "GitHub repository"
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
                    if server == .repository {
                        TextField("Repository", text: $repository, prompt: Text("acme/cves"))
                    }
                } footer: {
                    if server == .repository {
                        outcome("You sign in with your GitHub login, from gh auth login.")
                    } else {
                        Text(
                            server == .production
                                ? "Records you publish here are public."
                                : "Start on the test instance, where nothing you publish is real."
                        )
                        .foregroundStyle(.secondary)
                        .footnote()
                    }
                }
                if server != .repository {
                    Section {
                        TextField("CNA short name", text: $org, prompt: Text("acme"))
                        TextField("Username", text: $user, prompt: Text("alice@acme.org"))
                            .textContentType(.username)
                        SecureField("API key", text: $key)
                            .textContentType(.password)
                    } footer: {
                        outcome("Your key goes to the keychain, shared with the cvedex command.")
                    }
                }
            }
            .formStyle(.grouped)
            .scrollDisabled(true)
            .frame(height: [.repository: 150, .other: 330][server] ?? 290)
            HStack {
                if busy { ProgressView().controlSize(.small) }
                if let cancel { Button("Cancel", action: cancel).keyboardShortcut(.cancelAction) }
                Button("Log In") { Task { await logIn() } }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
                    .disabled(incomplete || busy)
            }
            .padding(.horizontal, 20)
        }
    }

    private var incomplete: Bool {
        switch server {
        case .repository: repository.isEmpty
        case .other: url.isEmpty || org.isEmpty || user.isEmpty || key.isEmpty
        case .test, .production: org.isEmpty || user.isEmpty || key.isEmpty
        }
    }

    /// The failure of the last attempt, else a hint.
    private func outcome(_ hint: String) -> some View {
        Group {
            if let failure {
                Label(failure, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red)
            } else {
                Text(hint).foregroundStyle(.secondary)
            }
        }
        .footnote()
    }

    private func logIn() async {
        busy = true
        defer { busy = false }
        do {
            switch server {
            case .repository:
                // A pasted URL works as well as owner/name. cvedex asks GitHub, so there is no key to send.
                let name = repository.replacingOccurrences(of: server.rawValue, with: "")
                try await store.login(url: server.rawValue + name, org: "", user: "", key: "")
            case .other:
                try await store.login(url: url, org: org, user: user, key: key)
            case .test, .production:
                try await store.login(url: server.rawValue, org: org, user: user, key: key)
            }
            failure = nil
            done()
        } catch {
            failure = error.localizedDescription
        }
    }
}
