import CvedexKit
import SwiftUI

struct ContentView: View {
    @Environment(Store.self) private var store
    @State private var selection: CVEID.ID?
    @State private var state = "All"
    @State private var loggingIn = false
    @State private var reserving = false
    @State private var failure: String?

    private var shown: [CVEID] {
        state == "All" ? store.ids : store.ids.filter { $0.state == state.uppercased() }
    }

    var body: some View {
        NavigationSplitView {
            List(shown, selection: $selection) { id in
                VStack(alignment: .leading) {
                    Text(id.cveId).font(.body.monospaced())
                    Text(id.cvedexd?.note != nil ? "\(id.state), changes requested" : id.state)
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            .navigationSplitViewColumnWidth(min: 220, ideal: 260)
            .safeAreaInset(edge: .top) {
                Picker("State", selection: $state) {
                    ForEach(["All", "Reserved", "Published", "Rejected"], id: \.self, content: Text.init)
                }
                .labelsHidden().padding(8)
            }
            .overlay {
                if let error = store.error {
                    ContentUnavailableView(
                        "Could not load", systemImage: "exclamationmark.triangle",
                        description: Text(error.message))
                } else if shown.isEmpty && !store.loading {
                    ContentUnavailableView("No CVE IDs", systemImage: "tray")
                }
            }
        } detail: {
            if let id = store.ids.first(where: { $0.id == selection }) {
                RecordView(id: id).id(id)
            } else {
                ContentUnavailableView("Select a CVE ID", systemImage: "shield")
            }
        }
        .navigationTitle("cvedex")
        .navigationSubtitle(subtitle)
        .toolbar {
            ToolbarItemGroup {
                Button("Reserve", systemImage: "plus") { reserving = true }
                    .help("Reserve a CVE ID for this year")
                    .disabled(store.status?.loggedIn != true)
                Button("Refresh", systemImage: "arrow.clockwise") { Task { await store.refresh() } }
                    .keyboardShortcut("r")
                Menu("Account", systemImage: "person.crop.circle") {
                    Button("Log In…") { loggingIn = true }
                    Button("Log Out") {
                        Task { await attempt { try await store.logout() } }
                    }
                    .disabled(store.status?.loggedIn != true)
                }
            }
        }
        .task {
            await store.refresh()
            loggingIn = store.error == nil && store.status?.loggedIn == false
        }
        .sheet(isPresented: $loggingIn) { LoginView() }
        .confirmationDialog(
            "Reserve a CVE ID for \(String(Calendar.current.component(.year, from: .now)))?",
            isPresented: $reserving
        ) {
            Button("Reserve") {
                Task { await attempt { selection = try await store.reserve() } }
            }
        }
        .alert("cvedex", isPresented: .constant(failure != nil), presenting: failure) { _ in
            Button("OK") { failure = nil }
        } message: {
            Text($0)
        }
    }

    private var subtitle: String {
        guard let status = store.status else { return "" }
        let server = status.url.replacing("https://", with: "")
        guard let user = status.user?.username ?? status.submitter else { return "\(server), not logged in" }
        return "\(user) on \(server)"
    }

    private func attempt(_ action: () async throws -> Void) async {
        do {
            try await action()
        } catch {
            failure = error.localizedDescription
        }
    }
}
