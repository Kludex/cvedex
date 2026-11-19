import CvedexKit
import SwiftUI

struct MainView: View {
    @Environment(Store.self) private var store
    @State private var selection: String?
    @State private var created: String?
    @State private var query = ""

    var body: some View {
        NavigationSplitView {
            Sidebar(selection: $selection, created: $created, query: query)
                .searchable(text: $query, placement: .sidebar, prompt: "Search IDs and titles")
                .navigationSplitViewColumnWidth(min: 240, ideal: 270, max: 360)
        } detail: {
            if let id = store.ids.first(where: { $0.id == selection }) {
                RecordView(id: id, editing: id.id == created).id(id.id)
            } else {
                ContentUnavailableView(
                    "No ID Selected", systemImage: "shield.lefthalf.filled",
                    description: Text(
                        "Pick an ID in the sidebar to read its record, or reserve one to write a new record."))
            }
        }
        .onChange(of: selection) { if selection != created { created = nil } }
    }
}

struct Sidebar: View {
    @Environment(Store.self) private var store
    @Binding var selection: String?
    @Binding var created: String?
    let query: String
    @State private var reserving = false
    @State private var importing = false
    @State private var failure: String?

    private let groups = [("RESERVED", "Reserved"), ("PUBLISHED", "Published"), ("REJECTED", "Rejected")]

    private var matching: [CVEID] {
        let ids =
            query.isEmpty
            ? store.ids
            : store.ids.filter {
                $0.cveId.localizedCaseInsensitiveContains(query)
                    || store.title($0.cveId)?.localizedCaseInsensitiveContains(query) == true
            }
        return ids.sorted { $0.cveId.localizedStandardCompare($1.cveId) == .orderedDescending }
    }

    var body: some View {
        List(selection: $selection) {
            ForEach(groups, id: \.0) { state, name in
                let ids = matching.filter { $0.state == state }
                if !ids.isEmpty {
                    Section(name) {
                        ForEach(ids) { id in
                            IDRow(
                                id: id, title: store.title(id.cveId), draft: store.drafts.contains(id.id),
                                review: store.reviews.contains { $0.cveId == id.cveId }
                            )
                            .task(id: store.titles[id.cveId] == nil) { await store.loadTitle(id) }
                        }
                    }
                }
            }
        }
        .listStyle(.sidebar)
        .overlay {
            if let error = store.error {
                ContentUnavailableView(
                    "Could Not Load IDs", systemImage: "exclamationmark.triangle", description: Text(error.message))
            } else if matching.isEmpty && !store.loading {
                if query.isEmpty {
                    ContentUnavailableView(
                        "No IDs Yet", systemImage: "tray",
                        description: Text("Reserve an ID before you write its record, or start from a GitHub advisory.")
                    )
                } else {
                    ContentUnavailableView.search(text: query)
                }
            }
        }
        .safeAreaInset(edge: .bottom, spacing: 0) { AccountBar() }
        .toolbar {
            ToolbarItemGroup {
                Menu("New", systemImage: "plus") {
                    Button("Reserve ID…") { reserving = true }
                    Button("New from GitHub Advisory…") { importing = true }
                } primaryAction: {
                    reserving = true
                }
                .help("Reserve a CVE ID for this year, or hold to start one from a GitHub advisory")
            }
        }
        .confirmationDialog(
            "Reserve a CVE ID for \(String(Calendar.current.component(.year, from: .now)))?",
            isPresented: $reserving
        ) {
            Button("Reserve") {
                Task {
                    do {
                        selection = try await store.reserve()
                    } catch {
                        failure = error.localizedDescription
                    }
                }
            }
        } message: {
            Text("It counts against your CNA's quota until you publish or reject it.")
        }
        .sheet(isPresented: $importing) {
            AdvisoryForm(
                title: "New CVE from a GitHub Advisory",
                message: "Reserves a CVE ID for \(String(Calendar.current.component(.year, from: .now))), which counts "
                    + "against your CNA's quota, and fills in its record from the advisory. Nothing is published "
                    + "until you review the record.",
                action: "Reserve and Import",
                cancel: { importing = false }
            ) { url in
                created = try await store.reserve(fromAdvisory: url)
                selection = created
                importing = false
            }
        }
        .alert("Could not reserve an ID", isPresented: .constant(failure != nil), presenting: failure) { _ in
            Button("OK") { failure = nil }
        } message: {
            Text($0)
        }
    }
}

private struct IDRow: View {
    let id: CVEID
    let title: String?
    let draft: Bool
    /// Whether its record waits for a review you can give.
    let review: Bool

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: Style.symbol(id.state))
                .foregroundStyle(Style.color(id.state))
                .frame(width: 18)
            VStack(alignment: .leading, spacing: 1) {
                Text(id.cveId).fontWeight(.medium).monospacedDigit()
                Text(detail).font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.tail)
            }
            Spacer()
            if review {
                Image(systemName: "checkmark.seal").foregroundStyle(.purple).help("Waiting for review")
            }
            if draft {
                Image(systemName: "pencil.line").foregroundStyle(.secondary).help("Unsent draft")
            }
        }
        .padding(.vertical, 2)
        .help(title ?? "")
    }

    private var detail: String {
        if id.cvedexd?.note != nil { return "Changes requested" }
        if let title { return title }
        return id.reserved.map { "Reserved \(Style.day($0))" } ?? id.state.capitalized
    }
}

/// Who you are and where, at the foot of the sidebar.
private struct AccountBar: View {
    @Environment(Store.self) private var store
    @State private var adding = false

    var body: some View {
        if let status = store.status {
            HStack(spacing: 10) {
                Circle()
                    .fill(status.isProduction ? Color.red : status.url.contains("-test.") ? .orange : .blue)
                    .frame(width: 8, height: 8)
                VStack(alignment: .leading, spacing: 1) {
                    Text(status.user?.username ?? status.submitter ?? "").font(.callout).lineLimit(1)
                    Text(serverName(status.url)).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                }
                Spacer()
                Menu {
                    AccountPicker()
                    Button("Add Account…") { adding = true }
                    Button("Log Out") { Task { try? await store.logout() } }
                } label: {
                    Image(systemName: "ellipsis.circle")
                }
                .menuStyle(.borderlessButton)
                .menuIndicator(.hidden)
                .fixedSize()
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 10)
            .overlay(alignment: .top) { Divider() }
            .sheet(isPresented: $adding) {
                LoginForm(cancel: { adding = false }, done: { adding = false })
                    .padding()
                    .frame(width: 480)
            }
        }
    }
}

/// The accounts you are logged in to, with the one in use checked. Picking another uses it.
struct AccountPicker: View {
    @Environment(Store.self) private var store

    var body: some View {
        Picker("Accounts", selection: inUse) {
            ForEach(Array(store.accounts.enumerated()), id: \.offset) { n, account in
                Text("\(account.user) · \(serverName(account.url))").tag(n + 1)
            }
        }
        .pickerStyle(.inline)
    }

    /// The number `cvedex accounts` gives the account in use, or 0 for none.
    private var inUse: Binding<Int> {
        Binding(
            get: { (store.accounts.firstIndex(where: \.active) ?? -1) + 1 },
            set: { number in Task { try? await store.use(account: number) } })
    }
}

/// A server as people call it: MITRE's by name, a GitHub repository by its own, any other by its host.
private func serverName(_ url: String) -> String {
    switch url {
    case "https://cveawg.mitre.org": return "MITRE production"
    case "https://cveawg-test.mitre.org": return "MITRE test instance"
    default:
        guard let parsed = URL(string: url) else { return url }
        return parsed.host() == "github.com" ? String(parsed.path().dropFirst()) : parsed.host() ?? url
    }
}
