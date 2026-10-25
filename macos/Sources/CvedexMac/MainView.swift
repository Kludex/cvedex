import CvedexKit
import SwiftUI

struct MainView: View {
    @Environment(Store.self) private var store
    @State private var selection: String?
    @State private var query = ""

    var body: some View {
        NavigationSplitView {
            Sidebar(selection: $selection, query: query)
                .searchable(text: $query, placement: .sidebar, prompt: "Search IDs")
                .navigationSplitViewColumnWidth(min: 240, ideal: 270, max: 360)
        } detail: {
            if let id = store.ids.first(where: { $0.id == selection }) {
                RecordView(id: id).id(id.id)
            } else {
                ContentUnavailableView(
                    "No ID Selected", systemImage: "shield.lefthalf.filled",
                    description: Text(
                        "Pick an ID in the sidebar to read its record, or reserve one to write a new record."))
            }
        }
    }
}

struct Sidebar: View {
    @Environment(Store.self) private var store
    @Binding var selection: String?
    let query: String
    @State private var reserving = false
    @State private var failure: String?

    private let groups = [("RESERVED", "Reserved"), ("PUBLISHED", "Published"), ("REJECTED", "Rejected")]

    private var matching: [CVEID] {
        let ids = query.isEmpty ? store.ids : store.ids.filter { $0.cveId.localizedCaseInsensitiveContains(query) }
        return ids.sorted { $0.cveId.localizedStandardCompare($1.cveId) == .orderedDescending }
    }

    var body: some View {
        List(selection: $selection) {
            ForEach(groups, id: \.0) { state, name in
                let ids = matching.filter { $0.state == state }
                if !ids.isEmpty {
                    Section(name) {
                        ForEach(ids) { IDRow(id: $0, draft: store.drafts.contains($0.id)) }
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
                        description: Text("Reserve an ID before you write its record."))
                } else {
                    ContentUnavailableView.search(text: query)
                }
            }
        }
        .safeAreaInset(edge: .bottom, spacing: 0) { AccountBar() }
        .toolbar {
            ToolbarItemGroup {
                Button("Reserve ID", systemImage: "plus") { reserving = true }
                    .help("Reserve a CVE ID for this year")
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
        .alert("Could not reserve an ID", isPresented: .constant(failure != nil), presenting: failure) { _ in
            Button("OK") { failure = nil }
        } message: {
            Text($0)
        }
    }
}

private struct IDRow: View {
    let id: CVEID
    let draft: Bool

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: Style.symbol(id.state))
                .foregroundStyle(Style.color(id.state))
                .frame(width: 18)
            VStack(alignment: .leading, spacing: 1) {
                Text(id.cveId).fontWeight(.medium).monospacedDigit()
                Text(detail).font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            if draft {
                Image(systemName: "pencil.line").foregroundStyle(.secondary).help("Unsent draft")
            }
        }
        .padding(.vertical, 2)
    }

    private var detail: String {
        if id.cvedexd?.note != nil { return "Changes requested" }
        return id.reserved.map { "Reserved \(Style.day($0))" } ?? id.state.capitalized
    }
}

/// Who you are and where, at the foot of the sidebar.
private struct AccountBar: View {
    @Environment(Store.self) private var store
    @State private var switching = false

    var body: some View {
        if let status = store.status {
            HStack(spacing: 10) {
                Circle()
                    .fill(status.isProduction ? Color.red : status.url.contains("-test.") ? .orange : .blue)
                    .frame(width: 8, height: 8)
                VStack(alignment: .leading, spacing: 1) {
                    Text(status.user?.username ?? status.submitter ?? "").font(.callout).lineLimit(1)
                    Text(server(status)).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                }
                Spacer()
                Menu {
                    Button("Switch Account…") { switching = true }
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
            .sheet(isPresented: $switching) {
                LoginForm(cancel: { switching = false }, done: { switching = false })
                    .padding()
                    .frame(width: 480)
            }
        }
    }

    private func server(_ status: Status) -> String {
        if status.isProduction { return "MITRE production" }
        if status.url == "https://cveawg-test.mitre.org" { return "MITRE test instance" }
        return URL(string: status.url)?.host() ?? status.url
    }
}
