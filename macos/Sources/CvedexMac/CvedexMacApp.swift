import AppKit
import CvedexKit
import SwiftUI

@main
struct CvedexMacApp: App {
    @State private var store = CLI.find().map { Store(cli: CLI(executable: $0)) }

    init() {
        // Outside an app bundle, as with `swift run`, the app would not get a Dock icon or focus.
        NSApplication.shared.setActivationPolicy(.regular)
    }

    var body: some Scene {
        Window("cvedex", id: "main") {
            if let store {
                RootView().environment(store)
            } else {
                ContentUnavailableView(
                    "cvedex not found", systemImage: "exclamationmark.triangle",
                    description: Text("Install cvedex on your PATH, or run the app from its bundle."))
            }
        }
        .defaultSize(width: 1180, height: 780)
        .defaultLaunchBehavior(.presented)
        .commands {
            CommandGroup(replacing: .newItem) {}
            if let store {
                CommandGroup(after: .toolbar) {
                    Button("Refresh") { Task { await store.refresh() } }.keyboardShortcut("r")
                }
            }
        }
    }
}

/// The welcome screen until you log in, then the IDs and their records.
struct RootView: View {
    @Environment(Store.self) private var store

    var body: some View {
        ZStack {
            if store.status?.loggedIn == false {
                WelcomeView()
            } else if store.status == nil, let error = store.error {
                ContentUnavailableView {
                    Label("Could not run cvedex", systemImage: "exclamationmark.triangle")
                } description: {
                    Text(error.message)
                } actions: {
                    Button("Try Again") { Task { await store.refresh() } }
                }
            } else if store.status == nil {
                ProgressView()
            } else {
                MainView()
            }
        }
        .task { await store.refresh() }
    }
}
