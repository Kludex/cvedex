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
        WindowGroup("cvedex") {
            if let store {
                ContentView().environment(store)
            } else {
                ContentUnavailableView(
                    "cvedex not found", systemImage: "exclamationmark.triangle",
                    description: Text("Install cvedex on your PATH, or run the app from its bundle."))
            }
        }
    }
}
