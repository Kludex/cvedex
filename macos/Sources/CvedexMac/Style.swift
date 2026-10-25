import CvedexKit
import SwiftUI

enum Style {
    static func symbol(_ state: String) -> String {
        switch state {
        case "PUBLISHED": "checkmark.seal.fill"
        case "REJECTED": "xmark.seal"
        default: "circle.dashed"
        }
    }

    static func color(_ state: String) -> Color {
        switch state {
        case "PUBLISHED": .green
        case "REJECTED": .secondary
        default: .orange
        }
    }

    static func severity(_ severity: String) -> Color {
        switch severity.uppercased() {
        case "CRITICAL": .purple
        case "HIGH": .red
        case "MEDIUM": .orange
        case "LOW": .yellow
        default: .secondary
        }
    }

    /// A CVSS score as written everywhere, `7.5`, whatever your locale's decimal separator.
    static func score(_ score: Double) -> String {
        String(format: "%.1f", score)
    }

    /// `2026-10-22T20:56:35.215Z` as `22 Oct 2026`, in your locale.
    static func day(_ timestamp: String) -> String {
        let date =
            (try? Date(timestamp, strategy: .iso8601.year().month().day().time(includingFractionalSeconds: true)))
            ?? (try? Date(timestamp, strategy: .iso8601))
        return date?.formatted(date: .abbreviated, time: .omitted) ?? String(timestamp.prefix(10))
    }
}

/// A small tinted capsule for a state or a score.
struct Badge: View {
    let text: String
    let color: Color

    var body: some View {
        Text(text)
            .font(.caption.weight(.semibold))
            .padding(.horizontal, 7)
            .padding(.vertical, 2)
            .foregroundStyle(color)
            .background(color.opacity(0.14), in: .capsule)
    }
}

extension View {
    /// Lines a section footer up with the rows above it. Grouped forms put footers on the trailing edge.
    func footnote() -> some View {
        padding(.leading, 12).frame(maxWidth: .infinity, alignment: .leading)
    }

    /// Shows what the schema check found at `paths` under this field. It wraps the field rather than adding a
    /// row, because a grouped form crashes on rows that render nothing.
    func issue(_ problems: [Problem], _ paths: String...) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            self
            ForEach(problems.filter { paths.contains($0.path) }, id: \.self) { problem in
                Label(problem.message, systemImage: "exclamationmark.circle.fill")
                    .font(.caption)
                    .foregroundStyle(.red)
            }
        }
    }
}

extension Binding {
    /// One item of a list, safe to read after a row removed it.
    func element<Item: ContainerItem>(_ index: Int, blank: Item) -> Binding<Item> where Value == [Item] {
        Binding<Item>(
            get: { index < wrappedValue.count ? wrappedValue[index] : blank },
            set: { if index < wrappedValue.count { wrappedValue[index] = $0 } })
    }
}
