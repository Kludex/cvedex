import Foundation

/// One thing wrong with a record, at a JSON pointer such as `/affected/0/vendor`.
public struct Problem: Equatable, Hashable, Sendable {
    public let path: String
    public let message: String

    public init(path: String, message: String) {
        self.path = path
        self.message = message
    }

    /// Reads the problems `cvedex record check` lists, one `- /path: message` each, with the ones under a
    /// failed `oneOf` indented and without their own path.
    public static func parse(_ lines: [String]) -> [Problem] {
        var parent = ""
        return lines.compactMap { line in
            var text = line.trimmingCharacters(in: .whitespaces)
            if text.hasPrefix("- ") { text.removeFirst(2) }
            var path = line.hasPrefix(" ") ? parent : ""
            if text.hasPrefix("/"), let colon = text.range(of: ": ") {
                path = String(text[..<colon.lowerBound])
                text = String(text[colon.upperBound...])
            }
            if !line.hasPrefix(" ") { parent = path }
            // shortcut: drops the schema's alternatives bookkeeping by wording, revisit if the check's library changes.
            if text.hasSuffix("failed, none matched") || text.hasPrefix("maxProperties") { return nil }
            return Problem(path: path, message: humanize(text))
        }
    }

    /// The message for an empty field, which the form holds back until you ask what is missing.
    public static let required = "Required"

    private static func humanize(_ message: String) -> String {
        if message.hasPrefix("minLength: got 0,") { return required }
        if message.contains("is not valid uri") { return "Needs a full URL, starting with https://" }
        if message.contains("'^CWE-[1-9][0-9]*$'") { return "Needs a CWE ID, such as CWE-22" }
        return message
    }
}
