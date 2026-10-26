/// One line of a diff between two texts.
public enum DiffLine: Equatable, Sendable {
    case same(String)
    case removed(String)
    case added(String)
    /// Unchanged lines left out, far from any change.
    case skipped(Int)

    var isSame: Bool { if case .same = self { true } else { false } }

    /// The lines that differ between `old` and `new`, with `context` unchanged lines around each change. Empty
    /// when the texts are the same.
    public static func lines(from old: String, to new: String, context: Int = 2) -> [DiffLine] {
        let before = old.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        let after = new.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        var removed = Set<Int>()
        var added = Set<Int>()
        for change in after.difference(from: before) {
            switch change {
            case .remove(let offset, _, _): removed.insert(offset)
            case .insert(let offset, _, _): added.insert(offset)
            }
        }
        guard !removed.isEmpty || !added.isEmpty else { return [] }

        var lines: [DiffLine] = []
        var (i, j) = (0, 0)
        while i < before.count || j < after.count {
            if removed.contains(i) {
                lines.append(.removed(before[i]))
                i += 1
            } else if added.contains(j) {
                lines.append(.added(after[j]))
                j += 1
            } else {
                lines.append(.same(before[i]))
                (i, j) = (i + 1, j + 1)
            }
        }

        var shown: [DiffLine] = []
        var start = 0
        while start < lines.count {
            var end = start
            while end < lines.count && lines[end].isSame == lines[start].isSame { end += 1 }
            let head = start == 0 ? 0 : context
            let tail = end == lines.count ? 0 : context
            if lines[start].isSame && end - start > head + tail {
                shown += lines[start..<start + head]
                shown.append(.skipped(end - start - head - tail))
                shown += lines[end - tail..<end]
            } else {
                shown += lines[start..<end]
            }
            start = end
        }
        return shown
    }
}
