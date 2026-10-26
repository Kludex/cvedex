import Foundation

/// Runs the `cvedex` binary with `--json`, the app's only way to reach CVE Services.
public actor CLI {
    let executable: URL

    public init(executable: URL) {
        self.executable = executable
        // Writing a record to a cvedex that already exited must fail, not kill the app.
        signal(SIGPIPE, SIG_IGN)
    }

    /// The `cvedex` next to the app's executable, else the first one on `PATH`.
    public static func find(
        bundle: Bundle = .main, environment: [String: String] = ProcessInfo.processInfo.environment
    ) -> URL? {
        if let bundled = bundle.url(forAuxiliaryExecutable: "cvedex") {
            return bundled
        }
        let paths = (environment["PATH"] ?? "").split(separator: ":")
        return paths.map { URL(filePath: String($0)).appending(path: "cvedex") }
            .first { FileManager.default.isExecutableFile(atPath: $0.path) }
    }

    /// Runs `cvedex <arguments> --json`, writing `input` to its stdin, and returns its stdout.
    public func run(_ arguments: [String], input: Data = Data()) async throws -> Data {
        let process = Process()
        process.executableURL = executable
        process.arguments = arguments + ["--json"]
        process.environment = Self.environment
        let stdin = Pipe()
        let stdout = Pipe()
        let stderr = Pipe()
        process.standardInput = stdin
        process.standardOutput = stdout
        process.standardError = stderr
        async let output = Self.readAll(stdout.fileHandleForReading)
        async let errors = Self.readAll(stderr.fileHandleForReading)
        let status: Int32 = try await withCheckedThrowingContinuation { continuation in
            process.terminationHandler = { continuation.resume(returning: $0.terminationStatus) }
            do {
                try process.run()
            } catch {
                process.terminationHandler = nil
                try? stdout.fileHandleForWriting.close()
                try? stderr.fileHandleForWriting.close()
                continuation.resume(throwing: error)
                return
            }
            try? stdin.fileHandleForWriting.write(contentsOf: input)
            try? stdin.fileHandleForWriting.close()
        }
        let (data, message) = await (output, errors)
        guard status == 0 else {
            throw CLIError(stderr: message)
        }
        return data
    }

    /// The app's environment, with Homebrew on `PATH` so `cvedex` finds `gh` in an app opened from Finder, which
    /// gets only the system's directories.
    private static let environment = ProcessInfo.processInfo.environment.merging(
        [
            "PATH": [ProcessInfo.processInfo.environment["PATH"], "/opt/homebrew/bin", "/usr/local/bin"]
                .compactMap(\.self).joined(separator: ":")
        ]
    ) { _, new in new }

    private static func readAll(_ handle: FileHandle) async -> Data {
        await withCheckedContinuation { continuation in
            DispatchQueue.global().async { continuation.resume(returning: handle.readDataToEndOfFile()) }
        }
    }
}

/// A failed `cvedex` command, from the JSON it prints on stderr.
public struct CLIError: Error, Equatable, Sendable {
    /// The API's or cvedex's code, such as `CVE_RECORD_DNE` or `INVALID_RECORD`.
    public let code: String
    public let message: String
    /// What is wrong with a record, one line each, from cvedex's schema check or CVE Services.
    public let problems: [String]

    public init(code: String, message: String, problems: [String] = []) {
        self.code = code
        self.message = message
        self.problems = problems
    }

    init(stderr: Data) {
        guard let body = try? JSONDecoder().decode(Body.self, from: stderr) else {
            let text = String(decoding: stderr, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
            self.init(code: "CVEDEX_ERROR", message: text.isEmpty ? "cvedex failed" : text)
            return
        }
        self.init(
            code: body.error ?? "CVEDEX_ERROR", message: body.message ?? "cvedex failed",
            problems: body.details?.lines ?? [])
    }

    private struct Body: Decodable {
        let error: String?
        let message: String?
        let details: Details?
    }

    /// The problems in any of the shapes `details` comes in: cvedex's `problems`, a schema error's
    /// `errors`, or a list of bad parameters.
    private struct Details: Decodable {
        let lines: [String]

        private enum Keys: String, CodingKey { case problems, errors }

        private struct Problem: Decodable {
            let instancePath: String?
            let param: String?
            let message: String?
            let msg: String?

            var line: String {
                [instancePath ?? param, message ?? msg].compactMap(\.self).joined(separator: ": ")
            }
        }

        init(from decoder: any Decoder) throws {
            if let params = try? [Problem](from: decoder) {
                lines = params.map(\.line)
            } else if let fields = try? decoder.container(keyedBy: Keys.self) {
                lines =
                    (try? fields.decode([String].self, forKey: .problems))
                    ?? ((try? fields.decode([Problem].self, forKey: .errors)) ?? []).map(\.line)
            } else {
                lines = []
            }
        }
    }
}

extension CLIError: LocalizedError {
    public var errorDescription: String? { message }
}
