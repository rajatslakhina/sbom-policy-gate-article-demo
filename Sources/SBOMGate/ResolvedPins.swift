import Foundation

/// A minimal reader for `Package.resolved` (version 2 and 3), used to show
/// what the lockfile diff of the same PR would contain. It lists pins, not
/// who uses them: which is SE-0509's own motivation for the SBOM.
public struct ResolvedFile: Codable, Equatable, Sendable {
    public struct Pin: Codable, Equatable, Sendable {
        public struct State: Codable, Equatable, Sendable {
            public var revision: String?
            public var version: String?
            public var branch: String?
            public init(revision: String?, version: String?, branch: String? = nil) {
                self.revision = revision
                self.version = version
                self.branch = branch
            }
        }
        public var identity: String
        public var kind: String
        public var location: String
        public var state: State

        public init(identity: String, kind: String = "remoteSourceControl", location: String, state: State) {
            self.identity = identity
            self.kind = kind
            self.location = location
            self.state = state
        }
    }

    public var pins: [Pin]
    public var version: Int

    public init(pins: [Pin], version: Int = 3) {
        self.pins = pins
        self.version = version
    }

    public static func decode(_ json: String) throws -> ResolvedFile {
        try JSONDecoder().decode(ResolvedFile.self, from: Data(json.utf8))
    }

    /// Identities whose pin line would show up in a lockfile diff.
    public static func changedIdentities(base: ResolvedFile, head: ResolvedFile) -> Set<String> {
        let a = Dictionary(base.pins.map { ($0.identity, $0) }, uniquingKeysWith: { first, _ in first })
        let b = Dictionary(head.pins.map { ($0.identity, $0) }, uniquingKeysWith: { first, _ in first })
        var changed: Set<String> = []
        for id in Set(a.keys).union(b.keys) where a[id] != b[id] {
            changed.insert(id)
        }
        return changed
    }
}
