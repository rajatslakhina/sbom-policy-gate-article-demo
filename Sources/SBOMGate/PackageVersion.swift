import Foundation

/// A SwiftPM SBOM component version: SE-0509 records "either a version tag or
/// SHA", and appends `-modified` when the checkout had uncommitted changes.
public enum PackageVersion: Equatable, Sendable, CustomStringConvertible {
    case semver(major: Int, minor: Int, patch: Int, prerelease: String?, modified: Bool)
    case revision(sha: String, modified: Bool)
    case unknown(String)

    public init(_ raw: String) {
        var text = raw.trimmingCharacters(in: .whitespaces)
        var modified = false
        if text.hasSuffix("-modified") {
            modified = true
            text = String(text.dropLast("-modified".count))
        }
        if PackageVersion.isSHA(text) {
            self = .revision(sha: text.lowercased(), modified: modified)
            return
        }
        let cleaned = text.hasPrefix("v") ? String(text.dropFirst()) : text
        let coreAndPre = cleaned.split(separator: "-", maxSplits: 1, omittingEmptySubsequences: false)
        let core = coreAndPre.first.map(String.init) ?? ""
        let pre = coreAndPre.count > 1 ? String(coreAndPre[1]) : nil
        let parts = core.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard (1...3).contains(parts.count) else {
            self = .unknown(raw)
            return
        }
        var numbers: [Int] = []
        for part in parts {
            guard let n = Int(part), n >= 0 else {
                self = .unknown(raw)
                return
            }
            numbers.append(n)
        }
        while numbers.count < 3 { numbers.append(0) }
        self = .semver(major: numbers[0], minor: numbers[1], patch: numbers[2],
                       prerelease: pre, modified: modified)
    }

    static func isSHA(_ text: String) -> Bool {
        text.count == 40 && text.allSatisfy { $0.isHexDigit }
    }

    public var isRevisionPin: Bool {
        if case .revision = self { return true }
        return false
    }

    public var isModified: Bool {
        switch self {
        case .semver(_, _, _, _, let m): return m
        case .revision(_, let m): return m
        case .unknown(let raw): return raw.hasSuffix("-modified")
        }
    }

    /// Pre-1.0 tags make no compatibility promise under SemVer.
    public var isPreStable: Bool {
        if case .semver(let major, _, _, _, _) = self { return major == 0 }
        return false
    }

    public var description: String {
        switch self {
        case .semver(let a, let b, let c, let pre, let m):
            return "\(a).\(b).\(c)" + (pre.map { "-\($0)" } ?? "") + (m ? "-modified" : "")
        case .revision(let sha, let m):
            return String(sha.prefix(7)) + (m ? "-modified" : "")
        case .unknown(let raw):
            return raw
        }
    }

    /// How a version moved between two SBOMs.
    public enum Change: Equatable, Sendable {
        case same
        case patch
        case minor
        /// A SemVer-breaking move: a major bump, or a minor bump below 1.0.
        case breaking
        case downgrade
        case tagToRevision
        case revisionToTag
        case revisionChanged
        case incomparable
    }

    public static func change(from old: PackageVersion, to new: PackageVersion) -> Change {
        switch (old, new) {
        case let (.semver(a1, b1, c1, p1, _), .semver(a2, b2, c2, p2, _)):
            if (a1, b1, c1) == (a2, b2, c2) {
                return p1 == p2 ? .same : .patch
            }
            if (a2, b2, c2) < (a1, b1, c1) { return .downgrade }
            if a2 != a1 { return .breaking }
            if b2 != b1 { return a1 == 0 ? .breaking : .minor }
            return .patch
        case (.semver, .revision):
            return .tagToRevision
        case (.revision, .semver):
            return .revisionToTag
        case let (.revision(s1, _), .revision(s2, _)):
            return s1 == s2 ? .same : .revisionChanged
        default:
            return old == new ? .same : .incomparable
        }
    }
}

/// Where a package came from, normalised to `host/owner/repo` so that
/// `https://github.com/apple/swift-log.git`, `git@github.com:apple/swift-log.git`
/// and `pkg:swift/github.com/apple/swift-log@1.6.1` all compare equal.
public struct PackageSource: Hashable, Sendable, CustomStringConvertible {
    public let path: String

    public init?(purl: String?, repositoryURL: String?) {
        if let purl, let fromPurl = PackageSource.fromPurl(purl) {
            path = fromPurl
        } else if let repositoryURL, let fromURL = PackageSource.fromURL(repositoryURL) {
            path = fromURL
        } else {
            return nil
        }
    }

    public init(path: String) {
        self.path = path.lowercased()
    }

    public var description: String { path }

    /// Does this source sit under a trusted prefix such as `github.com/apple/`?
    /// Matching is on whole path segments, so `github.com/apple` does not
    /// trust `github.com/applesauce/…`.
    public func isUnder(_ prefix: String) -> Bool {
        var p = prefix.lowercased()
        while p.hasSuffix("/") { p.removeLast() }
        guard !p.isEmpty else { return false }
        return path == p || path.hasPrefix(p + "/")
    }

    static func fromPurl(_ purl: String) -> String? {
        guard purl.hasPrefix("pkg:swift/") else { return nil }
        var body = String(purl.dropFirst("pkg:swift/".count))
        if let at = body.firstIndex(of: "@") { body = String(body[..<at]) }
        // Product purls append ":ProductName" to the repository path.
        if let colon = body.firstIndex(of: ":") { body = String(body[..<colon]) }
        return body.isEmpty ? nil : body.lowercased()
    }

    static func fromURL(_ url: String) -> String? {
        var s = url.trimmingCharacters(in: .whitespaces)
        for scheme in ["https://", "http://", "ssh://", "git://"] where s.hasPrefix(scheme) {
            s = String(s.dropFirst(scheme.count))
        }
        if s.hasPrefix("git@") {
            s = String(s.dropFirst("git@".count))
            if let colon = s.firstIndex(of: ":") { s.replaceSubrange(colon...colon, with: "/") }
        }
        while s.hasSuffix("/") { s.removeLast() }
        if s.hasSuffix(".git") { s = String(s.dropLast(4)) }
        return s.isEmpty ? nil : s.lowercased()
    }
}
