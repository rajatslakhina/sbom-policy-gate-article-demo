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
        var cleaned = text.hasPrefix("v") ? String(text.dropFirst()) : text
        // SemVer build metadata ("+build.5") never affects precedence.
        if let plus = cleaned.firstIndex(of: "+") { cleaned = String(cleaned[..<plus]) }
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
                switch comparePrerelease(p1, p2) {
                case 0: return .same
                case let order where order > 0: return .downgrade   // e.g. 1.0.0 → 1.0.0-beta
                default: return .patch                              // e.g. 1.0.0-rc.1 → 1.0.0
                }
            }
            if (a2, b2, c2) < (a1, b1, c1) { return .downgrade }
            if a2 != a1 { return .breaking }
            // Below 1.0, SemVer promises nothing: a 0.x minor bump is breaking,
            // and so is any change at all inside 0.0.x.
            if a1 == 0 && (b2 != b1 || b1 == 0) { return .breaking }
            if b2 != b1 { return .minor }
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

    /// SemVer §11 precedence for prerelease tags: `-1` if `lhs` sorts lower,
    /// `1` if higher, `0` if equal. A release (no tag) outranks any prerelease.
    static func comparePrerelease(_ lhs: String?, _ rhs: String?) -> Int {
        switch (lhs, rhs) {
        case (nil, nil): return 0
        case (nil, _?): return 1
        case (_?, nil): return -1
        case let (l?, r?):
            let li = l.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
            let ri = r.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
            for (a, b) in zip(li, ri) where a != b {
                switch (Int(a), Int(b)) {
                case let (x?, y?): return x < y ? -1 : 1
                case (_?, nil): return -1          // numeric identifiers sort first
                case (nil, _?): return 1
                case (nil, nil): return a < b ? -1 : 1
                }
            }
            if li.count == ri.count { return 0 }
            return li.count < ri.count ? -1 : 1
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
