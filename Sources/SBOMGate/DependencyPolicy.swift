import Foundation

/// The dependency rules a team checks into the repo, next to `Package.swift`.
///
/// The point is that this is a reviewable file with an owner, not a paragraph
/// in a style guide: when an agent opens a PR that changes the graph, the gate
/// reads *this*, and changing what the gate accepts is itself a diff.
public struct DependencyPolicy: Equatable, Sendable, Codable {
    /// Source prefixes (`host/owner` or `host/owner/repo`) that may be added
    /// without a block. Matched on whole path segments.
    public var trustedSources: [String]
    /// Package identities allowed to be pinned to a revision (branch or
    /// commit) instead of a tag — usually an internal package mid-release.
    public var revisionPinAllowList: Set<String>
    /// When true, a revision pin outside the allow-list blocks instead of
    /// asking for review.
    public var blockRevisionPins: Bool

    public init(
        trustedSources: [String],
        revisionPinAllowList: Set<String> = [],
        blockRevisionPins: Bool = false
    ) {
        self.trustedSources = trustedSources
        self.revisionPinAllowList = revisionPinAllowList
        self.blockRevisionPins = blockRevisionPins
    }

    enum CodingKeys: String, CodingKey {
        case trustedSources, revisionPinAllowList, blockRevisionPins
    }

    /// Only `trustedSources` is required, so a minimal policy file is one line.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        trustedSources = try c.decode([String].self, forKey: .trustedSources)
        revisionPinAllowList = try c.decodeIfPresent(Set<String>.self, forKey: .revisionPinAllowList) ?? []
        blockRevisionPins = try c.decodeIfPresent(Bool.self, forKey: .blockRevisionPins) ?? false
    }

    /// Reads a policy from JSON, e.g. a `dependency-policy.json` kept next to
    /// `Package.swift` so that changing it goes through review like any code.
    public static func decode(_ json: String) throws -> DependencyPolicy {
        try JSONDecoder().decode(DependencyPolicy.self, from: Data(json.utf8))
    }

    public static func load(from url: URL) throws -> DependencyPolicy {
        try JSONDecoder().decode(DependencyPolicy.self, from: Data(contentsOf: url))
    }

    public func trusts(_ source: PackageSource?) -> Bool {
        guard let source else { return false }
        return trustedSources.contains(where: { source.isUnder($0) })
    }

    /// The policy used by the demo and the article's sample run.
    public static let sample = DependencyPolicy(
        trustedSources: [
            "github.com/apple",
            "github.com/swiftlang",
            "github.com/pointfreeco",
            "github.com/storefront-inc"
        ]
    )
}
