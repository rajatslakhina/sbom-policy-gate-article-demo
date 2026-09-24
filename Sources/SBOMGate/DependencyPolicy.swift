import Foundation

/// The dependency rules a team checks into the repo, next to `Package.swift`.
///
/// The point is that this is a reviewable file with an owner, not a paragraph
/// in a style guide: when an agent opens a PR that changes the graph, the gate
/// reads *this*, and changing what the gate accepts is itself a diff.
public struct DependencyPolicy: Equatable, Sendable {
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
