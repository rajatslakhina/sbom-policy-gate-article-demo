import Foundation

/// One thing the gate noticed, with the rule that fired and — where the graph
/// can say — the product path that makes it matter.
public struct Finding: Equatable, Sendable, Identifiable {
    public enum Severity: Int, Comparable, Sendable, CaseIterable {
        case info = 0
        case review = 1
        case block = 2

        public static func < (lhs: Severity, rhs: Severity) -> Bool { lhs.rawValue < rhs.rawValue }

        public var label: String {
            switch self {
            case .info: return "INFO"
            case .review: return "REVIEW"
            case .block: return "BLOCK"
            }
        }
    }

    public enum Rule: String, Sendable, CaseIterable {
        /// Same package identity, different repository. SwiftPM derives the
        /// identity from the last path component, so a fork keeps the name.
        case sourceMoved = "SOURCE_MOVED"
        /// One side records where a package came from and the other doesn't,
        /// so `SOURCE_MOVED` can't be checked. Asks a human instead of passing.
        case sourceUnknown = "SOURCE_UNKNOWN"
        /// A newly added package from outside `trustedSources`.
        case untrustedSource = "UNTRUSTED_SOURCE"
        /// A dependency pinned to a commit or branch instead of a tag.
        case revisionPin = "REVISION_PIN"
        /// A component version ending in `-modified`: the SBOM describes a
        /// working tree, not a commit anyone can rebuild.
        case workingTree = "WORKING_TREE"
        case breakingBump = "BREAKING_BUMP"
        case downgrade = "DOWNGRADE"
        case newPackage = "NEW_PACKAGE"
        /// A package that was already in the graph now has a product path
        /// from something the root builds. No pin changes, so
        /// `Package.resolved` shows nothing.
        case newlyShipped = "NEWLY_SHIPPED"
        case compatibleBump = "COMPATIBLE_BUMP"
        case removed = "REMOVED"
        /// Base and head were produced by different SwiftPM versions, so a
        /// difference may be the tool's, not the PR's.
        case toolDrift = "TOOL_DRIFT"
    }

    public let rule: Rule
    public let severity: Severity
    public let package: String
    public let message: String
    public let path: [String]?

    public var id: String { rule.rawValue + "|" + package }

    public init(rule: Rule, severity: Severity, package: String, message: String, path: [String]? = nil) {
        self.rule = rule
        self.severity = severity
        self.package = package
        self.message = message
        self.path = path
    }
}

public struct GateReport: Equatable, Sendable {
    public enum Verdict: Equatable, Sendable {
        case pass
        case needsReview
        case blocked
    }

    public let findings: [Finding]

    public var verdict: Verdict {
        switch findings.map(\.severity).max() {
        case .block?: return .blocked
        case .review?: return .needsReview
        default: return .pass
        }
    }

    public func count(_ severity: Finding.Severity) -> Int {
        findings.filter { $0.severity == severity }.count
    }

    /// Packages any finding touches.
    public var packagesTouched: Set<String> {
        Set(findings.map(\.package))
    }
}

public enum SBOMGateError: Error, Equatable, CustomStringConvertible {
    /// Diffing a CycloneDX 1.7 file against a 1.6 one compares two schemas,
    /// not two dependency graphs. Regenerate both with the same toolchain.
    case specVersionMismatch(base: String, head: String)
    case missingRoot
    /// Base and head describe different root packages; any diff would be noise.
    case rootMismatch(base: String, head: String)
    /// Generated with `--sbom-filter product` (no packages) or `package`
    /// (no products), so the gate would pass things it can't see.
    case filteredSBOM(side: String)

    public var description: String {
        switch self {
        case let .specVersionMismatch(base, head):
            return "Base SBOM is CycloneDX \(base), head is \(head). Regenerate both with the same toolchain."
        case .missingRoot:
            return "SBOM has no metadata.component, so there is no root to trace product paths from."
        case let .rootMismatch(base, head):
            return "Base SBOM describes '\(base)', head describes '\(head)'. Compare SBOMs of the same package."
        case let .filteredSBOM(side):
            return "The \(side) SBOM has no package or no product components. Generate both with the default --sbom-filter all."
        }
    }
}

/// Compares the SBOM of the merge base with the SBOM of a PR head and decides
/// what a human has to look at.
///
/// Deterministic on purpose: no model reads the graph. The same two files and
/// the same policy always produce the same findings in the same order.
public enum SBOMGate {

    public static func evaluate(base: CycloneDXDocument, head: CycloneDXDocument, policy: DependencyPolicy) throws -> GateReport {
        guard base.specVersion == head.specVersion else {
            throw SBOMGateError.specVersionMismatch(base: base.specVersion, head: head.specVersion)
        }
        let old = SBOMGraph(base)
        let new = SBOMGraph(head)
        guard let baseRoot = old.rootIdentity, let headRoot = new.rootIdentity else {
            throw SBOMGateError.missingRoot
        }
        guard baseRoot == headRoot else {
            throw SBOMGateError.rootMismatch(base: baseRoot, head: headRoot)
        }
        // `--sbom-filter package` keeps packages but drops products;
        // `--sbom-filter product` does the reverse. A package with no
        // dependencies at all has neither, and is a valid SBOM.
        for (side, graph) in [("base", old), ("head", new)]
        where graph.packages.isEmpty != graph.dependencyProductRefs.isEmpty {
            throw SBOMGateError.filteredSBOM(side: side)
        }

        var findings: [Finding] = []

        if let a = old.toolVersion, let b = new.toolVersion, a != b {
            findings.append(Finding(
                rule: .toolDrift, severity: .review, package: new.rootIdentity ?? "root",
                message: "Base built by SwiftPM \(a), head by \(b). Some differences may come from the tool."))
        }

        if let rv = new.rootVersion, rv.isModified {
            findings.append(Finding(
                rule: .workingTree, severity: .block, package: new.rootIdentity ?? "root",
                message: "Head SBOM was generated from uncommitted changes (\(rv)). Regenerate from the PR commit."))
        }

        let rootID = new.rootIdentity
        let identities = Set(old.packages.keys).union(new.packages.keys)
            .filter { $0 != rootID && $0 != old.rootIdentity }
            .sorted()

        for id in identities {
            let before = old.packages[id]
            let after = new.packages[id]

            switch (before, after) {
            case (nil, let added?):
                findings += addedFindings(added, graph: new, policy: policy)

            case (let removed?, nil):
                findings.append(Finding(
                    rule: .removed, severity: .info, package: id,
                    message: "Removed (was \(removed.version?.description ?? "unversioned"))."))

            case let (b?, a?):
                findings += changedFindings(before: b, after: a, oldGraph: old, newGraph: new, policy: policy)

            case (nil, nil):
                break
            }
        }

        let ordered = findings.enumerated().sorted { lhs, rhs in
            if lhs.element.severity != rhs.element.severity {
                return lhs.element.severity > rhs.element.severity
            }
            return lhs.offset < rhs.offset
        }.map(\.element)
        return GateReport(findings: ordered)
    }

    /// Convenience for the common case of two JSON files on disk or in memory.
    public static func evaluate(baseJSON: String, headJSON: String, policy: DependencyPolicy) throws -> GateReport {
        try evaluate(base: CycloneDXDocument.decode(baseJSON),
                     head: CycloneDXDocument.decode(headJSON),
                     policy: policy)
    }

    // MARK: - Rules

    static func addedFindings(_ pkg: SBOMGraph.Package, graph: SBOMGraph, policy: DependencyPolicy) -> [Finding] {
        var out: [Finding] = []
        let path = graph.shippingPath(to: pkg.identity)
        let where_ = pkg.source?.description ?? "an unknown source"
        let version = pkg.version?.description ?? "unversioned"

        if !policy.trusts(pkg.source) {
            out.append(Finding(
                rule: .untrustedSource, severity: .block, package: pkg.identity,
                message: "New package from \(where_), which is not a trusted source.", path: path))
        }
        if let v = pkg.version, v.isRevisionPin, !policy.revisionPinAllowList.contains(pkg.identity) {
            out.append(Finding(
                rule: .revisionPin, severity: policy.blockRevisionPins ? .block : .review, package: pkg.identity,
                message: "New package pinned to revision \(v), not a tag.", path: path))
        }
        if let v = pkg.version, v.isModified {
            out.append(Finding(
                rule: .workingTree, severity: .block, package: pkg.identity,
                message: "Resolved from a modified checkout (\(v)).", path: path))
        }
        let preStable = pkg.version?.isPreStable ?? false
        out.append(Finding(
            rule: .newPackage, severity: preStable ? .review : .info, package: pkg.identity,
            message: preStable
                ? "New package at \(version): below 1.0, so any minor release may break the API."
                : "New package at \(version) from \(where_).",
            path: path))
        return out
    }

    static func changedFindings(
        before: SBOMGraph.Package, after: SBOMGraph.Package,
        oldGraph: SBOMGraph, newGraph: SBOMGraph, policy: DependencyPolicy
    ) -> [Finding] {
        var out: [Finding] = []
        let id = after.identity
        let path = newGraph.shippingPath(to: id)

        if let s1 = before.source, let s2 = after.source, s1 != s2 {
            out.append(Finding(
                rule: .sourceMoved, severity: .block, package: id,
                message: "Same identity, different repository: \(s1) → \(s2). SwiftPM names a package by its last path component, so a fork keeps the name.",
                path: path))
        } else if (before.source == nil) != (after.source == nil) {
            out.append(Finding(
                rule: .sourceUnknown, severity: .review, package: id,
                message: "Only one side records where this package came from (\(before.source?.description ?? "none") → \(after.source?.description ?? "none")), so a repository change can't be ruled out.",
                path: path))
        }

        if let v1 = before.version, let v2 = after.version {
            switch PackageVersion.change(from: v1, to: v2) {
            case .tagToRevision, .revisionChanged:
                if !policy.revisionPinAllowList.contains(id) {
                    out.append(Finding(
                        rule: .revisionPin, severity: policy.blockRevisionPins ? .block : .review, package: id,
                        message: "\(v1) → revision \(v2). A branch or commit pin has no compatibility promise.",
                        path: path))
                }
            case .breaking:
                out.append(Finding(
                    rule: .breakingBump, severity: .review, package: id,
                    message: "\(v1) → \(v2) is a SemVer-breaking bump.", path: path))
            case .downgrade:
                out.append(Finding(
                    rule: .downgrade, severity: .review, package: id,
                    message: "\(v1) → \(v2) is a downgrade.", path: path))
            case .minor, .patch, .revisionToTag:
                out.append(Finding(
                    rule: .compatibleBump, severity: .info, package: id,
                    message: "\(v1) → \(v2).", path: path))
            case .same, .incomparable:
                break
            }
            if v2.isModified && !v1.isModified {
                out.append(Finding(
                    rule: .workingTree, severity: .block, package: id,
                    message: "Resolved from a modified checkout (\(v2)).", path: path))
            }
        }

        if oldGraph.shippingPath(to: id) == nil, let path {
            let unchanged = before.rawVersion == after.rawVersion && before.source == after.source
            out.append(Finding(
                rule: .newlyShipped, severity: .review, package: id,
                message: "Already in the graph, but now linked by a product you ship."
                    + (unchanged ? " No pin changed." : ""),
                path: path))
        }
        return out
    }
}
