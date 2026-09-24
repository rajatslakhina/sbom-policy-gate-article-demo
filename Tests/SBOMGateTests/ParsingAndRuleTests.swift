import XCTest
@testable import SBOMGate

final class ParsingAndRuleTests: XCTestCase {

    // The component and dependency shapes below are SE-0509's own CycloneDX
    // examples, trimmed to one package.
    static let proposalShapedJSON = """
    {
      "bomFormat": "CycloneDX",
      "specVersion": "1.7",
      "version": 1,
      "metadata": {
        "timestamp": "2025-11-19T21:42:50Z",
        "tools": { "components": [ {
          "bom-ref": "urn:uuid:40316357-938f-4a8c-9962-e928fbc251a6",
          "name": "swift-package-manager", "version": "6.3.0-dev",
          "purl": "pkg:swift/github.com/swiftlang/swift-package-manager@6.3.0-dev",
          "scope": "excluded", "type": "application" } ] },
        "component": {
          "bom-ref": "app", "name": "app", "version": "1.0.0",
          "purl": "pkg:swift/github.com/me/app@1.0.0", "type": "application",
          "properties": [ { "name": "swift-entity", "value": "swift-package" } ] }
      },
      "components": [
        { "bom-ref": "swift-asn1:SwiftASN1", "name": "SwiftASN1",
          "pedigree": { "commits": [ { "uid": "40d25bbb2fc5b557a9aa8512210bded327c0f60d",
                                        "url": "https://github.com/apple/swift-asn1.git" } ] },
          "properties": [ { "name": "swift-entity", "value": "swift-product" } ],
          "purl": "pkg:swift/github.com/apple/swift-asn1:SwiftASN1@1.5.0",
          "scope": "required", "type": "library", "version": "1.5.0" },
        { "bom-ref": "swift-asn1", "name": "swift-asn1",
          "properties": [ { "name": "swift-entity", "value": "swift-package" } ],
          "purl": "pkg:swift/github.com/apple/swift-asn1@1.5.0",
          "scope": "required", "type": "library", "version": "1.5.0" }
      ],
      "dependencies": [
        { "ref": "app", "dependsOn": ["app:App", "swift-asn1"] },
        { "ref": "app:App", "dependsOn": ["swift-asn1:SwiftASN1"] },
        { "ref": "swift-asn1", "dependsOn": ["swift-asn1:SwiftASN1"] },
        { "ref": "swift-asn1:SwiftASN1" }
      ]
    }
    """

    func testDecodesProposalShapedDocument() throws {
        let doc = try CycloneDXDocument.decode(Self.proposalShapedJSON)
        XCTAssertEqual(doc.specVersion, "1.7")
        XCTAssertEqual(doc.components.count, 2)
        XCTAssertEqual(doc.components.first?.swiftEntity, "swift-product")
        XCTAssertEqual(doc.dependencies.last?.dependsOn, [], "missing dependsOn decodes as empty")

        let graph = SBOMGraph(doc)
        XCTAssertEqual(graph.toolVersion, "6.3.0-dev")
        XCTAssertEqual(Array(graph.packages.keys), ["swift-asn1"])
        XCTAssertEqual(graph.packages["swift-asn1"]?.source, PackageSource(path: "github.com/apple/swift-asn1"))
        // The root product is only named in the edges, not as a component.
        XCTAssertEqual(graph.rootProducts, ["app:App"])
        XCTAssertEqual(graph.shippingPath(to: "swift-asn1"), ["app:App", "swift-asn1:SwiftASN1"])
    }

    func testMalformedJSONThrows() {
        XCTAssertThrowsError(try CycloneDXDocument.decode("{ \"components\": [] }"))
        XCTAssertThrowsError(try CycloneDXDocument.decode("not json"))
    }

    func testDocumentWithoutArraysDecodesEmpty() throws {
        let doc = try CycloneDXDocument.decode(#"{"specVersion":"1.7"}"#)
        XCTAssertTrue(doc.components.isEmpty)
        XCTAssertTrue(doc.dependencies.isEmpty)
        XCTAssertTrue(SBOMGraph(doc).rootProducts.isEmpty)
        XCTAssertNil(SBOMGraph(doc).shippingPath(to: "anything"))
    }

    func testSpecVersionMismatchRefusesToDiff() {
        var older = SampleSBOMs.base
        older.specVersion = "1.6"
        XCTAssertThrowsError(try SBOMGate.evaluate(base: older, head: SampleSBOMs.head, policy: .sample)) { error in
            XCTAssertEqual(error as? SBOMGateError, .specVersionMismatch(base: "1.6", head: "1.7"))
        }
    }

    func testMissingRootThrows() {
        var head = SampleSBOMs.head
        head.metadata = nil
        XCTAssertThrowsError(try SBOMGate.evaluate(base: SampleSBOMs.base, head: head, policy: .sample)) { error in
            XCTAssertEqual(error as? SBOMGateError, .missingRoot)
        }
    }

    func testMissingBaseRootThrows() {
        var base = SampleSBOMs.base
        base.metadata?.component = nil
        XCTAssertThrowsError(try SBOMGate.evaluate(base: base, head: SampleSBOMs.head, policy: .sample)) { error in
            XCTAssertEqual(error as? SBOMGateError, .missingRoot)
        }
    }

    func testDifferentRootsRefuseToDiff() {
        var base = SampleSBOMs.base
        base.metadata?.component?.bomRef = "some-other-app"
        XCTAssertThrowsError(try SBOMGate.evaluate(base: base, head: SampleSBOMs.head, policy: .sample)) { error in
            XCTAssertEqual(error as? SBOMGateError, .rootMismatch(base: "some-other-app", head: "storefront"))
        }
    }

    func testFilteredSBOMsRefuseToDiff() {
        var productOnly = SampleSBOMs.head
        productOnly.components.removeAll { $0.swiftEntity == "swift-package" }
        XCTAssertThrowsError(try SBOMGate.evaluate(base: SampleSBOMs.base, head: productOnly, policy: .sample)) { error in
            XCTAssertEqual(error as? SBOMGateError, .filteredSBOM(side: "head"))
        }
        var packageOnly = SampleSBOMs.base
        packageOnly.components.removeAll { $0.swiftEntity == "swift-product" }
        XCTAssertThrowsError(try SBOMGate.evaluate(base: packageOnly, head: SampleSBOMs.head, policy: .sample)) { error in
            XCTAssertEqual(error as? SBOMGateError, .filteredSBOM(side: "base"))
        }
    }

    func testPackageWithNoDependenciesIsValid() throws {
        let leaf = CycloneDXDocument(
            specVersion: "1.7",
            metadata: .init(component: .init(bomRef: "leaf", name: "leaf", version: "1.0.0", purl: nil)),
            components: [],
            dependencies: [.init(ref: "leaf", dependsOn: ["leaf:Leaf"])])
        let report = try SBOMGate.evaluate(base: leaf, head: leaf, policy: .sample)
        XCTAssertEqual(report.verdict, .pass)
    }

    func testRootTestProductDoesNotCountAsShipping() throws {
        // SwiftPM can emit the root's own test product (scope "test"). A helper
        // reached only from it must not hide a later shipping path.
        func withTestProduct(_ doc: CycloneDXDocument) -> CycloneDXDocument {
            var d = doc
            d.components.append(.init(
                bomRef: "storefront:StorefrontPackageTests", name: "StorefrontPackageTests",
                version: "5.12.0", purl: nil, scope: "test",
                properties: [.init(name: "swift-entity", value: "swift-product")]))
            d.dependencies.append(.init(ref: "storefront:StorefrontPackageTests",
                                        dependsOn: ["swift-snapshot-testing:SnapshotTesting"]))
            return d
        }
        let base = withTestProduct(SampleSBOMs.base)
        XCTAssertEqual(SBOMGraph(base).rootProducts, ["storefront:StorefrontKit"])
        XCTAssertNil(SBOMGraph(base).shippingPath(to: "swift-snapshot-testing"))

        let report = try SBOMGate.evaluate(base: base, head: withTestProduct(SampleSBOMs.head), policy: .sample)
        XCTAssertTrue(report.findings.contains { $0.rule == .newlyShipped && $0.package == "swift-snapshot-testing" })
        XCTAssertEqual(report.findings.count, 8)
    }

    func testNewlyShippedOnlySaysNoPinChangedWhenTrue() throws {
        let report = try SBOMGate.evaluate(base: SampleSBOMs.base, head: SampleSBOMs.head, policy: .sample)
        let snap = try XCTUnwrap(report.findings.first { $0.rule == .newlyShipped })
        XCTAssertTrue(snap.message.hasSuffix("No pin changed."))

        var head = SampleSBOMs.head
        guard let i = head.components.firstIndex(where: { $0.bomRef == "swift-snapshot-testing" }) else {
            return XCTFail("sample must contain swift-snapshot-testing")
        }
        head.components[i].version = "1.18.0"
        head.components[i].purl = "pkg:swift/github.com/pointfreeco/swift-snapshot-testing@1.18.0"
        let bumped = try SBOMGate.evaluate(base: SampleSBOMs.base, head: head, policy: .sample)
        let moved = try XCTUnwrap(bumped.findings.first { $0.rule == .newlyShipped })
        XCTAssertFalse(moved.message.contains("No pin changed"))
    }

    func testPolicyLoadsFromJSON() throws {
        let minimal = try DependencyPolicy.decode(#"{"trustedSources": ["github.com/apple"]}"#)
        XCTAssertEqual(minimal, DependencyPolicy(trustedSources: ["github.com/apple"]))

        let full = try DependencyPolicy.decode("""
        {"trustedSources": ["github.com/apple"], "revisionPinAllowList": ["internal-kit"], "blockRevisionPins": true}
        """)
        XCTAssertEqual(full.revisionPinAllowList, ["internal-kit"])
        XCTAssertTrue(full.blockRevisionPins)
        XCTAssertThrowsError(try DependencyPolicy.decode(#"{"blockRevisionPins": true}"#), "trustedSources is required")
    }

    func testMissingSourceOnOneSideIsReviewed() throws {
        var head = SampleSBOMs.base
        guard let i = head.components.firstIndex(where: { $0.bomRef == "swift-log" }) else {
            return XCTFail("sample must contain swift-log")
        }
        head.components[i].purl = nil
        head.components[i].pedigree = nil
        let report = try SBOMGate.evaluate(base: SampleSBOMs.base, head: head, policy: .sample)
        XCTAssertEqual(report.findings.map(\.rule), [.sourceUnknown])
        XCTAssertEqual(report.verdict, .needsReview)
    }

    func testToolDriftIsReviewed() throws {
        var head = SampleSBOMs.base
        head.metadata?.tools?.components?[0].version = "6.4.1"
        let report = try SBOMGate.evaluate(base: SampleSBOMs.base, head: head, policy: .sample)
        XCTAssertEqual(report.findings.map(\.rule), [.toolDrift])
        XCTAssertEqual(report.verdict, .needsReview)
    }

    func testModifiedRootBlocks() throws {
        var head = SampleSBOMs.base
        head.metadata?.component?.version = "5.12.0-modified"
        let report = try SBOMGate.evaluate(base: SampleSBOMs.base, head: head, policy: .sample)
        XCTAssertEqual(report.findings.map(\.rule), [.workingTree])
        XCTAssertEqual(report.verdict, .blocked)
    }

    func testRemovedPackageIsInfo() throws {
        var head = SampleSBOMs.base
        head.components.removeAll { $0.bomRef == "swift-collections" }
        let report = try SBOMGate.evaluate(base: SampleSBOMs.base, head: head, policy: .sample)
        XCTAssertEqual(report.findings.map(\.rule), [.removed])
        XCTAssertEqual(report.verdict, .pass)
    }

    func testDowngradeIsReviewed() throws {
        var head = SampleSBOMs.base
        guard let i = head.components.firstIndex(where: { $0.bomRef == "swift-log" }) else {
            return XCTFail("sample must contain swift-log")
        }
        head.components[i].version = "1.5.0"
        head.components[i].purl = "pkg:swift/github.com/apple/swift-log@1.5.0"
        let report = try SBOMGate.evaluate(base: SampleSBOMs.base, head: head, policy: .sample)
        XCTAssertEqual(report.findings.map(\.rule), [.downgrade])
    }

    // MARK: Versions

    func testVersionParsing() {
        XCTAssertEqual(PackageVersion("1.5.0"), .semver(major: 1, minor: 5, patch: 0, prerelease: nil, modified: false))
        XCTAssertEqual(PackageVersion("v2.0"), .semver(major: 2, minor: 0, patch: 0, prerelease: nil, modified: false))
        XCTAssertEqual(PackageVersion("1.0.0-beta.2"), .semver(major: 1, minor: 0, patch: 0, prerelease: "beta.2", modified: false))
        let sha = "37990426e3f1cb4344f39641e634c76130c1fb42"
        XCTAssertEqual(PackageVersion(sha + "-modified"), .revision(sha: sha, modified: true))
        XCTAssertTrue(PackageVersion(sha).isRevisionPin)
        XCTAssertEqual(PackageVersion("main"), .unknown("main"))
        XCTAssertEqual(PackageVersion("1.2.3.4"), .unknown("1.2.3.4"))
        XCTAssertEqual(PackageVersion(""), .unknown(""))
    }

    func testVersionChanges() {
        func c(_ a: String, _ b: String) -> PackageVersion.Change {
            PackageVersion.change(from: PackageVersion(a), to: PackageVersion(b))
        }
        XCTAssertEqual(c("3.8.0", "4.0.0"), .breaking)
        XCTAssertEqual(c("0.3.1", "0.4.0"), .breaking, "below 1.0 a minor bump is breaking")
        XCTAssertEqual(c("1.3.0", "1.4.0"), .minor)
        XCTAssertEqual(c("1.3.0", "1.3.1"), .patch)
        XCTAssertEqual(c("1.3.1", "1.3.0"), .downgrade)
        XCTAssertEqual(c("1.0.0", "1.0.0"), .same)
        XCTAssertEqual(c("1.6.1", String(repeating: "a", count: 40)), .tagToRevision)
        XCTAssertEqual(c(String(repeating: "a", count: 40), String(repeating: "b", count: 40)), .revisionChanged)
        XCTAssertEqual(c("main", "develop"), .incomparable)
    }

    func testPrereleasePrecedence() {
        func c(_ a: String, _ b: String) -> PackageVersion.Change {
            PackageVersion.change(from: PackageVersion(a), to: PackageVersion(b))
        }
        XCTAssertEqual(c("1.0.0", "1.0.0-beta"), .downgrade, "a release outranks its prerelease")
        XCTAssertEqual(c("1.0.0-rc.2", "1.0.0-alpha"), .downgrade)
        XCTAssertEqual(c("1.0.0-alpha.2", "1.0.0-alpha.10"), .patch, "numeric identifiers compare numerically")
        XCTAssertEqual(c("1.0.0-rc.1", "1.0.0"), .patch)
        XCTAssertEqual(c("1.0.0-beta", "1.0.0-beta"), .same)
        XCTAssertEqual(c("1.2.3+build.1", "1.2.3+build.9"), .same, "build metadata is ignored")
        XCTAssertEqual(c("0.0.3", "0.0.4"), .breaking, "0.0.x promises nothing")
        XCTAssertEqual(c("0.3.1", "0.3.2"), .patch)
    }

    // MARK: Sources

    func testSourceNormalisation() {
        let a = PackageSource(purl: "pkg:swift/github.com/Apple/swift-log:Logging@1.6.1", repositoryURL: nil)
        let b = PackageSource(purl: nil, repositoryURL: "git@github.com:apple/swift-log.git")
        let c = PackageSource(purl: nil, repositoryURL: "https://github.com/apple/swift-log.git/")
        XCTAssertEqual(a?.path, "github.com/apple/swift-log")
        XCTAssertEqual(a, b)
        XCTAssertEqual(b, c)
        XCTAssertNil(PackageSource(purl: "pkg:npm/left-pad@1.0.0", repositoryURL: nil))
    }

    func testTrustMatchesWholeSegments() {
        let policy = DependencyPolicy(trustedSources: ["github.com/apple/"])
        XCTAssertTrue(policy.trusts(PackageSource(path: "github.com/apple/swift-log")))
        XCTAssertFalse(policy.trusts(PackageSource(path: "github.com/applesauce/swift-log")))
        XCTAssertFalse(policy.trusts(nil))
        XCTAssertFalse(DependencyPolicy(trustedSources: [""]).trusts(PackageSource(path: "github.com/x/y")))
    }
}
