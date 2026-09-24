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
