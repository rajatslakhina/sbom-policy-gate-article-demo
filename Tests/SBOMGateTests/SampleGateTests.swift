import XCTest
@testable import SBOMGate

/// Pins every number the article quotes about the sample PR.
final class SampleGateTests: XCTestCase {

    private func sampleReport(_ policy: DependencyPolicy = .sample) throws -> GateReport {
        try SBOMGate.evaluate(base: SampleSBOMs.base, head: SampleSBOMs.head, policy: policy)
    }

    func testSampleVerdictAndCounts() throws {
        let report = try sampleReport()
        XCTAssertEqual(report.verdict, .blocked)
        XCTAssertEqual(report.findings.count, 8)
        XCTAssertEqual(report.count(.block), 2)
        XCTAssertEqual(report.count(.review), 4)
        XCTAssertEqual(report.count(.info), 2)
    }

    func testSampleFindingsInOrder() throws {
        let report = try sampleReport()
        let summary = report.findings.map { "\($0.severity.label) \($0.rule.rawValue) \($0.package)" }
        XCTAssertEqual(summary, [
            "BLOCK UNTRUSTED_SOURCE retry-kit",
            "BLOCK SOURCE_MOVED swift-log",
            "REVIEW NEW_PACKAGE retry-kit",
            "REVIEW BREAKING_BUMP swift-crypto",
            "REVIEW REVISION_PIN swift-log",
            "REVIEW NEWLY_SHIPPED swift-snapshot-testing",
            "INFO COMPATIBLE_BUMP swift-asn1",
            "INFO NEW_PACKAGE swift-async-algorithms",
        ])
    }

    func testLockfileSeesFivePinsAndMissesTheSnapshotHelper() throws {
        let pins = ResolvedFile.changedIdentities(base: SampleSBOMs.baseResolved, head: SampleSBOMs.headResolved)
        XCTAssertEqual(pins, ["retry-kit", "swift-asn1", "swift-async-algorithms", "swift-crypto", "swift-log"])

        let report = try sampleReport()
        XCTAssertEqual(report.packagesTouched.count, 6)
        let onlyInGate = report.packagesTouched.subtracting(pins)
        XCTAssertEqual(onlyInGate, ["swift-snapshot-testing"])
    }

    func testPathsExplainWhyAPackageShips() throws {
        let report = try sampleReport()
        let asn1 = try XCTUnwrap(report.findings.first { $0.package == "swift-asn1" })
        XCTAssertEqual(asn1.path, ["storefront:StorefrontKit", "swift-crypto:_CryptoExtras", "swift-asn1:SwiftASN1"])

        let snap = try XCTUnwrap(report.findings.first { $0.rule == .newlyShipped })
        XCTAssertEqual(snap.path, ["storefront:StorefrontKit", "swift-snapshot-testing:SnapshotTesting"])
    }

    func testBaseHadNoShippingPathForSnapshotTesting() {
        let base = SBOMGraph(SampleSBOMs.base)
        XCTAssertNil(base.shippingPath(to: "swift-snapshot-testing"))
        XCTAssertEqual(base.rootProducts, ["storefront:StorefrontKit"])
    }

    func testTrustingTheForkOrgDoesNotExcuseTheIdentitySwap() throws {
        var policy = DependencyPolicy.sample
        policy.trustedSources += ["github.com/example-labs"]
        let report = try sampleReport(policy)
        // SOURCE_MOVED does not depend on trust: a changed repository blocks.
        XCTAssertEqual(report.count(.block), 1)

        policy.trustedSources += ["github.com/example-forks"]
        XCTAssertEqual(try sampleReport(policy).count(.block), 1,
                       "Trusting the fork's org must not excuse the identity swap")
    }

    func testBlockRevisionPinsEscalates() throws {
        var policy = DependencyPolicy.sample
        policy.blockRevisionPins = true
        let report = try sampleReport(policy)
        XCTAssertEqual(report.count(.block), 3)
        XCTAssertEqual(report.count(.review), 3)
    }

    func testAllowListedRevisionPinIsSilent() throws {
        var policy = DependencyPolicy.sample
        policy.revisionPinAllowList = ["swift-log"]
        let report = try sampleReport(policy)
        XCTAssertFalse(report.findings.contains { $0.rule == .revisionPin })
        XCTAssertTrue(report.findings.contains { $0.rule == .sourceMoved })
    }

    func testIdenticalSBOMsPass() throws {
        let report = try SBOMGate.evaluate(base: SampleSBOMs.base, head: SampleSBOMs.base, policy: .sample)
        XCTAssertEqual(report.verdict, .pass)
        XCTAssertTrue(report.findings.isEmpty)
    }

    func testDeterministic() throws {
        XCTAssertEqual(try sampleReport(), try sampleReport())
    }

    func testJSONRoundTripGivesTheSameReport() throws {
        let fromJSON = try SBOMGate.evaluate(baseJSON: SampleSBOMs.baseJSON, headJSON: SampleSBOMs.headJSON, policy: .sample)
        XCTAssertEqual(fromJSON, try sampleReport())
        XCTAssertTrue(SampleSBOMs.headJSON.contains("\"bom-ref\""))
    }
}
