#if canImport(SwiftUI)
import SwiftUI

/// The sample PR, gated. Flip the policy toggles and watch the verdict move:
/// the policy is data, so loosening it is a visible decision, not a vibe.
public struct SBOMGateDemoView: View {

    @State private var trustForks = false
    @State private var blockRevisionPins = false

    public init() {}

    private var policy: DependencyPolicy {
        var p = DependencyPolicy.sample
        if trustForks {
            p.trustedSources += ["github.com/example-forks", "github.com/example-labs"]
        }
        p.blockRevisionPins = blockRevisionPins
        return p
    }

    private var report: GateReport? {
        try? SBOMGate.evaluate(base: SampleSBOMs.base, head: SampleSBOMs.head, policy: policy)
    }

    private var lockfileChanges: Int {
        ResolvedFile.changedIdentities(base: SampleSBOMs.baseResolved, head: SampleSBOMs.headResolved).count
    }

    public var body: some View {
        NavigationStack {
            List {
                if let report {
                    Section {
                        verdictHeader(report)
                    }
                    Section("Policy") {
                        Toggle("Trust example-forks & example-labs", isOn: $trustForks)
                        Toggle("Block revision pins", isOn: $blockRevisionPins)
                    }
                    Section("Findings (\(report.findings.count))") {
                        ForEach(report.findings) { finding in
                            FindingRow(finding: finding)
                        }
                    }
                    Section {
                        Text("Package.resolved for the same PR changes \(lockfileChanges) pins. The gate touches \(report.packagesTouched.count) packages; the extra one changed no pin at all.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                } else {
                    Text("The sample SBOMs could not be compared.")
                }
            }
            .navigationTitle("SBOM Gate")
        }
    }

    @ViewBuilder
    private func verdictHeader(_ report: GateReport) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("PR: “Retry image loads on flaky networks”")
                .font(.subheadline)
                .foregroundStyle(.secondary)
            Text(verdictText(report.verdict))
                .font(.title2.weight(.bold))
                .foregroundStyle(verdictColor(report.verdict))
            HStack(spacing: 12) {
                countChip("BLOCK", report.count(.block), .red)
                countChip("REVIEW", report.count(.review), .orange)
                countChip("INFO", report.count(.info), .gray)
            }
        }
        .padding(.vertical, 4)
    }

    private func countChip(_ label: String, _ count: Int, _ color: Color) -> some View {
        Text("\(label) \(count)")
            .font(.caption.weight(.semibold).monospacedDigit())
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(color.opacity(0.15), in: Capsule())
            .foregroundStyle(color)
    }

    private func verdictText(_ v: GateReport.Verdict) -> String {
        switch v {
        case .pass: return "Pass"
        case .needsReview: return "Needs dependency-owner review"
        case .blocked: return "Blocked"
        }
    }

    private func verdictColor(_ v: GateReport.Verdict) -> Color {
        switch v {
        case .pass: return .green
        case .needsReview: return .orange
        case .blocked: return .red
        }
    }
}

private struct FindingRow: View {
    let finding: Finding

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(finding.severity.label)
                    .font(.caption2.weight(.bold))
                    .foregroundStyle(color)
                Text(finding.rule.rawValue)
                    .font(.caption.monospaced())
                Spacer()
                Text(finding.package)
                    .font(.caption.weight(.semibold))
            }
            Text(finding.message)
                .font(.footnote)
            if let path = finding.path {
                Text(path.joined(separator: " → "))
                    .font(.caption2.monospaced())
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 2)
    }

    private var color: Color {
        switch finding.severity {
        case .block: return .red
        case .review: return .orange
        case .info: return .gray
        }
    }
}

#Preview {
    SBOMGateDemoView()
}
#endif
