import SwiftUI
import SBOMGate

/// Runnable host for `SBOMGateDemoView`.
///
/// Everything interesting lives in the `SBOMGate` package in this same repo;
/// this target exists so you can clone one repo, open `Demo.xcodeproj`, hit
/// Run, and flip the policy toggles.
@main
struct DemoApp: App {
    var body: some Scene {
        WindowGroup {
            SBOMGateDemoView()
        }
    }
}
