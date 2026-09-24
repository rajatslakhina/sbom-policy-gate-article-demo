import Foundation

/// A SwiftPM SBOM read as a graph of packages and products.
///
/// SE-0509 shapes the `dependencies` section as: the root package depends on
/// packages and on its own products, a package depends on the products it
/// vends, and a product depends on products from *other* packages. The
/// product-to-product edges are the ones that answer "does this code ship
/// inside something I build", which is exactly what `Package.resolved`
/// cannot tell you.
public struct SBOMGraph: Sendable {
    public struct Package: Equatable, Sendable {
        public let identity: String
        public let name: String
        public let version: PackageVersion?
        public let source: PackageSource?
        public let rawVersion: String?
    }

    public let specVersion: String
    public let toolVersion: String?
    public let rootIdentity: String?
    public let rootVersion: PackageVersion?
    public let packages: [String: Package]
    public let productRefs: Set<String>
    /// Products whose component has `scope: "test"` (SE-0509: all of the
    /// product's modules are test modules). They never count as shipping.
    public let testProductRefs: Set<String>
    public let edges: [String: [String]]

    public init(_ doc: CycloneDXDocument) {
        specVersion = doc.specVersion
        toolVersion = doc.metadata?.tools?.components?
            .first(where: { $0.name == "swift-package-manager" })?.version
        let root = doc.metadata?.component
        rootIdentity = root?.bomRef
        rootVersion = root?.version.map(PackageVersion.init)

        var packages: [String: Package] = [:]
        var products: Set<String> = []
        var testProducts: Set<String> = []
        for component in doc.components {
            if SBOMGraph.isProductRef(component) {
                products.insert(component.bomRef)
                if component.scope == "test" { testProducts.insert(component.bomRef) }
                continue
            }
            packages[component.bomRef] = Package(
                identity: component.bomRef,
                name: component.name,
                version: component.version.map(PackageVersion.init),
                source: PackageSource(purl: component.purl, repositoryURL: component.sourceURL),
                rawVersion: component.version
            )
        }
        self.packages = packages
        self.productRefs = products
        self.testProductRefs = testProducts

        var edges: [String: [String]] = [:]
        for dep in doc.dependencies {
            edges[dep.ref, default: []].append(contentsOf: dep.dependsOn)
        }
        self.edges = edges
    }

    static func isProductRef(_ c: CycloneDXDocument.Component) -> Bool {
        if let entity = c.swiftEntity { return entity == "swift-product" }
        return c.bomRef.contains(":")
    }

    /// `"swift-crypto:Crypto"` → `"swift-crypto"`.
    public static func packageIdentity(ofProduct ref: String) -> String {
        guard let colon = ref.firstIndex(of: ":") else { return ref }
        return String(ref[..<colon])
    }

    /// Products that don't belong to the root package.
    public var dependencyProductRefs: Set<String> {
        guard let root = rootIdentity else { return productRefs }
        return productRefs.filter { SBOMGraph.packageIdentity(ofProduct: $0) != root }
    }

    /// The root package's own shipping products, sorted for deterministic
    /// output. A root test product (`scope: "test"`, e.g. `<Name>PackageTests`)
    /// is excluded: a test helper reached only from tests doesn't ship.
    /// A root product named only in `dependencies`, with no component and so
    /// no scope, is assumed to ship.
    public var rootProducts: [String] {
        rootProductsIncludingTests.filter { !testProductRefs.contains($0) }
    }

    var rootProductsIncludingTests: [String] {
        guard let root = rootIdentity else { return [] }
        var refs = Set(productRefs.filter { SBOMGraph.packageIdentity(ofProduct: $0) == root })
        // Products the root lists as dependencies but that were not emitted as
        // components still count as the root's own products.
        for ref in edges[root] ?? [] where ref.contains(":")
            && SBOMGraph.packageIdentity(ofProduct: ref) == root {
            refs.insert(ref)
        }
        return refs.sorted()
    }

    /// The shortest product-to-product path from one of the root's products
    /// to any product of `packageIdentity`, or `nil` if the package is only
    /// present in the package graph and no product the root builds links it.
    public func shippingPath(to packageIdentity: String) -> [String]? {
        let starts = rootProducts
        var queue: [[String]] = starts.map { [$0] }
        var seen = Set(starts)
        var index = 0
        while index < queue.count {
            let path = queue[index]
            index += 1
            guard let last = path.last else { continue }
            if SBOMGraph.packageIdentity(ofProduct: last) == packageIdentity {
                return path
            }
            for next in (edges[last] ?? []).sorted() where next.contains(":") && !seen.contains(next) {
                seen.insert(next)
                queue.append(path + [next])
            }
        }
        return nil
    }
}
