import Foundation

/// The subset of a CycloneDX 1.7 JSON document that SwiftPM 6.4 emits
/// (`swift build --sbom-spec cyclonedx` / `swift package generate-sbom`,
/// SE-0509). Only fields the gate reads are modelled; everything else in the
/// file is ignored by `JSONDecoder`, so a richer document still decodes.
public struct CycloneDXDocument: Codable, Equatable, Sendable {
    public var bomFormat: String?
    public var specVersion: String
    public var serialNumber: String?
    public var version: Int?
    public var metadata: Metadata?
    public var components: [Component]
    public var dependencies: [Dependency]

    public init(
        bomFormat: String? = "CycloneDX",
        specVersion: String,
        serialNumber: String? = nil,
        version: Int? = 1,
        metadata: Metadata?,
        components: [Component],
        dependencies: [Dependency]
    ) {
        self.bomFormat = bomFormat
        self.specVersion = specVersion
        self.serialNumber = serialNumber
        self.version = version
        self.metadata = metadata
        self.components = components
        self.dependencies = dependencies
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        bomFormat = try c.decodeIfPresent(String.self, forKey: .bomFormat)
        specVersion = try c.decode(String.self, forKey: .specVersion)
        serialNumber = try c.decodeIfPresent(String.self, forKey: .serialNumber)
        version = try c.decodeIfPresent(Int.self, forKey: .version)
        metadata = try c.decodeIfPresent(Metadata.self, forKey: .metadata)
        // A document with no dependencies (a leaf package) omits these arrays.
        components = try c.decodeIfPresent([Component].self, forKey: .components) ?? []
        dependencies = try c.decodeIfPresent([Dependency].self, forKey: .dependencies) ?? []
    }

    public static func decode(_ data: Data) throws -> CycloneDXDocument {
        try JSONDecoder().decode(CycloneDXDocument.self, from: data)
    }

    public static func decode(_ json: String) throws -> CycloneDXDocument {
        try decode(Data(json.utf8))
    }

    public struct Metadata: Codable, Equatable, Sendable {
        public var timestamp: String?
        public var tools: Tools?
        public var component: Component?

        public init(timestamp: String? = nil, tools: Tools? = nil, component: Component?) {
            self.timestamp = timestamp
            self.tools = tools
            self.component = component
        }
    }

    public struct Tools: Codable, Equatable, Sendable {
        public var components: [Component]?
        public init(components: [Component]?) { self.components = components }
    }

    public struct Component: Codable, Equatable, Sendable {
        public var bomRef: String
        public var name: String
        public var version: String?
        public var purl: String?
        public var scope: String?
        public var type: String?
        public var pedigree: Pedigree?
        public var properties: [Property]?

        enum CodingKeys: String, CodingKey {
            case bomRef = "bom-ref"
            case name, version, purl, scope, type, pedigree, properties
        }

        public init(
            bomRef: String,
            name: String,
            version: String?,
            purl: String?,
            scope: String? = "required",
            type: String? = "library",
            pedigree: Pedigree? = nil,
            properties: [Property]? = nil
        ) {
            self.bomRef = bomRef
            self.name = name
            self.version = version
            self.purl = purl
            self.scope = scope
            self.type = type
            self.pedigree = pedigree
            self.properties = properties
        }

        /// `swift-package` or `swift-product`, from the `swift-entity` property.
        public var swiftEntity: String? {
            properties?.first(where: { $0.name == "swift-entity" })?.value
        }

        /// The first pedigree commit URL, which SwiftPM fills with the
        /// repository the package was fetched from.
        public var sourceURL: String? {
            pedigree?.commits?.first?.url
        }
    }

    public struct Pedigree: Codable, Equatable, Sendable {
        public var commits: [Commit]?
        public init(commits: [Commit]?) { self.commits = commits }
    }

    public struct Commit: Codable, Equatable, Sendable {
        public var uid: String?
        public var url: String?
        public init(uid: String?, url: String?) {
            self.uid = uid
            self.url = url
        }
    }

    public struct Property: Codable, Equatable, Sendable {
        public var name: String
        public var value: String
        public init(name: String, value: String) {
            self.name = name
            self.value = value
        }
    }

    public struct Dependency: Codable, Equatable, Sendable {
        public var ref: String
        public var dependsOn: [String]

        public init(ref: String, dependsOn: [String]) {
            self.ref = ref
            self.dependsOn = dependsOn
        }

        public init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            ref = try c.decode(String.self, forKey: .ref)
            dependsOn = try c.decodeIfPresent([String].self, forKey: .dependsOn) ?? []
        }
    }
}
