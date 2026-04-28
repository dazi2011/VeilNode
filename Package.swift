// swift-tools-version: 6.0
import PackageDescription

let package = Package(
  name: "VeilNodeSuite",
  platforms: [
    .macOS(.v14)
  ],
  products: [
    .executable(name: "VeilNode", targets: ["VeilNode"])
  ],
  targets: [
    .executableTarget(
      name: "VeilNode",
      path: "clients/macos/Sources/VeilNode"
    )
  ]
)
