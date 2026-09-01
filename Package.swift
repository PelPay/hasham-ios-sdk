// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "HashamMobileSDK",
    platforms: [.iOS(.v16)],
    products: [
        .library(name: "HashamMobileSDK", targets: ["HashamMobileSDK"]),
    ],
    targets: [
        .target(
            name: "HashamMobileSDK",
            path: "Sources/HashamMobileSDK",
            linkerSettings: [
                .linkedFramework("Security"),
                .linkedFramework("DeviceCheck"),
            ]
        ),
    ]
)
