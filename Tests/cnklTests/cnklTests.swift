import XCTest
import class Foundation.Bundle

final class cnklTests: XCTestCase {
    func testExample() throws {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct
        // results.

        // Some of the APIs that we use below are available in macOS 10.13 and above.
        guard #available(macOS 10.13, *) else {
            return
        }

        // Mac Catalyst won't have `Process`, but it is supported for executables.
        #if !targetEnvironment(macCatalyst)

        let fooBinary = productsDirectory.appendingPathComponent("cnkl")

        let cnkl = "\(fooBinary.path).chunklist"
        try? FileManager.default.removeItem(atPath: cnkl)
        var process = Process()
        process.executableURL = fooBinary
        process.arguments = ["-g", fooBinary.path]

        try process.run()
        process.waitUntilExit()
        
        XCTAssert(process.terminationStatus == 0)
        XCTAssert(FileManager.default.fileExists(atPath: "\(fooBinary.path).chunklist"))
        process = Process()
        process.executableURL = fooBinary
        process.arguments = ["-c", "-l", cnkl, fooBinary.path]

        try process.run()
        process.waitUntilExit()
        XCTAssert(process.terminationStatus == 0)
        
        #endif
    }

    /// Returns path to the built products directory.
    var productsDirectory: URL {
      #if os(macOS)
        for bundle in Bundle.allBundles where bundle.bundlePath.hasSuffix(".xctest") {
            return bundle.bundleURL.deletingLastPathComponent()
        }
        fatalError("couldn't find the products directory")
      #else
        return Bundle.main.bundleURL
      #endif
    }
}
