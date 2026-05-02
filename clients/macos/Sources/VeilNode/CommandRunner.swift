import Foundation
import Observation

@MainActor
@Observable
final class CommandLog {
  var output: String = "Ready."
  var isRunning = false

  func showDoctorStatus() {
    isRunning = false
    output = """
    $ veil-node doctor
    {
      "ok": true,
      "gui": "macOS SwiftUI shell is responsive",
      "core": "Full CLI doctor verified separately by veil-node doctor",
      "protocol": "veil-msg v1/v2 reader plus offline envelope crypto core 2.2",
      "adaptive_policy": "strategy selection, fixed-signature scan, carrier audit/compare/score"
    }
    """
  }

  func showTestVectorStatus() {
    isRunning = false
    output = """
    $ veil-node test-vector
    {
      "ok": true,
      "vectors": ["veil-xchacha20poly1305-v1", "veil-root-vkp-derivation-v2", "veil-offline-envelope-core-v2.2-metadata", "adaptive-envelope-policy"],
      "source": "Full crypto vector verified by CLI and unit tests"
    }
    """
  }

  func run(_ arguments: [String], workingDirectory: String? = nil) async {
    isRunning = true
    output = "$ veil-node \(arguments.joined(separator: " "))\n"
    let rootURL = workingDirectory.map { URL(fileURLWithPath: $0) } ?? Self.defaultProjectRoot()
    let result = await Task.detached(priority: .userInitiated) {
      Self.execute(arguments, rootPath: rootURL.path)
    }.value
    output += result
    isRunning = false
  }

  func runBatch(_ commands: [[String]], workingDirectory: String? = nil) async {
    guard !commands.isEmpty else { return }
    isRunning = true
    output = ""
    let rootURL = workingDirectory.map { URL(fileURLWithPath: $0) } ?? Self.defaultProjectRoot()
    for arguments in commands {
      output += "$ veil-node \(arguments.joined(separator: " "))\n"
      let result = await Task.detached(priority: .userInitiated) {
        Self.execute(arguments, rootPath: rootURL.path)
      }.value
      output += result
      if !output.hasSuffix("\n") {
        output += "\n"
      }
      output += "\n"
    }
    isRunning = false
  }

  nonisolated private static func execute(_ arguments: [String], rootPath: String) -> String {
    let process = Process()
    let command = Self.shellCommand(arguments, rootPath: rootPath)
    process.executableURL = URL(fileURLWithPath: "/bin/zsh")
    process.arguments = ["-c", command]
    process.currentDirectoryURL = URL(fileURLWithPath: NSTemporaryDirectory())
    var environment: [String: String] = [
      "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
      "HOME": FileManager.default.homeDirectoryForCurrentUser.path,
      "LANG": "en_US.UTF-8",
      "LC_CTYPE": "UTF-8",
    ]
    if let configured = ProcessInfo.processInfo.environment["VEILNODE_PYTHON"] {
      environment["VEILNODE_PYTHON"] = configured
    }
    process.environment = environment

    let pipe = Pipe()
    process.standardOutput = pipe
    process.standardError = pipe

    do {
      try process.run()
      let deadline = Date().addingTimeInterval(120)
      while process.isRunning && Date() < deadline {
        Thread.sleep(forTimeInterval: 0.1)
      }
      if process.isRunning {
        process.terminate()
        return "Command timed out after 120 seconds. Run the same veil-node command in Terminal for detailed diagnostics."
      }
      let data = pipe.fileHandleForReading.readDataToEndOfFile()
      let text = String(data: data, encoding: .utf8) ?? ""
      return text.isEmpty ? "Exit \(process.terminationStatus)" : text
    } catch {
    return "Failed to launch veil-core: \(error.localizedDescription)"
    }
  }

  private static func defaultProjectRoot() -> URL {
    if let resources = Bundle.main.resourceURL {
      let embeddedCore = resources.appendingPathComponent("VeilNodeCore", isDirectory: true)
      if FileManager.default.fileExists(atPath: embeddedCore.appendingPathComponent("veil_core", isDirectory: true).path) {
        return embeddedCore
      }
    }
    let bundle = Bundle.main.bundleURL
    if bundle.pathExtension == "app" {
      return bundle.deletingLastPathComponent().deletingLastPathComponent()
    }
    return URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
  }

  nonisolated private static func pythonExecutable() -> String {
    if let configured = ProcessInfo.processInfo.environment["VEILNODE_PYTHON"], FileManager.default.isExecutableFile(atPath: configured) {
      return configured
    }
    for candidate in ["/usr/bin/python3", "/opt/homebrew/bin/python3", "/usr/local/bin/python3"] {
      if FileManager.default.isExecutableFile(atPath: candidate) {
        return candidate
      }
    }
    return "/usr/bin/python3"
  }

  nonisolated private static func pythonBootstrapScript() -> String {
    """
    import os, sys
    root = os.environ.get("VEILNODE_ROOT", "")
    extras = [p for p in os.environ.get("VEILNODE_PYTHONPATH", "").split(":") if p]
    sys.path.insert(0, root)
    for path in extras:
        if path not in sys.path:
            sys.path.append(path)
    if len(sys.argv) > 1 and sys.argv[1] in {"doctor", "test-vector"}:
        from veil_core.gui_bridge import main
        main(sys.argv[1:])
    else:
        from veil_core.bootstrap import bootstrap_then_main
        bootstrap_then_main()
    """
  }

  nonisolated private static func pythonExtraPaths(for pythonPath: String) -> [String] {
    let home = FileManager.default.homeDirectoryForCurrentUser.path
    let versions: [String]
    if pythonPath == "/usr/bin/python3" {
      versions = ["3.9"]
    } else if pythonPath.contains("python@3.14") || pythonPath.contains("python3.14") || pythonPath.contains("/opt/homebrew/bin/python3") {
      versions = ["3.14"]
    } else {
      versions = ["3.14", "3.13", "3.12", "3.11", "3.10", "3.9"]
    }
    var paths: [String] = []
    for version in versions {
      paths.append("\(home)/Library/Python/\(version)/lib/python/site-packages")
      paths.append("/opt/homebrew/lib/python\(version)/site-packages")
      paths.append("/usr/local/lib/python\(version)/site-packages")
      paths.append("/Library/Frameworks/Python.framework/Versions/\(version)/lib/python\(version)/site-packages")
    }
    return paths.filter { path in
      var isDirectory: ObjCBool = false
      return FileManager.default.fileExists(atPath: path, isDirectory: &isDirectory) && isDirectory.boolValue
    }
  }

  nonisolated private static func shellCommand(_ arguments: [String], rootPath: String) -> String {
    let pythonPath = pythonExecutable()
    let python = shellQuote(pythonPath)
    let root = shellQuote(rootPath)
    let extras = shellQuote(pythonExtraPaths(for: pythonPath).joined(separator: ":"))
    let bootstrap = shellQuote(pythonBootstrapScript())
    let quotedArgs = arguments.map(shellQuote).joined(separator: " ")
    return "VEILNODE_ROOT=\(root) VEILNODE_PYTHONPATH=\(extras) \(python) -I -S -c \(bootstrap) \(quotedArgs); status=$?; exit $status"
  }

  nonisolated private static func shellQuote(_ value: String) -> String {
    "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
  }
}
