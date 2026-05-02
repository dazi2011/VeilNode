import AppKit
import SwiftUI
import UniformTypeIdentifiers

struct DashboardView: View {
  @Environment(CommandLog.self) private var log

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      Text("VeilNode — offline envelope encryption for ordinary carrier files.")
        .font(.title2)
        .fontWeight(.semibold)
      HStack {
        ActionButton(title: "Run Doctor", systemImage: "stethoscope") {
          log.showDoctorStatus()
        }
        ActionButton(title: "Test Vectors", systemImage: "checkmark.seal") {
          log.showTestVectorStatus()
        }
      }
      ConsoleView(text: log.output, isRunning: log.isRunning)
    }
    .padding()
  }
}

struct SealView: View {
  @Environment(CommandLog.self) private var log
  @State private var inputs: [URL] = []
  @State private var carrier: URL?
  @State private var outputDirectory: URL?
  @State private var rootKeypart: URL?
  @State private var recipient = ""
  @State private var messagePassword = ""
  @State private var rootKeypartPassword = ""
  @State private var useRootKeypart = true
  @State private var lowSignature = true
  @State private var adaptivePolicy = true
  @State private var signatureProfile = "balanced"
  @State private var policyCandidates = "20"
  @State private var policyModel: URL?
  @State private var policyOutputPath = ""

  var body: some View {
    Form {
      Picker("Mode", selection: $useRootKeypart) {
        Text("Root keypart v2").tag(true)
        Text("External keypart v1").tag(false)
      }
      .pickerStyle(.segmented)
      Toggle("Crypto core 2.2 low-signature", isOn: $lowSignature)
      Toggle("Adaptive envelope policy", isOn: $adaptivePolicy)
      Picker("Signature profile", selection: $signatureProfile) {
        Text("Conservative").tag("conservative")
        Text("Balanced").tag("balanced")
        Text("Aggressive").tag("aggressive")
      }
      .pickerStyle(.segmented)
      TextField("Policy candidates", text: $policyCandidates)
      FileSelectionRow(title: "Inputs", systemImage: "doc.badge.plus", value: inputSummary) {
        inputs = FileDialogs.pickInputs()
      }
      FileSelectionRow(title: "Cover", systemImage: "doc.richtext", value: carrier?.path ?? "Choose a carrier file") {
        carrier = FileDialogs.pickFile()
      }
      FileSelectionRow(title: "Output Folder", systemImage: "folder", value: outputDirectory?.path ?? "Choose an output folder") {
        outputDirectory = FileDialogs.pickDirectory()
      }
      if useRootKeypart {
        FileSelectionRow(title: "Root Keypart", systemImage: "key", value: rootKeypart?.path ?? "Choose .vkpseed") {
          rootKeypart = FileDialogs.pickFile(allowedExtensions: ["vkpseed", "txt"])
        }
        SecureField("Root keypart password", text: $rootKeypartPassword)
      }
      FileSelectionRow(title: "Policy Model", systemImage: "brain", value: policyModel?.path ?? "Optional model.json") {
        policyModel = FileDialogs.pickFile(allowedExtensions: ["json"])
      }
      TextField("Policy output path", text: $policyOutputPath)
      TextField("Recipient alias", text: $recipient)
      SecureField("Message password", text: $messagePassword)
      Button {
        Task { await log.runBatch(sealCommands) }
      } label: {
        Label("Seal Selected", systemImage: "lock.doc")
      }
      .disabled(sealCommands.isEmpty || log.isRunning)
      ConsoleView(text: log.output, isRunning: log.isRunning)
    }
    .padding()
  }

  private var inputSummary: String {
    inputs.isEmpty ? "Choose one or more files/folders" : "\(inputs.count) selected"
  }

  private var sealCommands: [[String]] {
    guard let carrier, let outputDirectory, !inputs.isEmpty, !recipient.isEmpty else { return [] }
    if useRootKeypart && rootKeypart == nil { return [] }
    let ext = carrier.pathExtension.isEmpty ? "vmsg" : carrier.pathExtension
    return inputs.enumerated().map { index, input in
      let suffix = inputs.count > 1 ? "-\(index + 1)" : ""
      let base = input.deletingPathExtension().lastPathComponent
      let output = outputDirectory.appendingPathComponent("\(base)\(suffix).sealed.\(ext)")
      var args = ["seal", input.path, carrier.path, output.path, "--to", recipient, "--password", messagePassword]
      if useRootKeypart, let rootKeypart {
        args += ["--root-keypart", rootKeypart.path, "--root-keypart-password", rootKeypartPassword, "--crypto-core", "2.2"]
        if lowSignature {
          args += ["--low-signature", "--signature-profile", signatureProfile]
        }
        if adaptivePolicy {
          args += ["--adaptive-policy", "--policy-candidates", policyCandidates.isEmpty ? "20" : policyCandidates]
        }
        if let policyModel {
          args += ["--policy-model", policyModel.path]
        }
        if !policyOutputPath.isEmpty {
          args += ["--policy-out", policyOutputPath]
        }
      }
      return args
    }
  }
}

struct RootsView: View {
  @Environment(CommandLog.self) private var log
  @State private var rootPath: URL?
  @State private var outputPath = ""
  @State private var password = ""

  var body: some View {
    Form {
      FileSelectionRow(title: "Root Keypart", systemImage: "key", value: rootPath?.path ?? "Choose .vkpseed") {
        rootPath = FileDialogs.pickFile(allowedExtensions: ["vkpseed", "txt"])
      }
      TextField("Output root path", text: $outputPath)
      SecureField("Root password", text: $password)
      HStack {
        Button { Task { await log.run(["keypart", "root", "inspect", "--in", rootPath?.path ?? ""]) } } label: { Label("Inspect", systemImage: "info.circle") }
        Button { Task { await log.run(["keypart", "root", "create", "--out", outputPath, "--password", password]) } } label: { Label("Create", systemImage: "plus.circle") }
        Button { Task { await log.run(["keypart", "root", "rotate", "--in", rootPath?.path ?? "", "--out", outputPath, "--password", password]) } } label: { Label("Rotate", systemImage: "arrow.triangle.2.circlepath") }
      }
      ConsoleView(text: log.output, isRunning: log.isRunning)
    }
    .padding()
  }
}

struct CarrierView: View {
  @Environment(CommandLog.self) private var log
  @State private var before: URL?
  @State private var after: URL?

  var body: some View {
    Form {
      FileSelectionRow(title: "Before", systemImage: "doc", value: before?.path ?? "Choose original carrier") {
        before = FileDialogs.pickFile()
      }
      FileSelectionRow(title: "After", systemImage: "doc.fill", value: after?.path ?? "Choose output carrier") {
        after = FileDialogs.pickFile()
      }
      HStack {
        Button { Task { await log.run(["carrier", "audit", "--input", after?.path ?? "", "--json"]) } } label: { Label("Audit", systemImage: "checklist") }
        Button { Task { await log.run(["carrier", "compare", "--before", before?.path ?? "", "--after", after?.path ?? "", "--json"]) } } label: { Label("Compare", systemImage: "arrow.left.arrow.right") }
      }
      ConsoleView(text: log.output, isRunning: log.isRunning)
    }
    .padding()
  }
}

struct StrategyView: View {
  @Environment(CommandLog.self) private var log
  @State private var carrier: URL?
  @State private var payload: URL?
  @State private var before: URL?
  @State private var after: URL?
  @State private var policy: URL?
  @State private var model: URL?
  @State private var count = "20"

  var body: some View {
    Form {
      FileSelectionRow(title: "Carrier", systemImage: "doc.richtext", value: carrier?.path ?? "Choose carrier") { carrier = FileDialogs.pickFile() }
      FileSelectionRow(title: "Payload", systemImage: "doc.badge.plus", value: payload?.path ?? "Choose payload") { payload = FileDialogs.pickFile() }
      FileSelectionRow(title: "Before", systemImage: "doc", value: before?.path ?? "Choose before") { before = FileDialogs.pickFile() }
      FileSelectionRow(title: "After", systemImage: "doc.fill", value: after?.path ?? "Choose after") { after = FileDialogs.pickFile() }
      FileSelectionRow(title: "Policy", systemImage: "slider.horizontal.3", value: policy?.path ?? "Choose selected.policy.json") { policy = FileDialogs.pickFile(allowedExtensions: ["json"]) }
      FileSelectionRow(title: "Model", systemImage: "brain", value: model?.path ?? "Choose model.json") { model = FileDialogs.pickFile(allowedExtensions: ["json"]) }
      TextField("Candidates", text: $count)
      HStack {
        Button { Task { await log.run(["strategy", "features", "--carrier", carrier?.path ?? "", "--payload", payload?.path ?? "", "--json"]) } } label: { Label("Features", systemImage: "list.bullet.rectangle") }
        Button { Task { await log.run(["strategy", "generate", "--carrier", carrier?.path ?? "", "--payload", payload?.path ?? "", "--count", count, "--json"]) } } label: { Label("Generate", systemImage: "shuffle") }
        Button { Task { await log.run(["strategy", "select", "--carrier", carrier?.path ?? "", "--payload", payload?.path ?? "", "--count", count, "--json"]) } } label: { Label("Select", systemImage: "checkmark.circle") }
      }
      HStack {
        Button { Task { await log.run(["strategy", "score", "--before", before?.path ?? "", "--after", after?.path ?? "", "--policy", policy?.path ?? "", "--json"]) } } label: { Label("Score", systemImage: "gauge.medium") }
        Button { Task { await log.run(["strategy", "scan-signature", "--input", after?.path ?? "", "--json"]) } } label: { Label("Scan", systemImage: "magnifyingglass") }
        Button { Task { await log.run(["strategy", "model", "inspect", "--in", model?.path ?? ""]) } } label: { Label("Model", systemImage: "brain") }
      }
      ConsoleView(text: log.output, isRunning: log.isRunning)
    }
    .padding()
  }
}

struct OpenView: View {
  @Environment(CommandLog.self) private var log
  @State private var messages: [URL] = []
  @State private var keypart: URL?
  @State private var rootKeypart: URL?
  @State private var outputDirectory: URL?
  @State private var useRootKeypart = true
  @State private var messagePassword = ""
  @State private var identityPassword = ""
  @State private var rootKeypartPassword = ""

  var body: some View {
    Form {
      Picker("Mode", selection: $useRootKeypart) {
        Text("Root keypart v2").tag(true)
        Text("External keypart v1").tag(false)
      }
      .pickerStyle(.segmented)
      FileSelectionRow(title: "Messages", systemImage: "tray.and.arrow.down", value: messageSummary) {
        messages = FileDialogs.pickFiles()
      }
      FileSelectionRow(title: "Output Folder", systemImage: "folder", value: outputDirectory?.path ?? "Choose an output folder") {
        outputDirectory = FileDialogs.pickDirectory()
      }
      if useRootKeypart {
        FileSelectionRow(title: "Root Keypart", systemImage: "key", value: rootKeypart?.path ?? "Choose .vkpseed") {
          rootKeypart = FileDialogs.pickFile(allowedExtensions: ["vkpseed", "txt"])
        }
        SecureField("Root keypart password", text: $rootKeypartPassword)
      } else {
        FileSelectionRow(title: "Keypart", systemImage: "key.horizontal", value: keypart?.path ?? "Choose .vkp, or leave empty to use message.vkp") {
          keypart = FileDialogs.pickFile(allowedExtensions: ["vkp"])
        }
      }
      SecureField("Message password", text: $messagePassword)
      SecureField("Identity password", text: $identityPassword)
      HStack {
        Button {
          Task { await log.runBatch(openCommands(verifyOnly: true)) }
        } label: {
          Label("Verify Only", systemImage: "checkmark.shield")
        }
        .disabled(openCommands(verifyOnly: true).isEmpty || log.isRunning)
        Button {
          Task { await log.runBatch(openCommands(verifyOnly: false)) }
        } label: {
          Label("Open Selected", systemImage: "lock.open")
        }
        .disabled(openCommands(verifyOnly: false).isEmpty || log.isRunning)
      }
      ConsoleView(text: log.output, isRunning: log.isRunning)
    }
    .padding()
  }

  private var messageSummary: String {
    messages.isEmpty ? "Choose one or more messages" : "\(messages.count) selected"
  }

  private func openCommands(verifyOnly: Bool) -> [[String]] {
    guard let outputDirectory, !messages.isEmpty else { return [] }
    if useRootKeypart && rootKeypart == nil { return [] }
    return messages.enumerated().map { index, message in
      let suffix = messages.count > 1 ? "-\(index + 1)" : ""
      let base = message.deletingPathExtension().lastPathComponent
      let output = outputDirectory.appendingPathComponent("\(base)\(suffix)-opened", isDirectory: true)
      var args = ["open", message.path, "--out", output.path, "--password", messagePassword, "--identity-password", identityPassword]
      if useRootKeypart, let rootKeypart {
        args += ["--root-keypart", rootKeypart.path, "--root-keypart-password", rootKeypartPassword]
      } else {
        let selectedKeypart = keypart ?? message.deletingPathExtension().appendingPathExtension("vkp")
        args += ["--keypart", selectedKeypart.path]
      }
      if verifyOnly {
        args.append("--verify-only")
      }
      return args
    }
  }
}

struct ContactsView: View {
  @Environment(CommandLog.self) private var log
  @State private var identityURL: URL?
  @State private var alias = ""

  var body: some View {
    Form {
      FileSelectionRow(title: "Identity", systemImage: "person.text.rectangle", value: identityURL?.path ?? "Choose .vid") {
        identityURL = FileDialogs.pickFile(allowedExtensions: ["vid", "json"])
      }
      TextField("Alias", text: $alias)
      HStack {
        Button {
          if let identityURL {
            Task { await log.run(["contact", "import", identityURL.path, "--alias", alias]) }
          }
        } label: {
          Label("Import", systemImage: "person.badge.plus")
        }
        .disabled(identityURL == nil || log.isRunning)
        Button {
          Task { await log.run(["contact", "list"]) }
        } label: {
          Label("List", systemImage: "list.bullet")
        }
      }
      ConsoleView(text: log.output, isRunning: log.isRunning)
    }
    .padding()
  }
}

struct FileSelectionRow: View {
  let title: String
  let systemImage: String
  let value: String
  let action: () -> Void

  var body: some View {
    VStack(alignment: .leading, spacing: 6) {
      Text(title)
        .font(.headline)
      HStack {
        Text(value)
          .lineLimit(2)
          .truncationMode(.middle)
          .foregroundStyle(.secondary)
          .frame(maxWidth: .infinity, alignment: .leading)
        Button(action: action) {
          Image(systemName: systemImage)
        }
        .help("Choose \(title.lowercased())")
      }
    }
  }
}

enum FileDialogs {
  @MainActor
  static func pickInputs() -> [URL] {
    let panel = NSOpenPanel()
    panel.allowsMultipleSelection = true
    panel.canChooseFiles = true
    panel.canChooseDirectories = true
    panel.canCreateDirectories = false
    return panel.runModal() == .OK ? panel.urls : []
  }

  @MainActor
  static func pickFiles() -> [URL] {
    let panel = NSOpenPanel()
    panel.allowsMultipleSelection = true
    panel.canChooseFiles = true
    panel.canChooseDirectories = false
    return panel.runModal() == .OK ? panel.urls : []
  }

  @MainActor
  static func pickFile(allowedExtensions: [String]? = nil) -> URL? {
    let panel = NSOpenPanel()
    panel.allowsMultipleSelection = false
    panel.canChooseFiles = true
    panel.canChooseDirectories = false
    if let allowedExtensions {
      panel.allowedContentTypes = allowedExtensions.compactMap { UTType(filenameExtension: $0) }
    }
    return panel.runModal() == .OK ? panel.url : nil
  }

  @MainActor
  static func pickDirectory() -> URL? {
    let panel = NSOpenPanel()
    panel.allowsMultipleSelection = false
    panel.canChooseFiles = false
    panel.canChooseDirectories = true
    panel.canCreateDirectories = true
    return panel.runModal() == .OK ? panel.url : nil
  }
}

struct SettingsView: View {
  @Environment(CommandLog.self) private var log

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      Text("Core")
        .font(.headline)
      Text("All cryptographic operations are delegated to the shared veil-core package.")
        .foregroundStyle(.secondary)
      Text("Root lifecycle, Shamir backup, replay seen database, carrier audit/compare/profile, migration, and debug-only switches are available through the shared CLI.")
        .foregroundStyle(.secondary)
      ActionButton(title: "Show Profiles", systemImage: "slider.horizontal.3") {
        await log.run(["profile", "levels"])
      }
      ConsoleView(text: log.output, isRunning: log.isRunning)
    }
    .padding()
  }
}

struct ActionButton: View {
  let title: String
  let systemImage: String
  let action: () async -> Void

  var body: some View {
    Button {
      Task { await action() }
    } label: {
      Label(title, systemImage: systemImage)
    }
    .buttonStyle(.borderedProminent)
  }
}

struct ConsoleView: View {
  let text: String
  let isRunning: Bool

  var body: some View {
    VStack(alignment: .leading) {
      HStack {
        Text("Output")
          .font(.headline)
        if isRunning {
          ProgressView()
            .controlSize(.small)
        }
      }
      ScrollView {
        Text(text)
          .font(.system(.body, design: .monospaced))
          .frame(maxWidth: .infinity, alignment: .leading)
          .textSelection(.enabled)
          .padding(10)
      }
      .background(.quaternary)
      .clipShape(RoundedRectangle(cornerRadius: 8))
    }
  }
}

#Preview {
  AppView()
}
