import SwiftUI
import CryptoKit
import UniformTypeIdentifiers

@main
struct VeilNodeiOSApp: App {
  var body: some Scene {
    WindowGroup {
      RootView()
    }
  }
}

private enum AppTab: String, CaseIterable, Identifiable {
  case overview
  case inspect
  case commands
  case about

  var id: String { rawValue }

  var label: String {
    switch self {
    case .overview: return "Overview"
    case .inspect: return "Inspect"
    case .commands: return "Commands"
    case .about: return "About"
    }
  }

  var systemImage: String {
    switch self {
    case .overview: return "shield.lefthalf.filled"
    case .inspect: return "doc.text.magnifyingglass"
    case .commands: return "terminal"
    case .about: return "info.circle"
    }
  }
}

private struct RootView: View {
  @State private var selectedTab: AppTab = .overview

  var body: some View {
    TabView(selection: $selectedTab) {
      ForEach(AppTab.allCases) { tab in
        NavigationStack {
          switch tab {
          case .overview: OverviewView()
          case .inspect: InspectView()
          case .commands: CommandsView()
          case .about: AboutView()
          }
        }
        .tabItem { Label(tab.label, systemImage: tab.systemImage) }
        .tag(tab)
      }
    }
  }
}

private struct OverviewView: View {
  var body: some View {
    List {
      Section {
        VStack(alignment: .leading, spacing: 8) {
          Text("VeilNode")
            .font(.largeTitle)
            .fontWeight(.semibold)
          Text("Offline envelope encryption for ordinary carrier files.")
            .font(.subheadline)
            .foregroundStyle(.secondary)
        }
        .padding(.vertical, 4)
      }

      Section("Companion app") {
        Text("Sealing and opening run on your desktop CLI / GUI. This iOS / iPadOS companion does not ship a Python crypto core; it lets you receive carriers via Files or AirDrop, inspect them locally, and copy the right CLI commands to run on a desktop.")
          .font(.callout)
      }

      Section("Cryptographic boundary") {
        boundaryRow("root_vkp", "fixed by core")
        boundaryRow("HKDF / Argon2id / AEAD", "fixed by core")
        boundaryRow("msg_id, message_salt, file_hash", "fixed by core")
        boundaryRow("Adaptive policy layer", "envelope choices only")
      }

      Section("Use the desktop tools for") {
        Label("seal, open, verify", systemImage: "lock.doc")
        Label("identity, contact, root_vkp", systemImage: "person.text.rectangle")
        Label("strategy features / generate / select / score / scan", systemImage: "chart.line.uptrend.xyaxis")
        Label("carrier audit / compare / profile", systemImage: "doc.viewfinder")
      }
    }
    .navigationTitle("VeilNode")
    .listStyle(.insetGrouped)
  }

  private func boundaryRow(_ name: String, _ note: String) -> some View {
    HStack(alignment: .firstTextBaseline) {
      Text(name)
        .font(.system(.callout, design: .monospaced))
      Spacer()
      Text(note)
        .font(.caption)
        .foregroundStyle(.secondary)
    }
  }
}

private struct InspectView: View {
  @State private var importing = false
  @State private var report: InspectReport?
  @State private var error: String?

  var body: some View {
    List {
      Section {
        Button {
          importing = true
        } label: {
          Label("Import a carrier or .vmsg / .vpkg", systemImage: "square.and.arrow.down")
        }
        Text("Pick a file from Files, iCloud Drive or AirDrop. The companion app reports size and SHA-256 so you can confirm it matches the desktop output. It does not decrypt.")
          .font(.footnote)
          .foregroundStyle(.secondary)
      }

      if let report {
        Section("File") {
          DetailRow(name: "Name", value: report.name)
          DetailRow(name: "Size", value: report.sizeText)
          DetailRow(name: "SHA-256", value: report.sha256, monospaced: true)
        }
        Section {
          Button {
            UIPasteboard.general.string = report.sha256
          } label: {
            Label("Copy SHA-256", systemImage: "doc.on.doc")
          }
        }
      }

      if let error {
        Section("Error") {
          Text(error)
            .foregroundStyle(.red)
        }
      }
    }
    .listStyle(.insetGrouped)
    .navigationTitle("Inspect")
    .fileImporter(
      isPresented: $importing,
      allowedContentTypes: [.data],
      allowsMultipleSelection: false
    ) { result in
      switch result {
      case .success(let urls):
        if let url = urls.first {
          inspect(url)
        }
      case .failure(let err):
        self.error = err.localizedDescription
      }
    }
  }

  private func inspect(_ url: URL) {
    let didStartScope = url.startAccessingSecurityScopedResource()
    defer { if didStartScope { url.stopAccessingSecurityScopedResource() } }
    do {
      let data = try Data(contentsOf: url)
      var hasher = SHA256()
      hasher.update(data: data)
      let digest = hasher.finalize()
      let hex = digest.map { String(format: "%02x", $0) }.joined()
      report = InspectReport(name: url.lastPathComponent, size: data.count, sha256: hex)
      error = nil
    } catch {
      self.error = error.localizedDescription
      self.report = nil
    }
  }
}

private struct InspectReport {
  let name: String
  let size: Int
  let sha256: String

  var sizeText: String {
    ByteCountFormatter.string(fromByteCount: Int64(size), countStyle: .file)
  }
}

private struct DetailRow: View {
  let name: String
  let value: String
  var monospaced: Bool = false

  var body: some View {
    VStack(alignment: .leading, spacing: 4) {
      Text(name)
        .font(.caption)
        .foregroundStyle(.secondary)
      Text(value)
        .font(.system(.callout, design: monospaced ? .monospaced : .default))
        .textSelection(.enabled)
    }
  }
}

private struct CommandSnippet: Identifiable {
  let id = UUID()
  let title: String
  let command: String
  let note: String
}

private struct CommandsView: View {
  private let snippets: [CommandSnippet] = [
    CommandSnippet(
      title: "Health check",
      command: "veil-node doctor",
      note: "Verifies the local install."
    ),
    CommandSnippet(
      title: "Create identity",
      command: "veil-node --home ~/.veil/alice identity create --name alice --password idpass",
      note: "Run once per device."
    ),
    CommandSnippet(
      title: "Create root keypart",
      command: "veil-node keypart root create --out ~/.veil/root.vkpseed --password rootpass --label alice-bob",
      note: "v2 root, used by both seal and open."
    ),
    CommandSnippet(
      title: "Adaptive seal",
      command: "veil-node --home ~/.veil/alice seal IN.bin COVER.zip OUT.zip --to alice --password msgpass --root-keypart ~/.veil/root.vkpseed --root-keypart-password rootpass --crypto-core 2.2 --low-signature --adaptive-policy --policy-candidates 20",
      note: "Lowest-risk policy chosen by local dry-run + verify + score."
    ),
    CommandSnippet(
      title: "Open",
      command: "veil-node --home ~/.veil/alice open OUT.zip --out ~/Desktop/recovered --password msgpass --identity-password idpass --root-keypart ~/.veil/root.vkpseed --root-keypart-password rootpass",
      note: "All open failures default to: Unable to open message."
    ),
  ]

  var body: some View {
    List {
      Section {
        Text("Run these on your desktop. Tap a card to copy the command.")
          .font(.callout)
          .foregroundStyle(.secondary)
      }
      ForEach(snippets) { snippet in
        Section(snippet.title) {
          Text(snippet.command)
            .font(.system(.footnote, design: .monospaced))
            .textSelection(.enabled)
          Text(snippet.note)
            .font(.caption)
            .foregroundStyle(.secondary)
          Button {
            UIPasteboard.general.string = snippet.command
          } label: {
            Label("Copy command", systemImage: "doc.on.doc")
          }
        }
      }
    }
    .listStyle(.insetGrouped)
    .navigationTitle("Commands")
  }
}

private struct AboutView: View {
  private var suiteVersion: String {
    Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0.3.2"
  }

  var body: some View {
    List {
      Section {
        VStack(alignment: .leading, spacing: 6) {
          Text("VeilNode Suite \(suiteVersion)")
            .font(.headline)
          Text("crypto_core_version = 2.2")
            .font(.system(.caption, design: .monospaced))
            .foregroundStyle(.secondary)
          Text("The crypto core marker is a message compatibility tag, not the suite package version.")
            .font(.caption)
            .foregroundStyle(.secondary)
        }
      }

      Section("Engineering language") {
        Text("VeilNode does not claim 'undetectable'. The project's terms are: low-signature, metadata minimization, carrier fidelity, local engineering risk score.")
          .font(.callout)
      }

      Section("Links") {
        Link("Project repository", destination: URL(string: "https://github.com/dazi2011/VeilNode")!)
        Link("Latest release", destination: URL(string: "https://github.com/dazi2011/VeilNode/releases/latest")!)
        Link("Technical notes", destination: URL(string: "https://github.com/dazi2011/VeilNode/blob/main/docs/TECHNICAL.md")!)
        Link("Platform matrix", destination: URL(string: "https://github.com/dazi2011/VeilNode/blob/main/docs/PLATFORMS.md")!)
      }

      Section("Out of scope on iOS / iPadOS") {
        Text("• On-device sealing or opening (no Python core).")
        Text("• Replay-seen database (lives next to the desktop home).")
        Text("• Root keypart creation or rotation.")
        Text("Use the desktop CLI / GUI for these.")
      }
    }
    .listStyle(.insetGrouped)
    .navigationTitle("About")
  }
}

#Preview {
  RootView()
}
