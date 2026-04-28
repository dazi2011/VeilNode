import SwiftUI

@main
struct VeilNodeiOSApp: App {
  var body: some Scene {
    WindowGroup {
      MobileRootView()
    }
  }
}

enum MobileTab: String, CaseIterable, Identifiable {
  case inbox, seal, contacts, settings
  var id: String { rawValue }
}

struct MobileRootView: View {
  @State private var selectedTab: MobileTab = .inbox

  var body: some View {
    TabView(selection: $selectedTab) {
      NavigationStack { InboxView() }
        .tabItem { Label("Inbox", systemImage: "tray") }
        .tag(MobileTab.inbox)
      NavigationStack { MobileSealView() }
        .tabItem { Label("Seal", systemImage: "lock.doc") }
        .tag(MobileTab.seal)
      NavigationStack { MobileContactsView() }
        .tabItem { Label("Contacts", systemImage: "person.2") }
        .tag(MobileTab.contacts)
      NavigationStack { MobileSettingsView() }
        .tabItem { Label("Settings", systemImage: "gearshape") }
        .tag(MobileTab.settings)
    }
  }
}

struct InboxView: View {
  var body: some View {
    List {
      Label("Import .vpkg or .vmsg from Files / Share Sheet", systemImage: "square.and.arrow.down")
      Label("Verify before opening", systemImage: "checkmark.shield")
    }
    .navigationTitle("VeilNode")
  }
}

struct MobileSealView: View {
  var body: some View {
    List {
      Label("Small-file seal workflow", systemImage: "lock.doc")
      Label("Import carrier and payload from Files", systemImage: "folder")
    }
    .navigationTitle("Seal")
  }
}

struct MobileContactsView: View {
  var body: some View {
    List {
      Label("Import .vid contact", systemImage: "person.badge.plus")
      Label("Import .vpkg node package", systemImage: "shippingbox")
    }
    .navigationTitle("Contacts")
  }
}

struct MobileSettingsView: View {
  var body: some View {
    List {
      Label("Keychain SecureStore adapter", systemImage: "key")
      Label("Secure Enclave DeviceBinding adapter", systemImage: "touchid")
    }
    .navigationTitle("Settings")
  }
}

#Preview {
  MobileRootView()
}
