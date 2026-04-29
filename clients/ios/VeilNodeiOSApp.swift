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
  case inbox, seal, roots, carrier, contacts, settings
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
      NavigationStack { MobileRootsView() }
        .tabItem { Label("Roots", systemImage: "key") }
        .tag(MobileTab.roots)
      NavigationStack { MobileCarrierView() }
        .tabItem { Label("Carrier", systemImage: "doc.viewfinder") }
        .tag(MobileTab.carrier)
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
      Label("Open v1/v2/v2.2 with replay checks and generic failures", systemImage: "checkmark.shield")
    }
    .navigationTitle("VeilNode")
  }
}

struct MobileSealView: View {
  var body: some View {
    List {
      Label("Seal with crypto_core_version 2.2", systemImage: "lock.doc")
      Label("Low-signature profiles and optional decoy payloads", systemImage: "folder")
    }
    .navigationTitle("Seal")
  }
}

struct MobileRootsView: View {
  var body: some View {
    List {
      Label("Create / inspect / rotate root_vkp", systemImage: "key")
      Label("Retire / revoke / import root store", systemImage: "archivebox")
      Label("Split and recover Shamir backups", systemImage: "square.stack.3d.up")
    }
    .navigationTitle("Roots")
  }
}

struct MobileCarrierView: View {
  var body: some View {
    List {
      Label("Carrier audit and compare", systemImage: "doc.viewfinder")
      Label("Carrier mimic profile create / inspect", systemImage: "chart.bar")
    }
    .navigationTitle("Carrier")
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
      Label("Offline-only shared core command surface", systemImage: "key")
      Label("No Linux/NAS GUI release target", systemImage: "desktopcomputer.trianglebadge.exclamationmark")
    }
    .navigationTitle("Settings")
  }
}

#Preview {
  MobileRootView()
}
