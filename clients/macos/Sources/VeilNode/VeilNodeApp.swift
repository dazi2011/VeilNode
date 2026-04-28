import SwiftUI
import AppKit

@main
struct VeilNodeApp: App {
  @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate

  var body: some Scene {
    WindowGroup {
      AppView()
        .frame(minWidth: 880, minHeight: 620)
    }
    .windowStyle(.titleBar)
  }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
  func applicationDidFinishLaunching(_ notification: Notification) {
    NSApp.setActivationPolicy(.regular)
    NSApp.activate(ignoringOtherApps: true)
  }
}

enum AppTab: String, CaseIterable, Identifiable {
  case dashboard
  case seal
  case open
  case contacts
  case settings

  var id: String { rawValue }

  var title: String {
    switch self {
    case .dashboard: "Dashboard"
    case .seal: "Seal"
    case .open: "Open"
    case .contacts: "Contacts"
    case .settings: "Settings"
    }
  }

  var icon: String {
    switch self {
    case .dashboard: "checklist"
    case .seal: "lock.doc"
    case .open: "lock.open"
    case .contacts: "person.2"
    case .settings: "gearshape"
    }
  }
}

@MainActor
struct AppView: View {
  @State private var selectedTab: AppTab = .dashboard
  @State private var commandLog = CommandLog()

  var body: some View {
    TabView(selection: $selectedTab) {
      ForEach(AppTab.allCases) { tab in
        NavigationStack {
          tabContent(tab)
            .navigationTitle(tab.title)
        }
        .tabItem { Label(tab.title, systemImage: tab.icon) }
        .tag(tab)
      }
    }
    .environment(commandLog)
  }

  @ViewBuilder
  private func tabContent(_ tab: AppTab) -> some View {
    switch tab {
    case .dashboard:
      DashboardView()
    case .seal:
      SealView()
    case .open:
      OpenView()
    case .contacts:
      ContactsView()
    case .settings:
      SettingsView()
    }
  }
}
