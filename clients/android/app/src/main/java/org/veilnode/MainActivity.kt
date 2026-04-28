package org.veilnode

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier

class MainActivity : ComponentActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    setContent { VeilNodeApp() }
  }
}

enum class AppTab(val title: String) {
  Inbox("Inbox"),
  Seal("Seal"),
  Contacts("Contacts"),
  Settings("Settings")
}

@Composable
fun VeilNodeApp() {
  var selectedTab by remember { mutableStateOf(AppTab.Inbox) }
  Scaffold(
    bottomBar = {
      NavigationBar {
        AppTab.entries.forEach { tab ->
          NavigationBarItem(
            selected = selectedTab == tab,
            onClick = { selectedTab = tab },
            icon = { Text(tab.title.take(1)) },
            label = { Text(tab.title) }
          )
        }
      }
    }
  ) { padding ->
    Text(
      text = when (selectedTab) {
        AppTab.Inbox -> "Import .vpkg / .vmsg via Android share sheet."
        AppTab.Seal -> "Seal workflow using shared veil-core binding."
        AppTab.Contacts -> "Import .vid contacts."
        AppTab.Settings -> "Android Keystore / StrongBox adapter boundary."
      },
      modifier = Modifier.padding(padding)
    )
  }
}
