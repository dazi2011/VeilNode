package org.veilnode;

import android.app.Activity;
import android.graphics.Typeface;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.HorizontalScrollView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

public final class MainActivity extends Activity {
    private final String[] tabs = {"Inbox", "Seal", "Strategy", "Roots", "Carrier", "Contacts", "Settings"};
    private TextView title;
    private TextView body;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(buildContentView());
        selectTab("Inbox");
    }

    private View buildContentView() {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(28, 28, 28, 28);

        TextView heading = new TextView(this);
        heading.setText("VeilNode");
        heading.setTextSize(28);
        heading.setTypeface(Typeface.DEFAULT_BOLD);
        root.addView(heading);

        HorizontalScrollView navScroller = new HorizontalScrollView(this);
        LinearLayout nav = new LinearLayout(this);
        nav.setOrientation(LinearLayout.HORIZONTAL);
        for (String tab : tabs) {
            Button button = new Button(this);
            button.setText(tab);
            button.setAllCaps(false);
            button.setOnClickListener(view -> selectTab(tab));
            nav.addView(button);
        }
        navScroller.addView(nav);
        root.addView(navScroller);

        ScrollView contentScroller = new ScrollView(this);
        LinearLayout content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(0, 24, 0, 0);

        title = new TextView(this);
        title.setTextSize(22);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        content.addView(title);

        body = new TextView(this);
        body.setTextSize(16);
        body.setLineSpacing(6, 1.0f);
        body.setPadding(0, 18, 0, 0);
        content.addView(body);

        contentScroller.addView(content);
        root.addView(contentScroller, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                0,
                1.0f
        ));
        return root;
    }

    private void selectTab(String tab) {
        title.setText(tab);
        body.setText(descriptionFor(tab));
    }

    private String descriptionFor(String tab) {
        switch (tab) {
            case "Seal":
                return "Seal payloads with crypto_core_version 2.2, root_vkp input, adaptive envelope policy selection, low-signature mode and optional decoy payloads.";
            case "Strategy":
                return "Extract features, generate candidates, rank policy choices, scan fixed plaintext signatures and inspect portable model.json files. The model chooses envelope policy only; it never creates cryptography.";
            case "Roots":
                return "Create, inspect, rotate, retire, revoke, import, split and recover root keyparts through the shared offline core boundary.";
            case "Carrier":
                return "Audit and compare carriers, inspect structure deltas and view local engineering risk scores. Scores do not prove undetectability.";
            case "Contacts":
                return "Import .vid contacts and .vpkg node packages when the shared mobile core binding is connected.";
            case "Settings":
                return "Offline-only client shell. Linux and NAS GUI release targets are removed; those targets use the CLI.";
            case "Inbox":
            default:
                return "Open v1/v2/v2.2 envelopes with generic failure handling, replay checks and shared-core compatibility.";
        }
    }
}
