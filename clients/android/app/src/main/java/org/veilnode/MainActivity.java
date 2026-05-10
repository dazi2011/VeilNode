package org.veilnode;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.database.Cursor;
import android.graphics.Color;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Bundle;
import android.provider.OpenableColumns;
import android.text.method.LinkMovementMethod;
import android.text.SpannableString;
import android.text.style.URLSpan;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.InputStream;
import java.security.MessageDigest;

public final class MainActivity extends Activity {

    private static final int REQUEST_INSPECT = 1001;

    private LinearLayout content;
    private TextView screenTitle;
    private String currentTab = "Overview";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(buildRoot());
        showOverview();
    }

    private View buildRoot() {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(Color.parseColor("#FAFAFA"));
        root.setPadding(dp(20), dp(28), dp(20), dp(20));

        TextView heading = new TextView(this);
        heading.setText("VeilNode");
        heading.setTextSize(28);
        heading.setTypeface(Typeface.DEFAULT_BOLD);
        heading.setTextColor(Color.parseColor("#1A1A1A"));
        root.addView(heading);

        TextView tagline = new TextView(this);
        tagline.setText("Offline envelope encryption for ordinary carrier files.");
        tagline.setTextColor(Color.parseColor("#666666"));
        tagline.setPadding(0, dp(4), 0, dp(20));
        root.addView(tagline);

        LinearLayout tabs = new LinearLayout(this);
        tabs.setOrientation(LinearLayout.HORIZONTAL);
        String[] labels = {"Overview", "Inspect", "Commands", "About"};
        for (String label : labels) {
            Button button = new Button(this);
            button.setText(label);
            button.setAllCaps(false);
            button.setOnClickListener(view -> {
                currentTab = label;
                switch (label) {
                    case "Inspect":
                        showInspect();
                        break;
                    case "Commands":
                        showCommands();
                        break;
                    case "About":
                        showAbout();
                        break;
                    default:
                        showOverview();
                        break;
                }
            });
            LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f);
            params.setMargins(dp(2), 0, dp(2), 0);
            tabs.addView(button, params);
        }
        root.addView(tabs);

        screenTitle = new TextView(this);
        screenTitle.setTextSize(22);
        screenTitle.setTypeface(Typeface.DEFAULT_BOLD);
        screenTitle.setTextColor(Color.parseColor("#1A1A1A"));
        screenTitle.setPadding(0, dp(20), 0, dp(8));
        root.addView(screenTitle);

        ScrollView scroller = new ScrollView(this);
        content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        scroller.addView(content);
        root.addView(scroller, new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f));
        return root;
    }

    private void showOverview() {
        screenTitle.setText("Overview");
        content.removeAllViews();
        content.addView(card("Companion app",
                "Sealing and opening run on your desktop CLI / GUI. This Android companion does not ship a Python crypto core. " +
                        "It lets you receive carriers via Files / share-sheet, inspect them locally, and copy the right CLI commands."));
        content.addView(card("Cryptographic boundary",
                "Fixed by core: root_vkp · HKDF · Argon2id · AEAD · msg_id · message_salt · file_hash.\n" +
                        "Adaptive policy chooses envelope shape only — never cryptography."));
        content.addView(card("Use the desktop tools for",
                "• seal / open / verify\n" +
                        "• identity, contact, root_vkp lifecycle\n" +
                        "• strategy features / generate / select / score / scan\n" +
                        "• carrier audit / compare / profile"));
    }

    private void showInspect() {
        screenTitle.setText("Inspect");
        content.removeAllViews();
        content.addView(card("Inspect a carrier file",
                "Pick a file from Files / share-sheet. The companion reports size and SHA-256 so you can confirm it matches the desktop output. It does not decrypt."));

        Button pick = new Button(this);
        pick.setText("Choose file");
        pick.setAllCaps(false);
        pick.setOnClickListener(view -> {
            Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
            intent.addCategory(Intent.CATEGORY_OPENABLE);
            intent.setType("*/*");
            startActivityForResult(intent, REQUEST_INSPECT);
        });
        LinearLayout.LayoutParams pickParams = new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        pickParams.setMargins(0, dp(8), 0, 0);
        content.addView(pick, pickParams);
    }

    private void showInspectResult(String name, long size, String sha256) {
        content.removeAllViews();
        content.addView(card("File", "Name: " + name + "\nSize: " + formatBytes(size)));
        TextView digest = new TextView(this);
        digest.setText("SHA-256:\n" + sha256);
        digest.setTextIsSelectable(true);
        digest.setTypeface(Typeface.MONOSPACE);
        digest.setPadding(dp(16), dp(16), dp(16), dp(16));
        digest.setBackgroundColor(Color.parseColor("#FFFFFF"));
        LinearLayout.LayoutParams digestParams = new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        digestParams.setMargins(0, dp(12), 0, 0);
        content.addView(digest, digestParams);

        Button copy = new Button(this);
        copy.setText("Copy SHA-256");
        copy.setAllCaps(false);
        copy.setOnClickListener(view -> copyToClipboard("sha256", sha256));
        LinearLayout.LayoutParams copyParams = new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        copyParams.setMargins(0, dp(8), 0, 0);
        content.addView(copy, copyParams);

        Button again = new Button(this);
        again.setText("Inspect another file");
        again.setAllCaps(false);
        again.setOnClickListener(view -> showInspect());
        LinearLayout.LayoutParams againParams = new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        againParams.setMargins(0, dp(4), 0, 0);
        content.addView(again, againParams);
    }

    private void showCommands() {
        screenTitle.setText("Commands");
        content.removeAllViews();
        content.addView(card("Run these on your desktop", "Tap a card to copy."));

        addCommand("Health check", "veil-node doctor");
        addCommand("Create identity",
                "veil-node --home ~/.veil/alice identity create --name alice --password idpass");
        addCommand("Create root keypart",
                "veil-node keypart root create --out ~/.veil/root.vkpseed --password rootpass --label alice-bob");
        addCommand("Adaptive seal",
                "veil-node --home ~/.veil/alice seal IN.bin COVER.zip OUT.zip --to alice --password msgpass " +
                        "--root-keypart ~/.veil/root.vkpseed --root-keypart-password rootpass --crypto-core 2.2 " +
                        "--low-signature --adaptive-policy --policy-candidates 20");
        addCommand("Open",
                "veil-node --home ~/.veil/alice open OUT.zip --out ~/Desktop/recovered --password msgpass " +
                        "--identity-password idpass --root-keypart ~/.veil/root.vkpseed --root-keypart-password rootpass");
    }

    private void addCommand(String title, String command) {
        LinearLayout block = new LinearLayout(this);
        block.setOrientation(LinearLayout.VERTICAL);
        block.setBackgroundColor(Color.parseColor("#FFFFFF"));
        block.setPadding(dp(16), dp(14), dp(16), dp(14));
        LinearLayout.LayoutParams blockParams = new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        blockParams.setMargins(0, dp(8), 0, 0);

        TextView titleView = new TextView(this);
        titleView.setText(title);
        titleView.setTypeface(Typeface.DEFAULT_BOLD);
        titleView.setTextColor(Color.parseColor("#1A1A1A"));
        block.addView(titleView);

        TextView body = new TextView(this);
        body.setText(command);
        body.setTypeface(Typeface.MONOSPACE);
        body.setTextIsSelectable(true);
        body.setTextColor(Color.parseColor("#222222"));
        body.setPadding(0, dp(6), 0, dp(8));
        block.addView(body);

        Button copy = new Button(this);
        copy.setText("Copy command");
        copy.setAllCaps(false);
        copy.setOnClickListener(view -> copyToClipboard(title, command));
        block.addView(copy);

        content.addView(block, blockParams);
    }

    private void showAbout() {
        screenTitle.setText("About");
        content.removeAllViews();
        content.addView(card("VeilNode Suite 0.3.2", "crypto_core_version = 2.2\nThe crypto core marker is a message compatibility tag, not the suite package version."));
        content.addView(card("Engineering language",
                "VeilNode does not claim 'undetectable'. The project's terms are: low-signature, metadata minimization, carrier fidelity, local engineering risk score."));

        addLink("Project repository", "https://github.com/dazi2011/VeilNode");
        addLink("Latest release", "https://github.com/dazi2011/VeilNode/releases/latest");
        addLink("Technical notes", "https://github.com/dazi2011/VeilNode/blob/main/docs/TECHNICAL.md");
        addLink("Platform matrix", "https://github.com/dazi2011/VeilNode/blob/main/docs/PLATFORMS.md");

        content.addView(card("Out of scope on Android",
                "• On-device sealing or opening (no Python core).\n" +
                        "• Replay-seen database lives next to the desktop home.\n" +
                        "• Root keypart creation or rotation.\n" +
                        "Use the desktop CLI / GUI for these."));
    }

    private void addLink(String label, String url) {
        TextView link = new TextView(this);
        SpannableString spannable = new SpannableString(label);
        spannable.setSpan(new URLSpan(url), 0, label.length(), 0);
        link.setText(spannable);
        link.setMovementMethod(LinkMovementMethod.getInstance());
        link.setTextColor(Color.parseColor("#22577A"));
        link.setPadding(dp(16), dp(10), dp(16), dp(10));
        link.setBackgroundColor(Color.parseColor("#FFFFFF"));
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        params.setMargins(0, dp(6), 0, 0);
        content.addView(link, params);
    }

    private View card(String title, String body) {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackgroundColor(Color.parseColor("#FFFFFF"));
        card.setPadding(dp(16), dp(14), dp(16), dp(14));
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        params.setMargins(0, dp(8), 0, 0);
        card.setLayoutParams(params);

        TextView t = new TextView(this);
        t.setText(title);
        t.setTypeface(Typeface.DEFAULT_BOLD);
        t.setTextColor(Color.parseColor("#1A1A1A"));
        card.addView(t);

        TextView b = new TextView(this);
        b.setText(body);
        b.setTextColor(Color.parseColor("#333333"));
        b.setLineSpacing(dp(2), 1.0f);
        b.setPadding(0, dp(6), 0, 0);
        card.addView(b);
        return card;
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != REQUEST_INSPECT || resultCode != RESULT_OK || data == null) {
            return;
        }
        Uri uri = data.getData();
        if (uri == null) {
            return;
        }
        try {
            String name = queryName(uri);
            long size = querySize(uri);
            String sha256 = computeSha256(uri);
            screenTitle.setText("Inspect");
            showInspectResult(name == null ? uri.getLastPathSegment() : name, size, sha256);
        } catch (Exception ex) {
            Toast.makeText(this, "Inspect failed: " + ex.getMessage(), Toast.LENGTH_LONG).show();
        }
    }

    private String queryName(Uri uri) {
        try (Cursor cursor = getContentResolver().query(uri, null, null, null, null)) {
            if (cursor != null && cursor.moveToFirst()) {
                int idx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                if (idx >= 0) {
                    return cursor.getString(idx);
                }
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    private long querySize(Uri uri) {
        try (Cursor cursor = getContentResolver().query(uri, null, null, null, null)) {
            if (cursor != null && cursor.moveToFirst()) {
                int idx = cursor.getColumnIndex(OpenableColumns.SIZE);
                if (idx >= 0 && !cursor.isNull(idx)) {
                    return cursor.getLong(idx);
                }
            }
        } catch (Exception ignored) {
        }
        return -1L;
    }

    private String computeSha256(Uri uri) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream stream = getContentResolver().openInputStream(uri)) {
            if (stream == null) {
                throw new IllegalStateException("cannot open file");
            }
            byte[] buffer = new byte[64 * 1024];
            int read;
            while ((read = stream.read(buffer)) > 0) {
                digest.update(buffer, 0, read);
            }
        }
        byte[] bytes = digest.digest();
        StringBuilder hex = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            hex.append(String.format("%02x", b));
        }
        return hex.toString();
    }

    private String formatBytes(long bytes) {
        if (bytes < 0) {
            return "unknown";
        }
        if (bytes < 1024) return bytes + " B";
        double v = bytes;
        String[] units = {"KB", "MB", "GB", "TB"};
        int i = -1;
        do {
            v /= 1024.0;
            i++;
        } while (v >= 1024.0 && i < units.length - 1);
        return String.format("%.1f %s", v, units[i]);
    }

    private void copyToClipboard(String label, String text) {
        ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        if (clipboard == null) {
            Toast.makeText(this, "Clipboard unavailable", Toast.LENGTH_SHORT).show();
            return;
        }
        clipboard.setPrimaryClip(ClipData.newPlainText(label, text));
        Toast.makeText(this, "Copied", Toast.LENGTH_SHORT).show();
    }

    private int dp(int value) {
        float density = getResources().getDisplayMetrics().density;
        return Math.round(value * density);
    }
}
