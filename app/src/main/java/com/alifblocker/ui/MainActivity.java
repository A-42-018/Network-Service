package com.alifblocker.ui;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.net.VpnService;
import android.os.Bundle;
import android.text.InputType;
import android.view.Gravity;
import android.view.View;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.alifblocker.R;
import com.alifblocker.data.BlockedDomains;
import com.alifblocker.databinding.ActivityMainBinding;
import com.alifblocker.service.BlockerVpnService;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class MainActivity extends AppCompatActivity {

    private static final int VPN_REQUEST_CODE = 100;

    // SharedPreferences key where we persist custom domains
    private static final String KEY_CUSTOM_DOMAINS = "custom_domains";

    private ActivityMainBinding binding;
    private SharedPreferences prefs;

    // In-memory list that mirrors what's saved in prefs
    private final List<String> customDomains = new ArrayList<>();

    // Prevents the switch listener firing on programmatic changes
    private boolean isProgrammaticChange = false;

    // ── Lifecycle ────────────────────────────────────────────────────────────

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        prefs = getSharedPreferences("blocker_prefs", MODE_PRIVATE);

        // Load persisted custom domains into BlockedDomains + local list
        loadCustomDomains();

        updateUI();

        // ── Toggle switch ────────────────────────────────────────────────
        binding.switchBlocker.setOnCheckedChangeListener((btn, isChecked) -> {
            if (isProgrammaticChange) return;

            if (isChecked) {
                requestVpnPermission();
            } else {
                String pinHash = prefs.getString("pin_hash", null);
                if (pinHash != null) {
                    // Snap back to ON until correct PIN entered
                    setProgrammatic(true);
                    binding.switchBlocker.setChecked(true);
                    setProgrammatic(false);
                    showPinDialog();
                } else {
                    stopBlocker();
                }
            }
        });

        // ── Add domain button ────────────────────────────────────────────
        binding.btnAddDomain.setOnClickListener(v -> {
            String raw = binding.etCustomDomain.getText().toString().trim().toLowerCase();

            // Strip http:// or https:// if user pasted a full URL
            raw = raw.replaceFirst("^https?://", "").replaceFirst("/.*$", "");

            if (raw.isEmpty()) {
                Toast.makeText(this, "Please enter a domain", Toast.LENGTH_SHORT).show();
                return;
            }

            if (customDomains.contains(raw)) {
                Toast.makeText(this, raw + " is already blocked", Toast.LENGTH_SHORT).show();
                return;
            }

            // Add to memory + BlockedDomains + prefs
            customDomains.add(raw);
            BlockedDomains.addCustomDomain(raw);
            saveCustomDomains();

            // Add a row to the UI list
            addDomainRow(raw);

            binding.etCustomDomain.setText("");
            updateDomainCountBadge();
            updateDomainStat();
            Toast.makeText(this, "Blocked: " + raw, Toast.LENGTH_SHORT).show();
        });

        // ── PIN setup button ────────────────────────────────────────────
        binding.btnSetPin.setOnClickListener(v ->
                startActivity(new Intent(this, PinSetupActivity.class))
        );

        // ── Domain stat label ───────────────────────────────────────────
        updateDomainStat();
    }

    @Override
    protected void onResume() {
        super.onResume();
        updateUI();
    }

    // ── Custom Domain Persistence ────────────────────────────────────────────

    /** Load custom domains from SharedPreferences on startup. */
    private void loadCustomDomains() {
        Set<String> saved = prefs.getStringSet(KEY_CUSTOM_DOMAINS, new HashSet<>());
        customDomains.clear();
        customDomains.addAll(saved);

        // Rebuild the UI list and re-add to BlockedDomains
        binding.layoutCustomDomainList.removeAllViews();
        for (String domain : customDomains) {
            BlockedDomains.addCustomDomain(domain);
            addDomainRow(domain);
        }

        updateDomainCountBadge();
    }

    /** Persist the current custom domain list to SharedPreferences. */
    private void saveCustomDomains() {
        prefs.edit()
                .putStringSet(KEY_CUSTOM_DOMAINS, new HashSet<>(customDomains))
                .apply();
    }

    // ── Domain Row UI ────────────────────────────────────────────────────────

    /**
     * Dynamically creates one row for a blocked domain and appends it
     * to the layoutCustomDomainList in the XML.
     *
     * Layout:  [ 🔴  example.com          🗑️ ]
     */
    private void addDomainRow(String domain) {
        // Show divider + header now that list has items
        binding.dividerCustomDomains.setVisibility(View.VISIBLE);
        binding.layoutCustomDomainsHeader.setVisibility(View.VISIBLE);

        // ── Row container ──
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);

        LinearLayout.LayoutParams rowParams = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
        rowParams.setMargins(0, 0, 0, dpToPx(6));
        row.setLayoutParams(rowParams);

        row.setBackground(getRoundedBackground());
        row.setPadding(dpToPx(12), dpToPx(10), dpToPx(10), dpToPx(10));

        // ── Red dot indicator ──
        TextView dot = new TextView(this);
        dot.setText("●");
        dot.setTextColor(Color.parseColor("#FF5252"));
        dot.setTextSize(8);
        LinearLayout.LayoutParams dotParams = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
        dotParams.setMarginEnd(dpToPx(8));
        dot.setLayoutParams(dotParams);
        row.addView(dot);

        // ── Domain label ──
        TextView label = new TextView(this);
        label.setText(domain);
        label.setTextColor(Color.parseColor("#CCFFFFFF"));
        label.setTextSize(13);
        label.setSingleLine(true);
        label.setEllipsize(android.text.TextUtils.TruncateAt.END);
        LinearLayout.LayoutParams labelParams = new LinearLayout.LayoutParams(
                0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f);
        label.setLayoutParams(labelParams);
        row.addView(label);

        // ── Remove button ──
        TextView removeBtn = new TextView(this);
        removeBtn.setText("🗑️");
        removeBtn.setTextSize(16);
        removeBtn.setPadding(dpToPx(8), dpToPx(4), dpToPx(4), dpToPx(4));
        removeBtn.setClickable(true);
        removeBtn.setFocusable(true);
        row.addView(removeBtn);

        // ── Remove button click ──
        removeBtn.setOnClickListener(v -> {
            new AlertDialog.Builder(this)
                    .setTitle("Remove Domain")
                    .setMessage("Stop blocking \"" + domain + "\"?")
                    .setPositiveButton("Remove", (dialog, which) -> {
                        // Remove from memory, BlockedDomains, prefs, and UI
                        customDomains.remove(domain);
                        BlockedDomains.removeCustomDomain(domain);
                        saveCustomDomains();

                        binding.layoutCustomDomainList.removeView(row);

                        // Hide divider + header when list becomes empty
                        if (customDomains.isEmpty()) {
                            binding.dividerCustomDomains.setVisibility(View.GONE);
                            binding.layoutCustomDomainsHeader.setVisibility(View.GONE);
                        }

                        updateDomainCountBadge();
                        updateDomainStat();
                        Toast.makeText(this,
                                "Removed: " + domain, Toast.LENGTH_SHORT).show();
                    })
                    .setNegativeButton("Cancel", null)
                    .show();
        });

        binding.layoutCustomDomainList.addView(row);
    }

    /** Updates the "X added" counter in the list header. */
    private void updateDomainCountBadge() {
        int count = customDomains.size();
        binding.tvCustomCount.setText(count + (count == 1 ? " added" : " added"));
    }

    /** Updates the "Domains" stat pill in the status card. */
    private void updateDomainStat() {
        binding.tvDomainCount.setText(String.valueOf(BlockedDomains.getCount()));
    }

    // ── VPN Permission Flow ──────────────────────────────────────────────────

    private void requestVpnPermission() {
        Intent vpnIntent = VpnService.prepare(this);
        if (vpnIntent != null) {
            startActivityForResult(vpnIntent, VPN_REQUEST_CODE);
        } else {
            startBlocker();
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == VPN_REQUEST_CODE) {
            if (resultCode == Activity.RESULT_OK) {
                startBlocker();
            } else {
                setProgrammatic(true);
                binding.switchBlocker.setChecked(false);
                setProgrammatic(false);
                Toast.makeText(this, "VPN permission denied", Toast.LENGTH_SHORT).show();
            }
        }
    }

    // ── PIN Dialog ───────────────────────────────────────────────────────────

    private void showPinDialog() {
        EditText pinInput = new EditText(this);
        pinInput.setInputType(
                InputType.TYPE_CLASS_NUMBER | InputType.TYPE_NUMBER_VARIATION_PASSWORD);
        pinInput.setHint("Enter PIN");

        FrameLayout container = new FrameLayout(this);
        FrameLayout.LayoutParams params = new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.WRAP_CONTENT);
        params.leftMargin  = dpToPx(24);
        params.rightMargin = dpToPx(24);
        pinInput.setLayoutParams(params);
        container.addView(pinInput);

        new AlertDialog.Builder(this)
                .setTitle("🔒 Parental Lock")
                .setMessage("Enter your PIN to disable the blocker")
                .setView(container)
                .setCancelable(false)
                .setPositiveButton("Unlock", (dialog, which) -> {
                    String entered = pinInput.getText().toString().trim();
                    if (PinSetupActivity.verifyPin(prefs, entered)) {
                        stopBlocker();
                    } else {
                        Toast.makeText(this, "❌ Incorrect PIN", Toast.LENGTH_SHORT).show();
                    }
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    // ── Blocker Start / Stop ─────────────────────────────────────────────────

    private void startBlocker() {
        Intent intent = new Intent(this, BlockerVpnService.class);
        intent.setAction(BlockerVpnService.ACTION_START);
        startForegroundService(intent);
        prefs.edit().putBoolean("vpn_enabled", true).apply();
        updateUI();
        Toast.makeText(this, "🛡️ Blocker activated!", Toast.LENGTH_SHORT).show();
    }

    private void stopBlocker() {
        Intent intent = new Intent(this, BlockerVpnService.class);
        intent.setAction(BlockerVpnService.ACTION_STOP);
        startService(intent);
        prefs.edit().putBoolean("vpn_enabled", false).apply();

        setProgrammatic(true);
        binding.switchBlocker.setChecked(false);
        setProgrammatic(false);

        updateUI();
        Toast.makeText(this, "Blocker stopped", Toast.LENGTH_SHORT).show();
    }

    // ── UI Helpers ───────────────────────────────────────────────────────────

    private void updateUI() {
        boolean enabled = BlockerVpnService.isRunning()
                || prefs.getBoolean("vpn_enabled", false);

        setProgrammatic(true);
        binding.switchBlocker.setChecked(enabled);
        setProgrammatic(false);

        binding.tvStatus.setText(
                enabled ? "🛡️  Protection: ON" : "⚠️  Protection: OFF");
        binding.tvStatus.setTextColor(
                getColor(enabled ? R.color.green : R.color.red));
        binding.cardStatus.setCardBackgroundColor(
                getColor(enabled ? R.color.card_active : R.color.card_inactive));

        // PIN badge
        boolean pinSet = prefs.getString("pin_hash", null) != null;
        binding.tvPinBadge.setVisibility(pinSet ? View.VISIBLE : View.GONE);
    }

    private void setProgrammatic(boolean value) {
        isProgrammaticChange = value;
    }

    private int dpToPx(int dp) {
        float density = getResources().getDisplayMetrics().density;
        return Math.round(dp * density);
    }

    /**
     * Returns a simple rounded rectangle drawable for domain row backgrounds.
     * Uses a GradientDrawable so we don't need an extra XML file.
     */
    private android.graphics.drawable.GradientDrawable getRoundedBackground() {
        android.graphics.drawable.GradientDrawable bg =
                new android.graphics.drawable.GradientDrawable();
        bg.setShape(android.graphics.drawable.GradientDrawable.RECTANGLE);
        bg.setCornerRadius(dpToPx(12));
        bg.setColor(Color.parseColor("#14FFFFFF")); // subtle white tint
        bg.setStroke(1, Color.parseColor("#1AFFFFFF"));
        return bg;
    }
}