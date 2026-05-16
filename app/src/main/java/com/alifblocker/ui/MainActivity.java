package com.alifblocker.ui;

import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.VpnService;
import android.os.Bundle;
import android.view.View;
import android.widget.CompoundButton;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.alifblocker.R;
import com.alifblocker.data.BlockedDomains;
import com.alifblocker.databinding.ActivityMainBinding;
import com.alifblocker.service.BlockerVpnService;

public class MainActivity extends AppCompatActivity {

    private static final int VPN_REQUEST_CODE = 100;
    private ActivityMainBinding binding;
    private SharedPreferences prefs;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        prefs = getSharedPreferences("blocker_prefs", MODE_PRIVATE);

        updateUI();

        // Toggle switch
        binding.switchBlocker.setOnCheckedChangeListener((btn, isChecked) -> {
            if (isChecked) {
                requestVpnPermission();
            } else {
                stopBlocker();
            }
        });

        // Custom domain button
        binding.btnAddDomain.setOnClickListener(v -> {
            String domain = binding.etCustomDomain.getText().toString().trim();
            if (!domain.isEmpty()) {
                BlockedDomains.addCustomDomain(domain);
                binding.etCustomDomain.setText("");
                binding.tvDomainCount.setText("Blocking " + BlockedDomains.getCount() + " domains");
                Toast.makeText(this, "Added: " + domain, Toast.LENGTH_SHORT).show();
            }
        });

        // PIN setup
        binding.btnSetPin.setOnClickListener(v ->
            startActivity(new Intent(this, PinSetupActivity.class))
        );

        // Stats
        binding.tvDomainCount.setText("Blocking " + BlockedDomains.getCount() + " domains");
    }

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
                binding.switchBlocker.setChecked(false);
                Toast.makeText(this, "VPN permission denied", Toast.LENGTH_SHORT).show();
            }
        }
    }

    private void startBlocker() {
        Intent intent = new Intent(this, BlockerVpnService.class);
        intent.setAction(BlockerVpnService.ACTION_START);
        startForegroundService(intent);

        prefs.edit().putBoolean("vpn_enabled", true).apply();
        updateUI();
        Toast.makeText(this, "Blocker activated!", Toast.LENGTH_SHORT).show();
    }

    private void stopBlocker() {
        Intent intent = new Intent(this, BlockerVpnService.class);
        intent.setAction(BlockerVpnService.ACTION_STOP);
        startService(intent);

        prefs.edit().putBoolean("vpn_enabled", false).apply();
        updateUI();
        Toast.makeText(this, "Blocker stopped", Toast.LENGTH_SHORT).show();
    }

    private void updateUI() {
        boolean enabled = prefs.getBoolean("vpn_enabled", false);
        binding.switchBlocker.setChecked(enabled);
        binding.tvStatus.setText(enabled ? "🛡️ Protection: ON" : "⚠️ Protection: OFF");
        binding.tvStatus.setTextColor(getColor(enabled ? R.color.green : R.color.red));
        binding.cardStatus.setCardBackgroundColor(
            getColor(enabled ? R.color.card_active : R.color.card_inactive)
        );
    }

    @Override
    protected void onResume() {
        super.onResume();
        updateUI();
    }
}
