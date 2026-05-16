package com.alifblocker.ui;

import android.content.SharedPreferences;
import android.os.Bundle;
import android.util.Base64;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.alifblocker.databinding.ActivityPinSetupBinding;

import java.security.SecureRandom;
import java.security.spec.KeySpec;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Allows a parent/admin to set a PIN so the child cannot
 * simply turn off the blocker.
 */
public class PinSetupActivity extends AppCompatActivity {

    private ActivityPinSetupBinding binding;
    private SharedPreferences prefs;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        binding = ActivityPinSetupBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        prefs = getSharedPreferences("blocker_prefs", MODE_PRIVATE);

        String existingHash = prefs.getString("pin_hash", null);
        if (existingHash != null) {
            binding.tvPinStatus.setText("PIN is currently set. Enter new PIN to change.");
        } else {
            binding.tvPinStatus.setText("No PIN set. Anyone can turn off the blocker.");
        }

        binding.btnSavePin.setOnClickListener(v -> {
            String pin = binding.etPin.getText().toString().trim();
            String confirm = binding.etPinConfirm.getText().toString().trim();

            if (pin.length() < 4) {
                Toast.makeText(this, "PIN must be at least 4 digits", Toast.LENGTH_SHORT).show();
                return;
            }

            if (!pin.equals(confirm)) {
                Toast.makeText(this, "PINs do not match", Toast.LENGTH_SHORT).show();
                return;
            }

            byte[] salt = generateSalt();
            String hash = hashPin(pin, salt);
            prefs.edit()
                .putString("pin_hash", hash)
                .putString("pin_salt", Base64.encodeToString(salt, Base64.NO_WRAP))
                .apply();
            Toast.makeText(this, "PIN saved successfully!", Toast.LENGTH_SHORT).show();
            finish();
        });

        binding.btnClearPin.setOnClickListener(v -> {
            prefs.edit().remove("pin_hash").remove("pin_salt").apply();
            binding.tvPinStatus.setText("No PIN set. Anyone can turn off the blocker.");
            Toast.makeText(this, "PIN cleared", Toast.LENGTH_SHORT).show();
        });
    }

    private byte[] generateSalt() {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

    private String hashPin(String pin, byte[] salt) {
        try {
            KeySpec spec = new PBEKeySpec(pin.toCharArray(), salt, 10000, 256);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] hash = factory.generateSecret(spec).getEncoded();
            return Base64.encodeToString(hash, Base64.NO_WRAP);
        } catch (Exception e) {
            throw new RuntimeException("PIN hashing failed", e);
        }
    }

    public static boolean verifyPin(SharedPreferences prefs, String inputPin) {
        String storedHash = prefs.getString("pin_hash", null);
        String storedSalt = prefs.getString("pin_salt", null);
        if (storedHash == null || storedSalt == null) return true;
        try {
            byte[] salt = Base64.decode(storedSalt, Base64.NO_WRAP);
            KeySpec spec = new PBEKeySpec(inputPin.toCharArray(), salt, 10000, 256);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] hash = factory.generateSecret(spec).getEncoded();
            String inputHash = Base64.encodeToString(hash, Base64.NO_WRAP);
            return storedHash.equals(inputHash);
        } catch (Exception e) {
            return false;
        }
    }
}
