package com.alifblocker.ui;

import android.os.Bundle;
import androidx.appcompat.app.AppCompatActivity;
import com.alifblocker.databinding.ActivityBlockedBinding;

public class BlockedActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ActivityBlockedBinding binding = ActivityBlockedBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        String domain = getIntent().getStringExtra("domain");
        if (domain != null) {
            binding.tvBlockedDomain.setText("Blocked: " + domain);
        }

        binding.btnGoBack.setOnClickListener(v -> finish());
    }
}
