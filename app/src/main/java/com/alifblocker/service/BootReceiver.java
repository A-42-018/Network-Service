package com.alifblocker.service;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;

import androidx.work.ExistingWorkPolicy;
import androidx.work.OneTimeWorkRequest;
import androidx.work.WorkManager;

import java.util.concurrent.TimeUnit;

/**
 * Automatically restarts the VPN blocker after device reboot,
 * if the user had it enabled before shutdown.
 * Uses WorkManager for Android 12+ background launch compliance.
 */
public class BootReceiver extends BroadcastReceiver {

    @Override
    public void onReceive(Context context, Intent intent) {
        if (!Intent.ACTION_BOOT_COMPLETED.equals(intent.getAction())) return;

        SharedPreferences prefs = context.getSharedPreferences("blocker_prefs", Context.MODE_PRIVATE);
        boolean wasEnabled = prefs.getBoolean("vpn_enabled", false);

        if (wasEnabled) {
            OneTimeWorkRequest workRequest = new OneTimeWorkRequest.Builder(BootWorker.class)
                .setInitialDelay(5, TimeUnit.SECONDS)
                .build();
            WorkManager.getInstance(context)
                .enqueueUniqueWork("boot_start_vpn", ExistingWorkPolicy.REPLACE, workRequest);
        }
    }
}
