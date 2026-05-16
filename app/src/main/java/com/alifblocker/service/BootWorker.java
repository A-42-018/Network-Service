package com.alifblocker.service;

import android.content.Context;
import android.content.Intent;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.work.Worker;
import androidx.work.WorkerParameters;

/**
 * WorkManager Worker that starts the VPN service after boot.
 * Used instead of direct startForegroundService() to comply with
 * Android 12+ background launch restrictions.
 */
public class BootWorker extends Worker {

    private static final String TAG = "BootWorker";

    public BootWorker(@NonNull Context context, @NonNull WorkerParameters params) {
        super(context, params);
    }

    @NonNull
    @Override
    public Result doWork() {
        try {
            Intent vpnIntent = new Intent(getApplicationContext(), BlockerVpnService.class);
            vpnIntent.setAction(BlockerVpnService.ACTION_START);
            getApplicationContext().startForegroundService(vpnIntent);
            Log.i(TAG, "VPN started via WorkManager after boot");
            return Result.success();
        } catch (Exception e) {
            Log.e(TAG, "Failed to start VPN after boot: " + e.getMessage());
            return Result.retry();
        }
    }
}
