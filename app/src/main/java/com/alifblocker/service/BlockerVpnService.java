package com.alifblocker.service;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import androidx.core.app.NotificationCompat;

import com.alifblocker.R;
import com.alifblocker.data.BlockedDomains;
import com.alifblocker.ui.MainActivity;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.ByteBuffer;

/**
 * AlifBlocker VPN Service — DNS-only interception.
 *
 * Upgrades in this version:
 *
 *  1. UPSTREAM DNS → AdGuard Family Protection (94.140.14.15 / 94.140.15.16)
 *     Blocks adult content AT THE SERVER LEVEL as a second layer.
 *     Even domains not in our local list get blocked by AdGuard.
 *
 *  2. DoH IP BLOCKING → Cloudflare (1.1.1.1, 1.0.0.1) and other DoH
 *     provider IPs are routed through our TUN so browser encrypted-DNS
 *     bypass attempts are captured and dropped.
 *
 *  3. BLOCKLIST INIT → BlockedDomains.initializeWithContext() loads the
 *     cached Steven Black hosts file (~70k domains) from disk on start,
 *     and triggers a background download if cache is older than 7 days.
 *
 *  4. FALLBACK DNS → if primary AdGuard DNS times out, automatically
 *     retries with secondary AdGuard server.
 */
public class BlockerVpnService extends VpnService {

    private static final String TAG         = "BlockerVPN";
    private static final String CHANNEL_ID  = "blocker_vpn_channel";
    private static final int    NOTIFICATION_ID = 1;

    public static final String ACTION_START = "START_VPN";
    public static final String ACTION_STOP  = "STOP_VPN";

    private static volatile boolean isRunning = false;

    private ParcelFileDescriptor vpnInterface;
    private Thread vpnThread;

    // ── AdGuard Family Protection DNS ─────────────────────────────────────────
    // Blocks adult content server-side — second layer after our local list.
    private static final String PRIMARY_DNS   = "94.140.14.15";
    private static final String SECONDARY_DNS = "94.140.15.16";
    private static final int    DNS_PORT      = 53;

    // Virtual TUN address
    private static final String TUN_ADDRESS = "10.99.99.1";
    private static final int    TUN_PREFIX  = 32;

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && ACTION_STOP.equals(intent.getAction())) {
            stopVpn();
            return START_NOT_STICKY;
        }
        startForeground(NOTIFICATION_ID, buildNotification());
        startVpn();
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        stopVpn();
        super.onDestroy();
    }

    // ── VPN Setup ─────────────────────────────────────────────────────────────

    private void startVpn() {
        if (isRunning) return;

        // Load cached blocklist from disk + trigger background refresh if needed
        BlockedDomains.initializeWithContext(getApplicationContext());

        try {
            Builder builder = new Builder();
            builder.setSession("AlifBlocker")
                    .addAddress(TUN_ADDRESS, TUN_PREFIX)
                    .setMtu(1500)

                    // ── Route AdGuard DNS servers through TUN ──
                    .addRoute(PRIMARY_DNS,   32)
                    .addRoute(SECONDARY_DNS, 32)

                    // ── Route DoH provider IPs through TUN ──
                    // Browsers (Chrome, Firefox, Edge) use these IPs for
                    // encrypted DNS. Routing them here means we capture
                    // those packets too. Combined with blocking their domains,
                    // browsers fall back to system DNS (= our AdGuard DNS).
                    .addRoute("1.1.1.1",         32)  // Cloudflare
                    .addRoute("1.0.0.1",         32)  // Cloudflare
                    .addRoute("1.1.1.2",         32)  // Cloudflare Family
                    .addRoute("1.0.0.2",         32)  // Cloudflare Family
                    .addRoute("9.9.9.9",         32)  // Quad9
                    .addRoute("149.112.112.112", 32)  // Quad9

                    // Tell OS to use AdGuard Family as system DNS
                    .addDnsServer(PRIMARY_DNS)
                    .addDnsServer(SECONDARY_DNS)

                    // Exclude our own app from VPN (prevents protected socket loop)
                    .addDisallowedApplication(getPackageName());

            vpnInterface = builder.establish();

            if (vpnInterface == null) {
                Log.e(TAG, "Failed to establish VPN interface");
                return;
            }

            isRunning = true;

            vpnThread = new Thread(this::runVpnLoop, "VpnThread");
            vpnThread.setDaemon(true);
            vpnThread.start();

            Log.i(TAG, "VPN started — AdGuard Family DNS + DoH blocking active");

        } catch (Exception e) {
            Log.e(TAG, "VPN start error: " + e.getMessage(), e);
        }
    }

    private void stopVpn() {
        isRunning = false;

        if (vpnThread != null) {
            vpnThread.interrupt();
            vpnThread = null;
        }

        try {
            if (vpnInterface != null) {
                vpnInterface.close();
                vpnInterface = null;
            }
        } catch (Exception e) {
            Log.e(TAG, "Error closing VPN interface: " + e.getMessage());
        }

        stopForeground(true);
        stopSelf();
        Log.i(TAG, "VPN stopped");
    }

    // ── Packet Loop ───────────────────────────────────────────────────────────

    private void runVpnLoop() {
        FileInputStream  tunIn  = new FileInputStream(vpnInterface.getFileDescriptor());
        FileOutputStream tunOut = new FileOutputStream(vpnInterface.getFileDescriptor());

        byte[]     buf = new byte[32767];
        ByteBuffer pkt = ByteBuffer.wrap(buf);

        while (isRunning && !Thread.currentThread().isInterrupted()) {
            try {
                pkt.clear();
                int length = tunIn.read(buf);
                if (length <= 0) continue;

                // ── Parse IPv4 header ──
                if (length < 20) continue;
                int ipVersion = (buf[0] >> 4) & 0xF;
                if (ipVersion != 4) continue;

                int protocol = buf[9] & 0xFF;
                if (protocol != 17) continue;              // UDP only

                int ipHeaderLen = (buf[0] & 0x0F) * 4;
                if (length < ipHeaderLen + 8) continue;

                // ── Parse UDP header ──
                int dstPort = ((buf[ipHeaderLen + 2] & 0xFF) << 8)
                        | (buf[ipHeaderLen + 3] & 0xFF);

                if (dstPort != DNS_PORT) continue;         // DNS only

                // ── Extract DNS payload ──
                int dnsOffset = ipHeaderLen + 8;
                int dnsLen    = length - dnsOffset;
                if (dnsLen <= 0) continue;

                byte[] dnsQuery = new byte[dnsLen];
                System.arraycopy(buf, dnsOffset, dnsQuery, 0, dnsLen);

                // ── Check blocklist ──
                String domain = parseDnsQueryDomain(dnsQuery);
                Log.d(TAG, "DNS query: " + domain);

                byte[] dnsResponse;

                if (domain != null && BlockedDomains.isBlocked(domain)) {
                    Log.i(TAG, "BLOCKED: " + domain);
                    dnsResponse = buildBlockedDnsResponse(dnsQuery);
                } else {
                    // Forward to AdGuard Family DNS (with fallback)
                    dnsResponse = forwardToRealDns(dnsQuery);
                }

                if (dnsResponse == null) continue;

                byte[] reply = wrapInIpUdp(buf, ipHeaderLen, dnsResponse);
                if (reply != null) {
                    tunOut.write(reply);
                }

            } catch (Exception e) {
                if (isRunning) {
                    Log.e(TAG, "VPN loop error: " + e.getMessage());
                }
            }
        }

        Log.i(TAG, "VPN loop exited");
    }

    // ── DNS Helpers ───────────────────────────────────────────────────────────

    private String parseDnsQueryDomain(byte[] dns) {
        try {
            if (dns.length < 13) return null;
            int pos = 12;
            StringBuilder sb = new StringBuilder();

            while (pos < dns.length) {
                int labelLen = dns[pos] & 0xFF;
                if (labelLen == 0) break;
                if ((labelLen & 0xC0) == 0xC0) break;
                if (sb.length() > 0) sb.append('.');
                pos++;
                for (int i = 0; i < labelLen; i++, pos++) {
                    if (pos >= dns.length) break;
                    sb.append((char) dns[pos]);
                }
            }
            return sb.length() > 0 ? sb.toString().toLowerCase() : null;

        } catch (Exception e) {
            return null;
        }
    }

    private byte[] buildBlockedDnsResponse(byte[] query) {
        byte[] resp = new byte[query.length + 16];
        System.arraycopy(query, 0, resp, 0, query.length);

        resp[2] = (byte) 0x84; // QR=1, AA=1
        resp[3] = (byte) 0x00;
        resp[6] = 0x00;
        resp[7] = 0x01;        // answer count = 1

        int o = query.length;
        resp[o++] = (byte) 0xC0; resp[o++] = 0x0C;
        resp[o++] = 0x00; resp[o++] = 0x01;   // type A
        resp[o++] = 0x00; resp[o++] = 0x01;   // class IN
        resp[o++] = 0x00; resp[o++] = 0x00;
        resp[o++] = 0x00; resp[o++] = 0x3C;   // TTL 60s
        resp[o++] = 0x00; resp[o++] = 0x04;   // RDLENGTH = 4
        resp[o++] = 0x00; resp[o++] = 0x00;   // 0.0.0.0
        resp[o++] = 0x00; resp[o]   = 0x00;

        return resp;
    }

    /** Forward to primary AdGuard DNS; falls back to secondary on failure. */
    private byte[] forwardToRealDns(byte[] query) {
        byte[] result = queryDns(query, PRIMARY_DNS);
        if (result == null) {
            Log.w(TAG, "Primary DNS failed, trying secondary");
            result = queryDns(query, SECONDARY_DNS);
        }
        return result;
    }

    private byte[] queryDns(byte[] query, String serverIp) {
        DatagramSocket sock = null;
        try {
            sock = new DatagramSocket();
            protect(sock); // bypass VPN tunnel

            InetAddress server = InetAddress.getByName(serverIp);
            sock.send(new DatagramPacket(query, query.length, server, DNS_PORT));
            sock.setSoTimeout(3000);

            byte[] respBuf = new byte[4096];
            DatagramPacket respPkt = new DatagramPacket(respBuf, respBuf.length);
            sock.receive(respPkt);

            byte[] result = new byte[respPkt.getLength()];
            System.arraycopy(respBuf, 0, result, 0, result.length);
            return result;

        } catch (Exception e) {
            Log.e(TAG, "DNS query to " + serverIp + " failed: " + e.getMessage());
            return null;
        } finally {
            if (sock != null) sock.close();
        }
    }

    // ── Packet Building ───────────────────────────────────────────────────────

    private byte[] wrapInIpUdp(byte[] origPacket, int ipHeaderLen, byte[] dnsPayload) {
        try {
            int udpLen   = 8 + dnsPayload.length;
            int totalLen = ipHeaderLen + udpLen;
            byte[] pkt   = new byte[totalLen];

            System.arraycopy(origPacket, 0, pkt, 0, ipHeaderLen);

            pkt[2] = (byte) (totalLen >> 8);
            pkt[3] = (byte) (totalLen & 0xFF);

            // Swap src ↔ dst IP
            System.arraycopy(origPacket, 16, pkt, 12, 4);
            System.arraycopy(origPacket, 12, pkt, 16, 4);

            // Recompute IP checksum
            pkt[10] = 0; pkt[11] = 0;
            int ipCsum = ipChecksum(pkt, ipHeaderLen);
            pkt[10] = (byte) (ipCsum >> 8);
            pkt[11] = (byte) (ipCsum & 0xFF);

            // Swap src ↔ dst UDP ports
            int origSrcPort = ((origPacket[ipHeaderLen]     & 0xFF) << 8)
                    | (origPacket[ipHeaderLen + 1]  & 0xFF);
            int origDstPort = ((origPacket[ipHeaderLen + 2] & 0xFF) << 8)
                    | (origPacket[ipHeaderLen + 3]  & 0xFF);

            pkt[ipHeaderLen]     = (byte) (origDstPort >> 8);
            pkt[ipHeaderLen + 1] = (byte) (origDstPort & 0xFF);
            pkt[ipHeaderLen + 2] = (byte) (origSrcPort >> 8);
            pkt[ipHeaderLen + 3] = (byte) (origSrcPort & 0xFF);
            pkt[ipHeaderLen + 4] = (byte) (udpLen >> 8);
            pkt[ipHeaderLen + 5] = (byte) (udpLen & 0xFF);
            pkt[ipHeaderLen + 6] = 0;
            pkt[ipHeaderLen + 7] = 0;

            System.arraycopy(dnsPayload, 0, pkt, ipHeaderLen + 8, dnsPayload.length);

            return pkt;

        } catch (Exception e) {
            Log.e(TAG, "Packet wrap error: " + e.getMessage());
            return null;
        }
    }

    private int ipChecksum(byte[] hdr, int len) {
        int sum = 0;
        for (int i = 0; i < len - 1; i += 2) {
            sum += ((hdr[i] & 0xFF) << 8) | (hdr[i + 1] & 0xFF);
        }
        if ((len & 1) != 0) sum += (hdr[len - 1] & 0xFF) << 8;
        while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        return ~sum & 0xFFFF;
    }

    // ── Notification ──────────────────────────────────────────────────────────

    private Notification buildNotification() {
        createNotificationChannel();

        Intent stopIntent = new Intent(this, BlockerVpnService.class);
        stopIntent.setAction(ACTION_STOP);
        PendingIntent stopPending = PendingIntent.getService(
                this, 0, stopIntent, PendingIntent.FLAG_IMMUTABLE);

        Intent mainIntent = new Intent(this, MainActivity.class);
        PendingIntent mainPending = PendingIntent.getActivity(
                this, 0, mainIntent, PendingIntent.FLAG_IMMUTABLE);

        return new NotificationCompat.Builder(this, CHANNEL_ID)
                .setContentTitle("AlifBlocker Active")
                .setContentText("Protected by AdGuard Family DNS")
                .setSmallIcon(R.drawable.ic_shield)
                .setContentIntent(mainPending)
                .addAction(R.drawable.ic_stop, "Stop", stopPending)
                .setOngoing(true)
                .setPriority(NotificationCompat.PRIORITY_MIN)
                .setSilent(true)
                .build();
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel ch = new NotificationChannel(
                    CHANNEL_ID, "AlifBlocker", NotificationManager.IMPORTANCE_MIN);
            ch.setDescription("DNS-based content blocker");
            ch.setShowBadge(false);
            NotificationManager nm = getSystemService(NotificationManager.class);
            if (nm != null) nm.createNotificationChannel(ch);
        }
    }

    public static boolean isRunning() {
        return isRunning;
    }
}