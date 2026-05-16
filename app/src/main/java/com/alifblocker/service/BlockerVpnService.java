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
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

/**
 * Local VPN Service that intercepts DNS queries (UDP port 53)
 * and returns NXDOMAIN (or 0.0.0.0) for blocked adult domains.
 *
 * How it works:
 *  1. Creates a local TUN interface via Android VpnService API.
 *  2. All device traffic is routed through this TUN interface.
 *  3. We read UDP packets destined for port 53 (DNS).
 *  4. We parse the DNS query to extract the queried hostname.
 *  5. If hostname matches our blocklist → reply with 0.0.0.0 (blocked).
 *  6. Otherwise → forward to real DNS server (8.8.8.8) and relay the response.
 */
public class BlockerVpnService extends VpnService {

    private static final String TAG = "BlockerVPN";
    private static final String CHANNEL_ID = "blocker_vpn_channel";
    private static final int NOTIFICATION_ID = 1;

    public static final String ACTION_START = "START_VPN";
    public static final String ACTION_STOP = "STOP_VPN";

    private static boolean isRunning = false;

    private ParcelFileDescriptor vpnInterface;
    private Thread vpnThread;
    private Thread httpThread;
    private ServerSocket httpServer;

    // Real DNS upstream
    private static final String UPSTREAM_DNS = "8.8.8.8";
    private static final int DNS_PORT = 53;

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

    private void startVpn() {
        if (isRunning) return;

        try {
            Builder builder = new Builder();
            builder.setSession("Network Service")
                   .addAddress("10.0.0.2", 32)          // TUN virtual IP
                   .addRoute("0.0.0.0", 0)               // All traffic
                   .addDnsServer("10.0.0.1")             // Use our fake DNS
                   .setMtu(1500)
                   .addDisallowedApplication(getPackageName()); // Don't route our own traffic

            vpnInterface = builder.establish();

            if (vpnInterface == null) {
                Log.e(TAG, "Failed to establish VPN interface");
                return;
            }

            isRunning = true;

            vpnThread = new Thread(this::runVpnLoop, "VpnThread");
            vpnThread.start();

            startHttpServer();

            Log.i(TAG, "VPN started successfully");

        } catch (Exception e) {
            Log.e(TAG, "VPN start error: " + e.getMessage(), e);
        }
    }

    /**
     * Main VPN loop: reads packets from TUN, processes DNS, forwards rest.
     */
    private void runVpnLoop() {
        FileInputStream in = new FileInputStream(vpnInterface.getFileDescriptor());
        FileOutputStream out = new FileOutputStream(vpnInterface.getFileDescriptor());

        ByteBuffer packet = ByteBuffer.allocate(32767);

        while (isRunning && !Thread.interrupted()) {
            try {
                packet.clear();
                int length = in.read(packet.array());
                if (length <= 0) continue;

                packet.limit(length);

                // Parse IP header version
                int ipVersion = (packet.get(0) >> 4) & 0xF;
                if (ipVersion != 4) continue; // Only handle IPv4

                // Protocol field at byte 9
                int protocol = packet.get(9) & 0xFF;
                if (protocol != 17) continue; // Only UDP (17)

                // IP header length
                int ipHeaderLen = (packet.get(0) & 0x0F) * 4;

                // Source/dest ports in UDP header
                int srcPort = ((packet.get(ipHeaderLen) & 0xFF) << 8) | (packet.get(ipHeaderLen + 1) & 0xFF);
                int dstPort = ((packet.get(ipHeaderLen + 2) & 0xFF) << 8) | (packet.get(ipHeaderLen + 3) & 0xFF);

                if (dstPort != 53 && srcPort != 53) continue; // Only DNS packets

                if (dstPort == DNS_PORT) {
                    // Outgoing DNS query
                    int udpDataOffset = ipHeaderLen + 8;
                    int udpDataLen = length - udpDataOffset;

                    if (udpDataLen <= 0) continue;

                    byte[] dnsData = new byte[udpDataLen];
                    System.arraycopy(packet.array(), udpDataOffset, dnsData, 0, udpDataLen);

                    String queriedDomain = parseDnsQuery(dnsData);
                    Log.d(TAG, "DNS Query: " + queriedDomain);

                    if (queriedDomain != null && BlockedDomains.isBlocked(queriedDomain)) {
                        Log.i(TAG, "BLOCKED: " + queriedDomain);
                        // Send blocked DNS response (0.0.0.0)
                        byte[] blockedResponse = buildBlockedDnsResponse(dnsData);
                        byte[] fullPacket = buildUdpIpPacket(
                            packet.array(), ipHeaderLen, blockedResponse, length
                        );
                        if (fullPacket != null) {
                            out.write(fullPacket);
                        }
                    } else {
                        // Forward to real DNS
                        byte[] response = forwardDnsQuery(dnsData);
                        if (response != null) {
                            byte[] fullPacket = buildUdpIpPacket(
                                packet.array(), ipHeaderLen, response, length
                            );
                            if (fullPacket != null) {
                                out.write(fullPacket);
                            }
                        }
                    }
                }

            } catch (Exception e) {
                if (isRunning) {
                    Log.e(TAG, "VPN loop error: " + e.getMessage());
                }
            }
        }
    }

    /**
     * Parse the queried domain name from a raw DNS query byte array.
     */
    private String parseDnsQuery(byte[] dns) {
        try {
            // DNS query question section starts at byte 12
            int pos = 12;
            StringBuilder domain = new StringBuilder();

            while (pos < dns.length) {
                int labelLen = dns[pos] & 0xFF;
                if (labelLen == 0) break;
                if (domain.length() > 0) domain.append('.');
                pos++;
                for (int i = 0; i < labelLen && pos < dns.length; i++, pos++) {
                    domain.append((char) dns[pos]);
                }
            }
            return domain.toString().toLowerCase();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Build a DNS response that returns 0.0.0.0 (blocked).
     */
    private byte[] buildBlockedDnsResponse(byte[] query) {
        // Response = original query + answer section with 0.0.0.0
        // Copy query, set QR=1 (response), RCODE=0, add answer
        byte[] response = new byte[query.length + 16];
        System.arraycopy(query, 0, response, 0, query.length);

        // Flags: QR=1, AA=1, RCODE=0 → 0x8400
        response[2] = (byte) 0x84;
        response[3] = (byte) 0x00;

        // Answer count = 1
        response[6] = 0x00;
        response[7] = 0x01;

        int offset = query.length;

        // Answer: pointer to name (0xC00C = pointer to offset 12)
        response[offset++] = (byte) 0xC0;
        response[offset++] = 0x0C;

        // Type A (0x0001)
        response[offset++] = 0x00;
        response[offset++] = 0x01;

        // Class IN (0x0001)
        response[offset++] = 0x00;
        response[offset++] = 0x01;

        // TTL = 60 seconds
        response[offset++] = 0x00;
        response[offset++] = 0x00;
        response[offset++] = 0x00;
        response[offset++] = 0x3C;

        // RDLENGTH = 4
        response[offset++] = 0x00;
        response[offset++] = 0x04;

        // RDATA = 127.0.0.1
        response[offset++] = 0x7F;
        response[offset++] = 0x00;
        response[offset++] = 0x00;
        response[offset] = 0x01;

        return response;
    }

    /**
     * Forward DNS query to upstream (8.8.8.8) and return the response.
     */
    private byte[] forwardDnsQuery(byte[] query) {
        try {
            DatagramSocket socket = new DatagramSocket();
            protect(socket); // Exclude from VPN so it goes to real network

            InetAddress dnsServer = InetAddress.getByName(UPSTREAM_DNS);
            DatagramPacket requestPacket = new DatagramPacket(query, query.length, dnsServer, DNS_PORT);
            socket.setSoTimeout(3000);
            socket.send(requestPacket);

            byte[] responseBuffer = new byte[4096];
            DatagramPacket responsePacket = new DatagramPacket(responseBuffer, responseBuffer.length);
            socket.receive(responsePacket);
            socket.close();

            byte[] response = new byte[responsePacket.getLength()];
            System.arraycopy(responseBuffer, 0, response, 0, responsePacket.getLength());
            return response;

        } catch (Exception e) {
            Log.e(TAG, "DNS forward error: " + e.getMessage());
            return null;
        }
    }

    /**
     * Wrap a DNS response in a proper IP+UDP packet to write back to TUN.
     */
    private byte[] buildUdpIpPacket(byte[] originalPacket, int ipHeaderLen, byte[] dnsPayload, int origLen) {
        try {
            int udpLen = 8 + dnsPayload.length;
            int totalLen = ipHeaderLen + udpLen;

            byte[] packet = new byte[totalLen];

            // Copy IP header from original (swapping src/dst)
            System.arraycopy(originalPacket, 0, packet, 0, ipHeaderLen);

            // Swap source and destination IP
            byte[] srcIp = new byte[4];
            byte[] dstIp = new byte[4];
            System.arraycopy(originalPacket, 12, srcIp, 0, 4);
            System.arraycopy(originalPacket, 16, dstIp, 0, 4);
            System.arraycopy(dstIp, 0, packet, 12, 4); // new src = original dst
            System.arraycopy(srcIp, 0, packet, 16, 4); // new dst = original src

            // Update total length
            packet[2] = (byte) (totalLen >> 8);
            packet[3] = (byte) (totalLen & 0xFF);

            // UDP header
            int origSrcPort = ((originalPacket[ipHeaderLen] & 0xFF) << 8) | (originalPacket[ipHeaderLen + 1] & 0xFF);
            int origDstPort = ((originalPacket[ipHeaderLen + 2] & 0xFF) << 8) | (originalPacket[ipHeaderLen + 3] & 0xFF);

            // Swap ports
            packet[ipHeaderLen]     = (byte) (origDstPort >> 8);
            packet[ipHeaderLen + 1] = (byte) (origDstPort & 0xFF);
            packet[ipHeaderLen + 2] = (byte) (origSrcPort >> 8);
            packet[ipHeaderLen + 3] = (byte) (origSrcPort & 0xFF);

            // UDP length
            packet[ipHeaderLen + 4] = (byte) (udpLen >> 8);
            packet[ipHeaderLen + 5] = (byte) (udpLen & 0xFF);

            // UDP checksum (0 = disabled for IPv4)
            packet[ipHeaderLen + 6] = 0;
            packet[ipHeaderLen + 7] = 0;

            // DNS payload
            System.arraycopy(dnsPayload, 0, packet, ipHeaderLen + 8, dnsPayload.length);

            // Recalculate IP checksum
            packet[10] = 0;
            packet[11] = 0;
            int checksum = computeIpChecksum(packet, ipHeaderLen);
            packet[10] = (byte) (checksum >> 8);
            packet[11] = (byte) (checksum & 0xFF);

            return packet;

        } catch (Exception e) {
            Log.e(TAG, "Packet build error: " + e.getMessage());
            return null;
        }
    }

    private int computeIpChecksum(byte[] header, int length) {
        int sum = 0;
        for (int i = 0; i < length; i += 2) {
            int word = ((header[i] & 0xFF) << 8);
            if (i + 1 < length) word |= (header[i + 1] & 0xFF);
            sum += word;
        }
        while ((sum >> 16) != 0) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        return ~sum & 0xFFFF;
    }

    private void stopVpn() {
        isRunning = false;
        if (vpnThread != null) vpnThread.interrupt();
        stopHttpServer();
        try {
            if (vpnInterface != null) vpnInterface.close();
        } catch (Exception e) {
            Log.e(TAG, "Error closing VPN: " + e.getMessage());
        }
        stopForeground(true);
        stopSelf();
    }

    private Notification buildNotification() {
        createNotificationChannel();

        Intent stopIntent = new Intent(this, BlockerVpnService.class);
        stopIntent.setAction(ACTION_STOP);
        PendingIntent stopPending = PendingIntent.getService(this, 0, stopIntent,
            PendingIntent.FLAG_IMMUTABLE);

        Intent mainIntent = new Intent(this, MainActivity.class);
        PendingIntent mainPending = PendingIntent.getActivity(this, 0, mainIntent,
            PendingIntent.FLAG_IMMUTABLE);

        return new NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Network Service")
            .setContentText("Running in background")
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
            NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID,
                "Network Service",
                NotificationManager.IMPORTANCE_MIN
            );
            channel.setDescription("Background network service");
            channel.setShowBadge(false);
            NotificationManager nm = getSystemService(NotificationManager.class);
            if (nm != null) nm.createNotificationChannel(channel);
        }
    }

    public static boolean isRunning() {
        return isRunning;
    }

    private void startHttpServer() {
        httpThread = new Thread(() -> {
            try {
                httpServer = new ServerSocket(80, 10, InetAddress.getByName("127.0.0.1"));
                while (isRunning && !Thread.interrupted()) {
                    try {
                        Socket client = httpServer.accept();
                        new Thread(() -> handleHttpRequest(client)).start();
                    } catch (Exception e) {
                        if (isRunning) Log.e(TAG, "HTTP accept error: " + e.getMessage());
                    }
                }
            } catch (Exception e) {
                Log.e(TAG, "HTTP server error: " + e.getMessage());
            }
        }, "HttpThread");
        httpThread.start();
    }

    private void handleHttpRequest(Socket client) {
        try {
            client.setSoTimeout(3000);
            java.io.InputStream in = client.getInputStream();
            OutputStream out = client.getOutputStream();

            byte[] buf = new byte[4096];
            int len = in.read(buf);
            if (len <= 0) { client.close(); return; }

            String request = new String(buf, 0, len, StandardCharsets.UTF_8);
            String host = extractHost(request);

            String body = "<!DOCTYPE html><html><head>"
                + "<meta charset='UTF-8'>"
                + "<meta name='viewport' content='width=device-width,initial-scale=1'>"
                + "<title>Access Blocked</title>"
                + "<style>"
                + "*{margin:0;padding:0;box-sizing:border-box}"
                + "body{background:#0D0D0D;color:#fff;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;text-align:center;padding:20px}"
                + ".card{max-width:400px}"
                + "h1{font-size:64px;margin-bottom:16px}"
                + "h2{font-size:24px;color:#FF5252;margin-bottom:8px}"
                + "p{color:#AAA;font-size:14px;margin-bottom:8px}"
                + ".domain{color:#FF5252;font-weight:bold;word-break:break-all}"
                + "</style></head><body>"
                + "<div class='card'>"
                + "<h1>🚫</h1>"
                + "<h2>Access Blocked</h2>"
                + "<p class='domain'>" + (host != null ? host : "this website") + "</p>"
                + "<p>This site has been blocked.</p>"
                + "</div></body></html>";

            byte[] bodyBytes = body.getBytes(StandardCharsets.UTF_8);
            String response = "HTTP/1.1 200 OK\r\n"
                + "Content-Type: text/html; charset=utf-8\r\n"
                + "Content-Length: " + bodyBytes.length + "\r\n"
                + "Connection: close\r\n"
                + "\r\n";

            out.write(response.getBytes(StandardCharsets.UTF_8));
            out.write(bodyBytes);
            out.flush();
            client.close();
        } catch (Exception e) {
            try { client.close(); } catch (Exception ignored) {}
        }
    }

    private String extractHost(String httpRequest) {
        for (String line : httpRequest.split("\r\n")) {
            if (line.toLowerCase().startsWith("host:")) {
                String host = line.substring(5).trim();
                int portIdx = host.indexOf(':');
                return portIdx > 0 ? host.substring(0, portIdx) : host;
            }
        }
        return null;
    }

    private void stopHttpServer() {
        try {
            if (httpServer != null) httpServer.close();
        } catch (Exception e) {
            Log.e(TAG, "Error closing HTTP server: " + e.getMessage());
        }
        if (httpThread != null) httpThread.interrupt();
    }

    @Override
    public void onDestroy() {
        stopVpn();
        super.onDestroy();
    }
}
