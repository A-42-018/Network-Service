package com.alifblocker.data;

import android.content.Context;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Master blocklist — DNS-based blocking.
 *
 * Layers of blocking:
 *  1. Hardcoded core list (always present, works offline)
 *  2. DoH provider domains (stops browsers bypassing via encrypted DNS)
 *  3. Downloaded hosts list from Steven Black (70,000+ adult domains)
 *     — cached to disk, refreshed weekly
 */
public class BlockedDomains {

    private static final String TAG = "BlockedDomains";

    // Cached blocklist file name (saved in app's internal storage)
    private static final String CACHE_FILE       = "blocklist_cache.txt";
    private static final long   UPDATE_INTERVAL_MS = 7L * 24 * 60 * 60 * 1000; // 7 days

    // Steven Black porn-only hosts list — 70,000+ domains, updated daily
    private static final String HOSTS_URL =
            "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn/hosts";

    // ── Hardcoded core list ───────────────────────────────────────────────────
    private static final String[] BLOCKED_LIST = {

            // ── DoH providers — block so browsers can't bypass our DNS ──
            // (Chrome, Firefox, Edge use these for encrypted DNS over HTTPS)
            "dns.google",
            "dns64.dns.google",
            "cloudflare-dns.com",
            "1dot1dot1dot1.cloudflare-dns.com",
            "doh.opendns.com",
            "doh.cleanbrowsing.org",
            "dns.nextdns.io",
            "doh.familyshield.opendns.com",
            "mozilla.cloudflare-dns.com",
            "firefox.settings.services.mozilla.com",
            "chrome.cloudflare-dns.com",
            "doh.dns.apple.com",
            "doh.sb",
            "dns.quad9.net",
            "dns11.quad9.net",
            "dns.adguard.com",
            "dns-unfiltered.adguard.com",

            // ── Major adult platforms ──
            "pornhub.com", "www.pornhub.com", "rt.pornhub.com", "de.pornhub.com",
            "xvideos.com", "www.xvideos.com", "xvideos2.com",
            "xnxx.com", "www.xnxx.com",
            "xhamster.com", "www.xhamster.com", "xhamster2.com", "xhamster3.com",
            "redtube.com", "www.redtube.com",
            "youporn.com", "www.youporn.com",
            "tube8.com", "www.tube8.com",
            "spankbang.com", "www.spankbang.com", "spankbang.party",
            "eporner.com", "www.eporner.com",
            "porntrex.com", "www.porntrex.com",
            "txxx.com", "www.txxx.com",
            "hclips.com", "www.hclips.com",
            "drtuber.com", "www.drtuber.com",
            "tnaflix.com", "www.tnaflix.com",
            "fuq.com", "www.fuq.com",
            "hdtube.porn",
            "hotmovs.com", "www.hotmovs.com",
            "nudevista.com",
            "motherless.com", "www.motherless.com",
            "4tube.com", "www.4tube.com",
            "nuvid.com", "www.nuvid.com",
            "beeg.com", "www.beeg.com",
            "thumbzilla.com", "www.thumbzilla.com",
            "keezmovies.com", "www.keezmovies.com",
            "porntube.com", "www.porntube.com",
            "fux.com", "www.fux.com",
            "slutload.com", "www.slutload.com",
            "ashemaletube.com",
            "shemale.xxx",
            "trannytube.tv",

            // ── Cam sites ──
            "cam4.com", "www.cam4.com",
            "chaturbate.com", "www.chaturbate.com",
            "livejasmin.com", "www.livejasmin.com",
            "myfreecams.com", "www.myfreecams.com",
            "bongacams.com", "www.bongacams.com",
            "stripchat.com", "www.stripchat.com",
            "camsoda.com", "www.camsoda.com",
            "flirt4free.com",
            "imlive.com",
            "streamate.com",
            "jerkmate.com",
            "camsoda.com",
            "camster.com",
            "amateur.tv",
            "camonster.com",
            "xcams.com",

            // ── Creator platforms ──
            "onlyfans.com", "www.onlyfans.com",
            "fansly.com", "www.fansly.com",
            "manyvids.com",
            "clips4sale.com",
            "loyalfans.com",
            "fancentro.com",
            "justfor.fans",
            "admireme.vip",

            // ── Studios ──
            "naughtyamerica.com", "www.naughtyamerica.com",
            "brazzers.com", "www.brazzers.com",
            "bangbros.com", "www.bangbros.com",
            "realitykings.com", "www.realitykings.com",
            "mofos.com", "www.mofos.com",
            "digitalplayground.com",
            "wicked.com",
            "vivid.com",
            "hustler.com", "www.hustler.com",
            "penthouse.com", "www.penthouse.com",
            "playboy.com", "www.playboy.com",
            "privatecastle.com",
            "sexart.com",
            "hegre.com",
            "met-art.com",
            "femjoy.com",

            // ── General adult ──
            "pornmd.com",
            "porn.com", "www.porn.com",
            "sex.com", "www.sex.com",
            "adult.com",
            "adultfriendfinder.com", "www.adultfriendfinder.com",
            "ashleymadison.com", "www.ashleymadison.com",
            "fetlife.com", "www.fetlife.com",
            "xtube.com", "www.xtube.com",
            "porndig.com",
            "pornzog.com",
            "sexvid.xxx",
            "fapster.xxx",
            "3movs.com",
            "tukif.com",
            "cliphunter.com",
            "sunporno.com",
            "shesfreaky.com",
            "gaytube.com",
            "gay.com",
            "men.com",
            "manhunt.net",
            "hentaihaven.xxx",
            "nhentai.net", "www.nhentai.net",
            "hentai.tv",
            "rule34.xxx",
            "rule34.paheal.net",
            "gelbooru.com",
            "danbooru.donmai.us",
            "e621.net",
            "xgroovy.com",
            "freeones.com",
            "babepedia.com",
            "poringa.net",
            "pinkrod.com",
            "porn300.com",
            "eroprofile.com",
            "sexu.com",
            "xxxbunker.com",
            "pornicom.com",
            "xxxdan.com",
            "empflix.com",
            "netfapx.com",
            "iporntv.net",
            "watchmygf.me",
            "homemoviestube.com",
            "anysex.com",
            "pornone.com",
            "sleazyneasy.com",
            "gotporn.com",
            "sextvx.com",
            "vidoza.net",
            "vidzz.net",
            "fapvideos.com",
            "fapality.com",
            "fapvid.com",
            "faphouse.com",
            "pornktube.com",
            "vjav.com",
            "javhd.com",
            "javmost.com",
            "jav.guru",
            "avgle.com",
            "javfull.net",
            "missav.com",

            // ── Adult ad networks ──
            "exoclick.com",
            "trafficjunky.com",
            "juicyads.com",
            "ero-advertising.com",
            "adxxx.com",
            "plugrush.com",
            "adultadworld.com",
            "reporo.com",
            "cpmrevenue.com",
            "hilltopads.net",
            "etargetnet.com",
            "adspyglass.com",
            "pornvertiser.com",
            "tsyndicate.com"
    };

    private static Set<String> blockedSet = null;

    // ── Public API ────────────────────────────────────────────────────────────

    public static Set<String> getBlockedDomains() {
        if (blockedSet == null) {
            blockedSet = new HashSet<>(Arrays.asList(BLOCKED_LIST));
        }
        return blockedSet;
    }

    /**
     * Check if a hostname should be blocked.
     * Handles subdomains by walking up the domain tree.
     */
    public static boolean isBlocked(String hostname) {
        if (hostname == null || hostname.isEmpty()) return false;
        hostname = hostname.toLowerCase().trim();

        // Strip trailing dot (some DNS queries include it)
        if (hostname.endsWith(".")) hostname = hostname.substring(0, hostname.length() - 1);

        Set<String> blocked = getBlockedDomains();

        // Direct match
        if (blocked.contains(hostname)) return true;

        // Walk up subdomains: sub.example.com → example.com → com
        int dot = hostname.indexOf('.');
        while (dot != -1) {
            String parent = hostname.substring(dot + 1);
            if (blocked.contains(parent)) return true;
            dot = hostname.indexOf('.', dot + 1);
        }

        return false;
    }

    /** Add a custom domain to the runtime blocklist. */
    public static void addCustomDomain(String domain) {
        getBlockedDomains().add(domain.toLowerCase().trim());
    }

    /** Remove a domain from the runtime blocklist. */
    public static void removeCustomDomain(String domain) {
        getBlockedDomains().remove(domain.toLowerCase().trim());
    }

    /** Total number of blocked domains. */
    public static int getCount() {
        return getBlockedDomains().size();
    }

    // ── Hosts file loader ─────────────────────────────────────────────────────

    /**
     * Parse and load a hosts-file-format string into the blocklist.
     * Handles both:
     *   "0.0.0.0 domain.com"  (hosts format)
     *   "domain.com"          (plain list format)
     */
    public static void loadFromHostsContent(String content) {
        if (content == null || content.isEmpty()) return;
        Set<String> blocked = getBlockedDomains();
        int added = 0;
        for (String line : content.split("\n")) {
            line = line.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;

            // Remove inline comments
            int commentIdx = line.indexOf('#');
            if (commentIdx > 0) line = line.substring(0, commentIdx).trim();

            String[] parts = line.split("\\s+");
            String domain = parts.length > 1 ? parts[1] : parts[0];

            // Skip loopback / placeholder IPs
            if (domain.equals("0.0.0.0") || domain.equals("127.0.0.1")
                    || domain.equals("localhost") || !domain.contains(".")) continue;

            blocked.add(domain.toLowerCase());
            added++;
        }
        Log.i(TAG, "Loaded " + added + " domains from hosts content. Total: " + blocked.size());
    }

    // ── Disk cache + network update ───────────────────────────────────────────

    /**
     * Call once at startup (in a background thread).
     * Loads cached list from disk immediately, then downloads a fresh
     * copy if the cache is older than UPDATE_INTERVAL_MS (7 days).
     */
    public static void initializeWithContext(Context context) {
        File cacheFile = new File(context.getFilesDir(), CACHE_FILE);

        // 1. Load whatever is cached on disk right now (fast, works offline)
        if (cacheFile.exists()) {
            loadFromDisk(cacheFile);
        }

        // 2. Check if we need a fresh download
        boolean needsUpdate = !cacheFile.exists()
                || (System.currentTimeMillis() - cacheFile.lastModified()) > UPDATE_INTERVAL_MS;

        if (needsUpdate) {
            // Download in background — doesn't block startup
            new Thread(() -> downloadAndCache(context, cacheFile),
                    "BlocklistUpdater").start();
        }
    }

    /** Load the cached hosts file from internal storage into the blocklist. */
    private static void loadFromDisk(File file) {
        try {
            StringBuilder sb = new StringBuilder();
            BufferedReader reader = new BufferedReader(new FileReader(file));
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line).append("\n");
            }
            reader.close();
            loadFromHostsContent(sb.toString());
            Log.i(TAG, "Loaded blocklist from disk cache: " + file.length() + " bytes");
        } catch (Exception e) {
            Log.e(TAG, "Failed to load disk cache: " + e.getMessage());
        }
    }

    /** Download fresh hosts list, load it, and save to disk cache. */
    private static void downloadAndCache(Context context, File cacheFile) {
        Log.i(TAG, "Downloading fresh blocklist from: " + HOSTS_URL);
        try {
            HttpURLConnection conn = (HttpURLConnection) new URL(HOSTS_URL).openConnection();
            conn.setConnectTimeout(15000);
            conn.setReadTimeout(30000);
            conn.setRequestProperty("User-Agent", "AlifBlocker/1.0");

            if (conn.getResponseCode() != 200) {
                Log.w(TAG, "Download failed: HTTP " + conn.getResponseCode());
                return;
            }

            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(conn.getInputStream()));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line).append("\n");
            }
            reader.close();
            conn.disconnect();

            String content = sb.toString();

            // Load into memory
            loadFromHostsContent(content);

            // Save to disk cache
            FileWriter writer = new FileWriter(cacheFile);
            writer.write(content);
            writer.close();

            Log.i(TAG, "Blocklist downloaded and cached. Total domains: " + getCount());

        } catch (Exception e) {
            Log.e(TAG, "Download error: " + e.getMessage());
        }
    }

    /**
     * Force a fresh download immediately (call from a background thread).
     * Useful for a manual "Update Blocklist" button in the UI.
     */
    public static void forceUpdate(Context context) {
        File cacheFile = new File(context.getFilesDir(), CACHE_FILE);
        downloadAndCache(context, cacheFile);
    }
}