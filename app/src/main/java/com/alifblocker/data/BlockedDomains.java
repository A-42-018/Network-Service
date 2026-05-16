package com.alifblocker.data;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Master blocklist of adult/porn domains.
 * Uses DNS-based blocking via VPN local resolver.
 */
public class BlockedDomains {

    // Core adult site domains (TLDs and common subdomains)
    private static final String[] BLOCKED_LIST = {
        // Major adult platforms
        "pornhub.com", "www.pornhub.com", "rt.pornhub.com",
        "xvideos.com", "www.xvideos.com",
        "xnxx.com", "www.xnxx.com",
        "xhamster.com", "www.xhamster.com",
        "redtube.com", "www.redtube.com",
        "youporn.com", "www.youporn.com",
        "tube8.com", "www.tube8.com",
        "spankbang.com", "www.spankbang.com",
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
        "onlyfans.com", "www.onlyfans.com",
        "fansly.com", "www.fansly.com",
        "manyvids.com",
        "clips4sale.com",
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
        "nudevistacom",
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
        // Ad networks associated with adult content
        "exoclick.com",
        "trafficjunky.com",
        "juicyads.com",
        "ero-advertising.com",
        "adxxx.com",
        "juicyads.com"
    };

    private static Set<String> blockedSet = null;

    public static Set<String> getBlockedDomains() {
        if (blockedSet == null) {
            blockedSet = new HashSet<>(Arrays.asList(BLOCKED_LIST));
        }
        return blockedSet;
    }

    /**
     * Check if a hostname should be blocked.
     * Handles subdomains by stripping and checking parent domain.
     */
    public static boolean isBlocked(String hostname) {
        if (hostname == null || hostname.isEmpty()) return false;
        hostname = hostname.toLowerCase().trim();

        Set<String> blocked = getBlockedDomains();

        // Direct match
        if (blocked.contains(hostname)) return true;

        // Strip leading www. and re-check
        if (hostname.startsWith("www.")) {
            String stripped = hostname.substring(4);
            if (blocked.contains(stripped)) return true;
        }

        // Check parent domain (subdomain match)
        int dotIndex = hostname.indexOf('.');
        while (dotIndex != -1) {
            String parent = hostname.substring(dotIndex + 1);
            if (blocked.contains(parent)) return true;
            dotIndex = hostname.indexOf('.', dotIndex + 1);
        }

        return false;
    }

    /** Add a custom domain to the blocklist at runtime */
    public static void addCustomDomain(String domain) {
        getBlockedDomains().add(domain.toLowerCase().trim());
    }

    /** Remove a domain from the blocklist */
    public static void removeCustomDomain(String domain) {
        getBlockedDomains().remove(domain.toLowerCase().trim());
    }

    public static int getCount() {
        return getBlockedDomains().size();
    }
}
