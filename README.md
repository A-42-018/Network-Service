# 🛡️ AdultBlocker — Android App

A DNS-based adult content blocker for Android using the **VpnService API**.  
Built for educational purposes by Alif, DIU SWE.

---

## 📱 Features

| Feature | Description |
|---|---|
| 🔒 DNS Blocking | Intercepts DNS queries via local VPN and blocks 100+ adult domains |
| ➕ Custom Domains | Add any domain to the blocklist manually |
| 🔑 Parental PIN Lock | Set a PIN so children can't disable the blocker |
| 🚀 Boot Auto-Start | Automatically restarts after device reboot |
| 🔔 Persistent Notification | Shows VPN is active with a quick-stop button |
| 📴 Works Everywhere | Blocks in all browsers AND apps (DNS-level) |

---

## 🏗️ Project Structure

```
AdultBlocker/
├── app/src/main/
│   ├── AndroidManifest.xml
│   ├── java/com/alifblocker/
│   │   ├── data/
│   │   │   └── BlockedDomains.java      ← Master blocklist + runtime add/remove
│   │   ├── service/
│   │   │   ├── BlockerVpnService.java   ← Core VPN DNS interceptor (main logic)
│   │   │   └── BootReceiver.java        ← Auto-restart on boot
│   │   └── ui/
│   │       ├── MainActivity.java        ← Main toggle + custom domain UI
│   │       ├── PinSetupActivity.java    ← Parental PIN management
│   │       └── BlockedActivity.java     ← "This site is blocked" screen
│   └── res/
│       ├── layout/                      ← All XML layouts
│       ├── values/                      ← Colors, themes, strings
│       └── drawable/                    ← Vector icons
├── build.gradle
└── settings.gradle
```

---

## ⚙️ How It Works (Technical)

```
User visits pornhub.com
        │
        ▼
Browser sends DNS query (UDP port 53)
        │
        ▼
Our VPN TUN interface intercepts the packet
        │
        ▼
BlockerVpnService reads the DNS query
        │
        ├─ Domain in blocklist? ──YES──► Return 0.0.0.0 (site unreachable)
        │
        └─ Not blocked? ──────────────► Forward to 8.8.8.8 (Google DNS)
                                         Return real IP to browser
```

**Key Android API used:** `android.net.VpnService`  
This is the same API used by apps like AdGuard, Blokada, and NextDNS.

---

## 🚀 How to Build & Run

### Requirements
- Android Studio Hedgehog (2023.1+)
- Android SDK 34
- Java 8+
- Physical device or emulator with API 24+

### Steps

1. **Clone / open the project** in Android Studio
2. **Sync Gradle** — it will download all dependencies
3. **Run on device:**  
   ```
   Run → Run 'app'
   ```
4. **Grant VPN permission** when the system dialog appears
5. **Toggle the switch** to activate blocking

### Build APK
```bash
./gradlew assembleRelease
# APK → app/build/outputs/apk/release/app-release-unsigned.apk
```

---

## 📦 Dependencies

```gradle
implementation 'androidx.appcompat:appcompat:1.6.1'
implementation 'com.google.android.material:material:1.11.0'
implementation 'androidx.constraintlayout:constraintlayout:2.1.4'
implementation 'androidx.room:room-runtime:2.6.1'      // For future DB blocklist
implementation 'androidx.work:work-runtime:2.9.0'      // For scheduled updates
```

---

## 🔐 Permissions Explained

| Permission | Why |
|---|---|
| `INTERNET` | Forward non-blocked DNS to 8.8.8.8 |
| `FOREGROUND_SERVICE` | Keep VPN alive in background |
| `RECEIVE_BOOT_COMPLETED` | Auto-start after reboot |
| `POST_NOTIFICATIONS` | Show "VPN active" notification |
| `BIND_VPN_SERVICE` | Required for VpnService API |

---

## 💡 How to Extend

### Add more blocked domains
Edit `BlockedDomains.java` and add entries to `BLOCKED_LIST[]`.

### Add subdomain wildcard blocking
The `isBlocked()` method already handles this — any subdomain of a blocked domain is also blocked.

### Integrate with a remote blocklist API
In `BlockerVpnService`, replace the hardcoded list with an HTTP fetch from:
- https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn/hosts
- https://oisd.nl (OISD blocklist)

### Add usage statistics
Use Room database to log `(timestamp, domain, blocked)` per DNS query.

---

## ⚠️ Notes

- This app uses a **local VPN** — no traffic is sent to any external server.
- DNS over HTTPS (DoH) in some browsers (e.g. Firefox) may bypass DNS blocking. To counter this, also block `mozilla.cloudflare-dns.com` and `dns.google`.
- For production use, consider integrating the [OISD blocklist](https://oisd.nl) which is updated daily.

---

## 👨‍💻 Author

**Alif** — SWE 2nd Year, Daffodil International University  
Built as a learning project on Android VpnService & DNS filtering.
