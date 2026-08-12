# WinARP Android

Android port of the Windows `winarp`: LAN scan + multi-thread ARP poisoning, with a clean Material 3 dark UI.

> **For CTF / authorized sandbox only.** Do not use on unauthorized networks.

## Feature parity

| Feature | Windows | Android |
|---------|---------|---------|
| NIC list | ✅ | ✅ Wi-Fi / NIC |
| LAN scan (IP/MAC/name) | ✅ | ✅ |
| Multi-select host attack | ✅ | ✅ |
| IP-range attack | ✅ | ✅ |
| Multi-thread concurrent poison | ✅ | ✅ coroutine concurrency |
| One-way poison | ✅ | ✅ |
| Stop & restore ARP | ✅ | ✅ |
| Native GUI | Win32 | Jetpack Compose |

## Permissions

- **Scan**: usually no root required. Uses neighbor probing + `/proc/net/arp`; with root it can do active AF_PACKET ARP probing.
- **Disruption / ARP poison**: requires **root**, to open an `AF_PACKET` raw socket and send ARP replies.

On Android 11+ the app process is denied several reads a LAN/ARP tool needs
(`NetworkInterface.getHardwareAddress()` returns null, `/proc/net/arp` is
unreadable, `AF_PACKET` is blocked). When root is available the app routes
interface enumeration, MAC, gateway and the neighbor table through `su`
(`ip -o -4 addr show`, `ip -o link show`, `ip route show table all`,
`ip neigh show`); without root it falls back to the sandboxed Java APIs and no
longer drops interfaces that report a null MAC.

## Requirements

- Android Studio Hedgehog+ (or a version compatible with AGP 8.5)
- JDK 17
- Android SDK 34
- NDK + CMake (for `winarp_native`)
- A physical device on Android 8.0+ recommended; attack features require root

## Build the APK with Android Studio

1. Open the folder: `winarp/android`
2. Wait for Gradle Sync to finish (dependencies / NDK components download automatically)
3. Menu **Build → Build Bundle(s) / APK(s) → Build APK(s)**
4. Output is roughly at:
   - Debug: `app/build/outputs/apk/debug/app-debug.apk`
   - Release: `app/build/outputs/apk/release/app-release-unsigned.apk`

Command line (local Android SDK required):

```bash
cd android
# Windows
gradlew.bat assembleDebug
# macOS / Linux
./gradlew assembleDebug
```

If the Gradle Wrapper jar is missing, Android Studio generates it the first time
you open the project, or run:

```bash
gradle wrapper --gradle-version 8.7
```

## Usage flow

1. Connect the phone to the target Wi-Fi
2. Open the app, confirm NIC / gateway / subnet are correct
3. Tap **Scan LAN**
4. Check targets, or fill in an IP range
5. After granting root, tap **Attack selected / Attack IP range**
6. **Stop & restore** attempts to write the correct ARP back

## Project layout

```
android/
  app/src/main/
    java/com/winarp/mobile/
      ui/           # Compose UI + ViewModel
      net/          # scan / poison / root / IP utils
      data/         # data models
    cpp/            # AF_PACKET ARP native engine
```

## Differences from the desktop version

- Android cannot use Npcap; it uses Linux `AF_PACKET` + JNI instead.
- Without root, scanning still works as much as possible, but MAC completeness depends on the system neighbor table.
- Some vendor ROMs may restrict raw sockets, so even with root extra allowances may be needed.
