# winarp

Windows LAN scan + multi-thread ARP poison (CTF), with Android port.

> **For CTF / authorized sandbox only.** Do not use on unauthorized networks.

## Windows

```bash
go build -o winarp.exe .
# or just run
go run .
```

## Android

Project path: [`android/`](android/)

### GitHub Actions APK

Push to `main` (or run **Actions → Android CI → Run workflow**) to build a debug APK.

Artifact name: **`winarp-android-debug`**

### Local build

Open `android/` in Android Studio (JDK 17 + SDK 34 + NDK), then **Build APK**.
