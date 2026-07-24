# WinARP Android

Windows 版 `winarp` 的 Android 移植：局域网扫描 + 多线程 ARP 污染，Material 3 深色简洁界面。

> **仅用于 CTF / 授权沙箱。** 勿用于未授权网络。

## 功能对照

| 功能 | Windows | Android |
|------|---------|---------|
| 网卡列表 | ✅ | ✅ Wi-Fi / 网卡 |
| 局域网扫描 (IP/MAC/名称) | ✅ | ✅ |
| 多选主机攻击 | ✅ | ✅ |
| IP 段攻击 | ✅ | ✅ |
| 多线程并发污染 | ✅ | ✅ 协程并发 |
| 单向污染 | ✅ | ✅ |
| 停止并恢复 ARP | ✅ | ✅ |
| 原生 GUI | Win32 | Jetpack Compose |

## 权限说明

- **扫描**：通常无需 Root。通过邻居探测 + `/proc/net/arp`，Root 下可用 AF_PACKET 主动 ARP 探测。
- **断网 / ARP 污染**：需要 **Root**，以便打开 `AF_PACKET` 原始套接字发送 ARP 应答。

## 环境要求

- Android Studio Hedgehog+（或兼容 AGP 8.5 的版本）
- JDK 17
- Android SDK 34
- NDK + CMake（用于 `winarp_native`）
- 真机建议 Android 8.0+，攻击功能需已 Root

## 用 Android Studio 构建 APK

1. 打开目录：`winarp/android`
2. 等待 Gradle Sync 完成（自动下载依赖 / NDK 组件）
3. 菜单 **Build → Build Bundle(s) / APK(s) → Build APK(s)**
4. 输出大致位于：
   - Debug: `app/build/outputs/apk/debug/app-debug.apk`
   - Release: `app/build/outputs/apk/release/app-release-unsigned.apk`

命令行（需本机已配置 Android SDK）：

```bash
cd android
# Windows
gradlew.bat assembleDebug
# macOS / Linux
./gradlew assembleDebug
```

若没有 Gradle Wrapper jar，可在 Android Studio 首次打开工程时自动生成，或执行：

```bash
gradle wrapper --gradle-version 8.7
```

## 使用流程

1. 手机连接目标 Wi-Fi
2. 打开 App，确认网卡 / 网关 / 网段正确
3. 点 **扫描局域网**
4. 勾选目标，或填写 IP 段
5. Root 授权后点 **攻击选中 / 攻击 IP 段**
6. **停止并恢复** 会尝试写回正确 ARP

## 项目结构

```
android/
  app/src/main/
    java/com/winarp/mobile/
      ui/           # Compose 界面 + ViewModel
      net/          # 扫描 / 污染 / Root / IP 工具
      data/         # 数据模型
    cpp/            # AF_PACKET ARP 原生引擎
```

## 与桌面版差异

- Android 无法使用 Npcap；改为 Linux `AF_PACKET` + JNI。
- 无 Root 时扫描仍尽量可用，但 MAC 完整度取决于系统邻居表。
- 部分厂商 ROM 可能限制原始套接字，即使 Root 也需额外放行。
