#include <jni.h>
#include <android/log.h>

#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <cstdio>
#include <ifaddrs.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#define LOG_TAG "WinARP-Native"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace {

constexpr uint16_t kEthTypeArp = 0x0806;
constexpr uint16_t kArpHtypeEther = 1;
constexpr uint16_t kArpPtypeIpv4 = 0x0800;
constexpr uint16_t kArpOpRequest = 1;
constexpr uint16_t kArpOpReply = 2;

bool parseMac(const char *text, uint8_t out[6]) {
    unsigned int b[6] = {0};
    if (std::sscanf(text, "%x:%x:%x:%x:%x:%x", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6) {
        return false;
    }
    for (int i = 0; i < 6; ++i) {
        out[i] = static_cast<uint8_t>(b[i] & 0xFF);
    }
    return true;
}

bool parseIpv4(const char *text, uint8_t out[4]) {
    in_addr addr{};
    if (inet_pton(AF_INET, text, &addr) != 1) {
        return false;
    }
    std::memcpy(out, &addr.s_addr, 4);
    return true;
}

std::vector<uint8_t> buildArpFrame(
        const uint8_t dstMac[6],
        const uint8_t srcMac[6],
        uint16_t op,
        const uint8_t senderMac[6],
        const uint8_t senderIp[4],
        const uint8_t targetMac[6],
        const uint8_t targetIp[4]) {
    std::vector<uint8_t> pkt(42, 0);
    std::memcpy(pkt.data() + 0, dstMac, 6);
    std::memcpy(pkt.data() + 6, srcMac, 6);
    pkt[12] = static_cast<uint8_t>((kEthTypeArp >> 8) & 0xFF);
    pkt[13] = static_cast<uint8_t>(kEthTypeArp & 0xFF);
    pkt[14] = static_cast<uint8_t>((kArpHtypeEther >> 8) & 0xFF);
    pkt[15] = static_cast<uint8_t>(kArpHtypeEther & 0xFF);
    pkt[16] = static_cast<uint8_t>((kArpPtypeIpv4 >> 8) & 0xFF);
    pkt[17] = static_cast<uint8_t>(kArpPtypeIpv4 & 0xFF);
    pkt[18] = 6;
    pkt[19] = 4;
    pkt[20] = static_cast<uint8_t>((op >> 8) & 0xFF);
    pkt[21] = static_cast<uint8_t>(op & 0xFF);
    std::memcpy(pkt.data() + 22, senderMac, 6);
    std::memcpy(pkt.data() + 28, senderIp, 4);
    std::memcpy(pkt.data() + 32, targetMac, 6);
    std::memcpy(pkt.data() + 38, targetIp, 4);
    return pkt;
}

int openRawSocket(const char *ifName, sockaddr_ll *addrOut) {
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        LOGE("socket AF_PACKET failed: %s", std::strerror(errno));
        return -1;
    }

    ifreq ifr{};
    std::snprintf(ifr.ifr_name, IFNAMSIZ, "%s", ifName);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        LOGE("SIOCGIFINDEX failed: %s", std::strerror(errno));
        close(fd);
        return -1;
    }

    std::memset(addrOut, 0, sizeof(*addrOut));
    addrOut->sll_family = AF_PACKET;
    addrOut->sll_protocol = htons(ETH_P_ALL);
    addrOut->sll_ifindex = ifr.ifr_ifindex;
    addrOut->sll_halen = ETH_ALEN;

    if (bind(fd, reinterpret_cast<sockaddr *>(addrOut), sizeof(*addrOut)) < 0) {
        LOGE("bind failed: %s", std::strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

int sendFrame(int fd, const sockaddr_ll &addr, const std::vector<uint8_t> &frame) {
    ssize_t n = sendto(fd, frame.data(), frame.size(), 0,
                       reinterpret_cast<const sockaddr *>(&addr), sizeof(addr));
    if (n < 0) {
        LOGE("sendto failed: %s", std::strerror(errno));
        return -1;
    }
    return static_cast<int>(n);
}

jstring jniError(JNIEnv *env, const char *msg) {
    return env->NewStringUTF(msg);
}

} // namespace

extern "C" JNIEXPORT jboolean JNICALL
Java_com_winarp_mobile_net_NativeArp_nativeCanOpenRaw(
        JNIEnv *env, jclass, jstring ifNameJ) {
    const char *ifName = env->GetStringUTFChars(ifNameJ, nullptr);
    sockaddr_ll addr{};
    int fd = openRawSocket(ifName, &addr);
    env->ReleaseStringUTFChars(ifNameJ, ifName);
    if (fd < 0) {
        return JNI_FALSE;
    }
    close(fd);
    return JNI_TRUE;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_winarp_mobile_net_NativeArp_nativeSendArp(
        JNIEnv *env,
        jclass,
        jstring ifNameJ,
        jstring dstMacJ,
        jstring srcMacJ,
        jint op,
        jstring senderMacJ,
        jstring senderIpJ,
        jstring targetMacJ,
        jstring targetIpJ) {
    const char *ifName = env->GetStringUTFChars(ifNameJ, nullptr);
    const char *dstMacS = env->GetStringUTFChars(dstMacJ, nullptr);
    const char *srcMacS = env->GetStringUTFChars(srcMacJ, nullptr);
    const char *senderMacS = env->GetStringUTFChars(senderMacJ, nullptr);
    const char *senderIpS = env->GetStringUTFChars(senderIpJ, nullptr);
    const char *targetMacS = env->GetStringUTFChars(targetMacJ, nullptr);
    const char *targetIpS = env->GetStringUTFChars(targetIpJ, nullptr);

    uint8_t dstMac[6], srcMac[6], senderMac[6], targetMac[6], senderIp[4], targetIp[4];
    jstring result = nullptr;

    if (!parseMac(dstMacS, dstMac) || !parseMac(srcMacS, srcMac) ||
        !parseMac(senderMacS, senderMac) || !parseMac(targetMacS, targetMac) ||
        !parseIpv4(senderIpS, senderIp) || !parseIpv4(targetIpS, targetIp)) {
        result = jniError(env, "invalid mac/ip");
    } else {
        sockaddr_ll addr{};
        int fd = openRawSocket(ifName, &addr);
        if (fd < 0) {
            result = jniError(env, std::strerror(errno));
        } else {
            auto frame = buildArpFrame(
                    dstMac, srcMac, static_cast<uint16_t>(op),
                    senderMac, senderIp, targetMac, targetIp);
            std::memcpy(addr.sll_addr, dstMac, 6);
            if (sendFrame(fd, addr, frame) < 0) {
                result = jniError(env, std::strerror(errno));
            } else {
                result = env->NewStringUTF("");
            }
            close(fd);
        }
    }

    env->ReleaseStringUTFChars(ifNameJ, ifName);
    env->ReleaseStringUTFChars(dstMacJ, dstMacS);
    env->ReleaseStringUTFChars(srcMacJ, srcMacS);
    env->ReleaseStringUTFChars(senderMacJ, senderMacS);
    env->ReleaseStringUTFChars(senderIpJ, senderIpS);
    env->ReleaseStringUTFChars(targetMacJ, targetMacS);
    env->ReleaseStringUTFChars(targetIpJ, targetIpS);
    return result;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_winarp_mobile_net_NativeArp_nativeProbeArp(
        JNIEnv *env,
        jclass,
        jstring ifNameJ,
        jstring localMacJ,
        jstring localIpJ,
        jstring targetIpJ,
        jint timeoutMs) {
    const char *ifName = env->GetStringUTFChars(ifNameJ, nullptr);
    const char *localMacS = env->GetStringUTFChars(localMacJ, nullptr);
    const char *localIpS = env->GetStringUTFChars(localIpJ, nullptr);
    const char *targetIpS = env->GetStringUTFChars(targetIpJ, nullptr);

    uint8_t localMac[6], localIp[4], targetIp[4];
    jstring result = env->NewStringUTF("");

    do {
        if (!parseMac(localMacS, localMac) || !parseIpv4(localIpS, localIp) ||
            !parseIpv4(targetIpS, targetIp)) {
            result = jniError(env, "");
            break;
        }

        sockaddr_ll addr{};
        int fd = openRawSocket(ifName, &addr);
        if (fd < 0) {
            break;
        }

        timeval tv{};
        tv.tv_sec = timeoutMs / 1000;
        tv.tv_usec = (timeoutMs % 1000) * 1000;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        uint8_t bcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
        uint8_t zeroMac[6] = {0, 0, 0, 0, 0, 0};
        auto req = buildArpFrame(bcast, localMac, kArpOpRequest, localMac, localIp, zeroMac, targetIp);
        std::memcpy(addr.sll_addr, bcast, 6);
        sendFrame(fd, addr, req);

        uint8_t buf[128];
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::milliseconds(timeoutMs > 0 ? timeoutMs : 300);
        while (std::chrono::steady_clock::now() < deadline) {
            ssize_t n = recv(fd, buf, sizeof(buf), 0);
            if (n < 42) {
                continue;
            }
            uint16_t ethType = (static_cast<uint16_t>(buf[12]) << 8) | buf[13];
            if (ethType != kEthTypeArp) {
                continue;
            }
            uint16_t op = (static_cast<uint16_t>(buf[20]) << 8) | buf[21];
            if (op != kArpOpReply) {
                continue;
            }
            if (std::memcmp(buf + 28, targetIp, 4) != 0) {
                continue;
            }
            char macText[32];
            std::snprintf(macText, sizeof(macText), "%02x:%02x:%02x:%02x:%02x:%02x",
                          buf[22], buf[23], buf[24], buf[25], buf[26], buf[27]);
            result = env->NewStringUTF(macText);
            break;
        }
        close(fd);
    } while (false);

    env->ReleaseStringUTFChars(ifNameJ, ifName);
    env->ReleaseStringUTFChars(localMacJ, localMacS);
    env->ReleaseStringUTFChars(localIpJ, localIpS);
    env->ReleaseStringUTFChars(targetIpJ, targetIpS);
    return result;
}
