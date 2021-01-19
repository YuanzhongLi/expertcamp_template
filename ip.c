#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "net.h"
#include "ip.h"

struct ip_hdr {
    uint8_t vhl;
    uint8_t tos;
    uint16_t total;
    uint16_t id;
    uint16_t offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t sum;
    ip_addr_t src;
    ip_addr_t dst;
    uint8_t options[0];
};

const ip_addr_t IP_ADDR_ANY       = 0x00000000; /* 0.0.0.0 */
const ip_addr_t IP_ADDR_BROADCAST = 0xffffffff; /* 255.255.255.255 */

/* NOTE: if you want to add/delete the entries after net_run(), you need to protect these lists with a mutex. */
static struct ip_iface *ifaces;

int
ip_addr_pton(const char *p, ip_addr_t *n)
{
    char *sp, *ep;
    int idx;
    long ret;

    sp = (char *)p;
    for (idx = 0; idx < 4; idx++) {
        ret = strtol(sp, &ep, 10);
        if (ret < 0 || ret > 255) {
            return -1;
        }
        if (ep == sp) {
            return -1;
        }
        if ((idx == 3 && *ep != '\0') || (idx != 3 && *ep != '.')) {
            return -1;
        }
        ((uint8_t *)n)[idx] = ret;
        sp = ep + 1;
    }
    return 0;
}

char *
ip_addr_ntop(const ip_addr_t n, char *p, size_t size)
{
    uint8_t *u8;

    u8 = (uint8_t *)&n;
    snprintf(p, size, "%d.%d.%d.%d", u8[0], u8[1], u8[2], u8[3]);
    return p;
}

void
ip_dump(const uint8_t *data, size_t len)
{
    struct ip_hdr *hdr;
    uint8_t v, hl, hlen;
    uint16_t total, offset, sum;
    char addr[IP_ADDR_STR_LEN];

    flockfile(stderr);
    hdr = (struct ip_hdr *)data;
    v = (hdr->vhl & 0xf0) >> 4;
    hl = hdr->vhl & 0x0f;
    hlen = hl << 2;
    fprintf(stderr, "       vhl: 0x%02x [v: %u, hl: %u (%u)]\n", hdr->vhl, v, hl, hlen);
    fprintf(stderr, "       tos: 0x%02x\n", hdr->tos);
    total = ntoh16(hdr->total);
    fprintf(stderr, "     total: %u (payload: %u)\n", total, total - hlen);
    fprintf(stderr, "        id: %u\n", ntoh16(hdr->id));
    offset = ntoh16(hdr->offset);
    fprintf(stderr, "    offset: 0x%04x [flags=%x, offset=%u]\n", offset, (offset & 0xe000) >> 13, offset & 0x1fff);
    fprintf(stderr, "       ttl: %u\n", hdr->ttl);
    fprintf(stderr, "  protocol: %u\n", hdr->protocol);
    sum = ntoh16(hdr->sum);
    fprintf(stderr, "       sum: 0x%04x (0x%04x)\n", sum, cksum16((uint16_t *)data, hlen, -sum));
    fprintf(stderr, "       src: %s\n", ip_addr_ntop(hdr->src, addr, sizeof(addr)));
    fprintf(stderr, "       dst: %s\n", ip_addr_ntop(hdr->dst, addr, sizeof(addr)));
#ifdef HEXDUMP
    hexdump(stderr, data, total);
#endif
    funlockfile(stderr);
}

struct ip_iface *
ip_iface_alloc(const char *unicast, const char *netmask)
{
    struct ip_iface *iface;

    if (!unicast || !netmask) {
        errorf("invalid arguments");
        return NULL;
    }
    iface = calloc(1, sizeof(*iface));
    if (!iface) {
        errorf("calloc() failure");
        return NULL;
    }
    NET_IFACE(iface)->family = NET_IFACE_FAMILY_IPV4;
    /*
     * exercise: step6
     *   ifaceの次のメンバに値を設定
     *     - unicast, netmask, broadcast
     */
    ip_addr_pton(unicast, &(iface->unicast));
    ip_addr_pton(netmask, &(iface->netmask));
    iface->broadcast = iface->unicast | (~iface->netmask);

    return iface;
}

/* NOTE: must not be call after net_run() */
int
ip_iface_register(struct net_device *dev, struct ip_iface *iface)
{
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];

    /*
     * exercise: step6
     *   (1) dev に iface を追加する
     *   (2) IPインタフェースのリスト（ifaces）の先頭に追加
     */
    if (net_device_add_iface(dev, (struct net_iface *)iface) == -1) {
        errorf("net_device_add_iface() failure");
        return -1;
    }
    iface->next = ifaces;
    ifaces = iface;

    infof("registerd: dev=%s, unicast=%s netmask=%s",
        dev->name, ip_addr_ntop(iface->unicast, addr1, sizeof(addr1)), ip_addr_ntop(iface->netmask, addr2, sizeof(addr2)));
    return 0;
}

struct ip_iface *
ip_iface_by_addr(ip_addr_t addr)
{
    struct ip_iface *entry;

    for (entry = ifaces; entry; entry = entry->next) {
        if (entry->unicast == addr) {
            break;
        }
    }
    return entry;
}

static void
ip_input(const uint8_t *data, size_t len, struct net_device *dev)
{
    struct ip_hdr *hdr;
    struct ip_iface *iface;
    char addr[IP_ADDR_STR_LEN];

    /*
     * exercise: step5
     *   IPデータグラムの検証
     *   (1) 受信データの長さを検証
     *     - IPヘッダの最小サイズ（IP_HDR_SIZE_MIN）に満たない場合はエラーを出力して return する
     *   (2) data を hdr に代入してIPヘッダのフィールドを検証
     *     - 括弧内の条件が満たされない場合はエラーを出力して return する
     *     a. IPバージョン（IP_VERSION_IPV4 と一致する）
     *     b. ヘッダ長（len がヘッダ長以上である）
     *     c. トータル長（len がトータル長以上である）
     *     d. ttl（ttl が 0 ではない）
     *     c. チェックサム（チェックサムを再計算した結果が0である）
     */

    if (len < IP_HDR_SIZE_MIN) {
        errorf("IP header size is too small");
        return;
    }

    uint8_t v, hl, hlen, ttl;
    uint16_t total;
    hdr = (struct ip_hdr *)data;
    v = (hdr->vhl & 0xf0) >> 4;
    hl = hdr->vhl & 0x0f;
    hlen = hl<<2;
    ttl = hdr->ttl;
    total = ntoh16(hdr->total);

    if (v != IP_VERSION_IPV4) {
        errorf("IP is not IPV4");
        return;
    }
    if (len < hlen) {
        errorf("len is less than hlen");
        return;
    }
    if (len < total) {
        errorf("len is less than total");
        return;
    }
    if (ttl == 0) {
        errorf("ttl is zero");
        return;
    }
    if (cksum16((uint16_t *)data, hlen, 0) != 0) {
        errorf("checksome error");
        return;
    }

    iface = (struct ip_iface *)net_device_get_iface(dev, NET_IFACE_FAMILY_IPV4);
    if (!iface) {
        /* IP interface is not registered to the device */
        return;
    }
    /*
     * exercise: step6
     *   パケットのフィルタリング
     *   (1) 宛先アドレスが以下の何れでもない場合は他のホストあてのパケットとみなして return する
     *     - インタフェースのIPアドレスと一致する
     *     - インタフェースのブロードキャストIPアドレスと一致する
     *     - グローバルなブロードキャストIPアドレス（255.255.255.255）と一致する
     */
    ip_addr_t dst;
    dst = hdr->dst;
    if (dst != iface->unicast) {
        if (dst != iface->broadcast) {
            if (dst != IP_ADDR_BROADCAST) {
                return; /* 他あてなので処理しない */
            }
        }
    }

    debugf("dev=%s, iface=%s, len=%zd", dev->name, ip_addr_ntop(iface->unicast, addr, sizeof(addr)), len);
    ip_dump(data, len);
}

static int
ip_output_device(struct ip_iface *iface, const uint8_t *data, size_t len, ip_addr_t dst)
{
    uint8_t hwaddr[NET_DEVICE_ADDR_LEN] = {};
    char addr[IP_ADDR_STR_LEN];

    if (NET_IFACE(iface)->dev->flags & NET_DEVICE_FLAG_NEED_ARP) {
        if (dst == iface->broadcast || dst == IP_ADDR_BROADCAST) {
            memcpy(hwaddr, NET_IFACE(iface)->dev->broadcast, NET_IFACE(iface)->dev->alen);
        } else {
            errorf("arp does not implement");
            return -1;
        }
    }
    debugf("dev=%s, iface=%s, len=%zu", NET_IFACE(iface)->dev->name, ip_addr_ntop(dst, addr, sizeof(addr)), len);
    ip_dump(data, len);
    /*
     * exercise: step7
     *   デバイスにIPデータグラムを出力する
     */

}

static ssize_t
ip_output_core(struct ip_iface *iface, uint8_t protocol, const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, uint16_t id, uint16_t offset)
{
    uint8_t buf[IP_DGRAM_SIZE_MAX];
    struct ip_hdr *hdr;
    uint16_t hlen;

    hdr = (struct ip_hdr *)buf;
    /*
     * exercise: step7
     *   IPデータグラムの生成
     *   (1) IPヘッダの各フィールドに値を設定（tosフィールドは0とする）
     *     - バイトオーダーの考慮を忘れずに
     *   (2) IPヘッダの後ろにデータを格納する
     */
    return ip_output_device(iface, buf, hlen + len, dst);
}

static uint16_t
ip_generate_id(void)
{
    static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    static uint16_t id = 128;
    uint16_t ret;
    pthread_mutex_unlock(&mutex);
    return ret;
}

ssize_t
ip_output(uint8_t protocol, const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst)
{
    struct ip_iface *iface;
    uint16_t id;

    /*
     * exercise: step7
     *   (1) 引数で指定された送信元アドレスと一致するIPインタフェースを取得する
     *     - 取得できなかったらエラーを返す
     *   (2) 宛先アドレスに到達可能か確認する
     *     - 以下のどちらにも合致しなかったら送信できないのでエラーを返す
     *       a. - 宛先アドレスがブロードキャストアドレスである
     *       b. - IPインタフェースと同じサブネットワークに属するアドレスである
     *   (3) IPデータグラムのサイズがデバイスのMTUを超える場合はフラグメント化が必要
     *     - 今回は実装しないのでエラーを返す
     */
    id = ip_generate_id();
    if (ip_output_core(iface, protocol, data, len, iface->unicast, dst, id, 0) == -1) {
        return -1;
    }
    return len;
}

int
ip_init(void)
{
    /*
     * exercise: step5
     *   プロトコルスタック本体にIPを登録
     */
    net_protocol_register("IPV4", NET_PROTOCOL_TYPE_IP, ip_input);
    return 0;
}
