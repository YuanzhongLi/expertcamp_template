#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "ip.h"
#include "udp.h"

struct pseudo_hdr {
    uint32_t src;
    uint32_t dst;
    uint8_t zero;
    uint8_t protocol;
    uint16_t len;
};

struct udp_hdr {
    uint16_t src;
    uint16_t dst;
    uint16_t len;
    uint16_t sum;
};

static void
udp_dump(const uint8_t *data, size_t len)
{
    struct udp_hdr *hdr;

    flockfile(stderr);
    hdr = (struct udp_hdr *)data;
    fprintf(stderr, "        src: %u\n", ntoh16(hdr->src));
    fprintf(stderr, "        dst: %u\n", ntoh16(hdr->dst));
    fprintf(stderr, "        len: %u\n", ntoh16(hdr->len));
    fprintf(stderr, "        sum: 0x%04x\n", ntoh16(hdr->sum));
#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

/*
 * UDP CORE
 */

static void
udp_input(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst)
{
    struct pseudo_hdr pseudo;
    uint16_t psum = 0, sum;
    struct udp_hdr *hdr;
    char addr1[IP_ADDR_STR_LEN], addr2[IP_ADDR_STR_LEN];

    /*
     * exercise: step15
     *   UDPデータグラムの検証
     *   (1) サイズの検証
     *   (2) チェックサムの検証（疑似ヘッダの存在を忘れずに）
     */
    /* サイズの検証 (1) */
    hdr = (struct udp_hdr *)data;
    if (len > IP_PAYLOAD_SIZE_MAX) {
        errorf("udp size is too long");
        return;
    }
    if (len < sizeof(*hdr)) {
        errorf("udp size is too short");
        return;
    }

    /* pseudo headerの作成 */
    pseudo.src = src;
    pseudo.dst = dst;
    pseudo.zero = 0;
    pseudo.protocol = IP_PROTOCOL_UDP;
    pseudo.len = sizeof(pseudo) + len;
    psum = ~(cksum16((uint16_t *)(&pseudo), sizeof(pseudo), 0)); // 途中までのsumなので反転させる

    if (cksum16((uint16_t *)data, len, psum) != 0) {
        errorf("checksome error");
        return;
    }

    debugf("%s:%d => %s:%d (%zu bytes payload)",
        ip_addr_ntop(src, addr1, sizeof(addr1)), ntoh16(hdr->src),
        ip_addr_ntop(dst, addr2, sizeof(addr2)), ntoh16(hdr->dst),
        len - sizeof(*hdr));
    udp_dump(data, len);
}

ssize_t
udp_output(struct udp_endpoint *src, struct udp_endpoint *dst, uint8_t *data, size_t len)
{
    struct pseudo_hdr pseudo;
    uint16_t psum = 0;
    uint8_t buf[IP_PAYLOAD_SIZE_MAX];
    struct udp_hdr *hdr;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];

    /*
     * exercise: step15
     *   UDPデータグラムを生成
     *     - チェックサム生成時に疑似ヘッダの存在を忘れずに
     */
    /* pseudo headerを作成 */
    pseudo.src = src->addr;
    pseudo.dst = dst->addr;
    pseudo.zero = 0;
    pseudo.protocol = IP_PROTOCOL_UDP;
    pseudo.len = sizeof(pseudo) + sizeof(*hdr) + len;

    psum = ~(cksum16((uint16_t *)(&pseudo), sizeof(pseudo), 0)); //途中までのsumなので反転させる

    /* UDP headerを作成 */
    hdr = (struct udp_hdr *)buf;
    hdr->src = src->port;
    hdr->dst = dst->port;
    hdr->len = sizeof(*hdr) + len;
    hdr->sum = 0;
    memcpy(hdr+1, data, len);
    hdr->sum = cksum16((uint16_t *)hdr, hdr->len, psum);

    debugf("%s:%d => %s:%d (%zu bytes payload)",
        ip_addr_ntop(src->addr, addr1, sizeof(addr1)), ntoh16(src->port),
        ip_addr_ntop(dst->addr, addr2, sizeof(addr2)), ntoh16(dst->port),
        len);
    udp_dump((uint8_t *)hdr, sizeof(*hdr) + len);
    /*
     * exercise: step15
     *   IPの送信関数を呼び出してUDPデータグラムを送信
     */
    return ip_output(IP_PROTOCOL_UDP, buf, hdr->len, pseudo.src, pseudo.dst);
}

int
udp_init(void)
{
    if (ip_protocol_register("UDP", IP_PROTOCOL_TCP, udp_input) == -1) {
        return -1;
    }
    return 0;
}
