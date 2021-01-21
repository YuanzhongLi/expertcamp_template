#ifndef UDP_H
#define UDP_H

#include <stddef.h>
#include <stdint.h>

#include "ip.h"

struct udp_endpoint {
    ip_addr_t addr;
    uint16_t port;
};

extern ssize_t
udp_output(struct udp_endpoint *src, struct udp_endpoint *dst, uint8_t *buf, size_t len);
extern int
udp_init(void);

#endif
