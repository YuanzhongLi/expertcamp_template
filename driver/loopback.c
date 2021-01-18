#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

#include "util.h"
#include "net.h"

#include "loopback.h"

#define LOOPBACK_MTU UINT16_MAX /* maximum size of IP datagram */

/*
 * exercise: step2
 *   Loopbackデバイスを実装
 */

