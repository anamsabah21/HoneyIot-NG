#ifndef DEFENSE_H
#define DEFENSE_H

#include "contiki.h"
#include "net/ipv6/uip.h"
#include "sys/log.h"
#include <string.h>

static uip_ipaddr_t blocked_ip;
static uint8_t attacker_blocked = 0;
static clock_time_t block_until = 0;

static int ip_equal(const uip_ipaddr_t *a, const uip_ipaddr_t *b) {
  return uip_ipaddr_cmp(a, b);
}

/* Block this attacker for N seconds */
static void defense_block_attacker(const uip_ipaddr_t *attacker, uint16_t seconds) {
  uip_ipaddr_copy(&blocked_ip, attacker);
  attacker_blocked = 1;
  block_until = clock_time() + (seconds * CLOCK_SECOND);
  LOG_INFO("DEFENSE: blocking attacker for %u seconds\n", seconds);
}

/* Check if attacker is blocked */
static int defense_is_blocked(const uip_ipaddr_t *sender) {
  if(attacker_blocked && (clock_time() > block_until)) {
    attacker_blocked = 0;
    LOG_INFO("DEFENSE: attacker unblocked\n");
  }
  return attacker_blocked && ip_equal(sender, &blocked_ip);
}

#endif
