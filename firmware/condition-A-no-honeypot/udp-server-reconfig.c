#include "contiki.h"
#include "net/ipv6/simple-udp.h"
#include "net/ipv6/uip.h"
#include "net/routing/routing.h"
#include "sys/log.h"

#include <string.h>
#include <stdint.h>

#define LOG_MODULE "REAL"
#define LOG_LEVEL LOG_LEVEL_INFO

#define WITH_SERVER_REPLY  1
#define UDP_CLIENT_PORT    8765
#define UDP_SERVER_PORT    5678

#define CTRL_PORT          3000
#define BLOCK_SECONDS      60

static struct simple_udp_connection app_conn;
static struct simple_udp_connection ctrl_conn;

/* Blocklist (single attacker for demo) */
static uip_ipaddr_t blocked_ip;
static uint8_t attacker_blocked = 0;
static clock_time_t block_until = 0;

/* Control message (binary) */
typedef struct {
  uint8_t type;            /* 1 = BLOCK */
  uint8_t ip[16];          /* attacker IPv6 */
  uint16_t seconds;        /* block duration */
} __attribute__((packed)) ctrl_msg_t;

static int
is_blocked(const uip_ipaddr_t *sender_addr)
{
  if(attacker_blocked && clock_time() > block_until) {
    attacker_blocked = 0;
    LOG_INFO("DEFENSE: attacker unblocked (timer)\n");
  }
  return attacker_blocked && uip_ipaddr_cmp(sender_addr, &blocked_ip);
}

/* Receive normal app traffic */
static void
app_rx_callback(struct simple_udp_connection *c,
                const uip_ipaddr_t *sender_addr,
                uint16_t sender_port,
                const uip_ipaddr_t *receiver_addr,
                uint16_t receiver_port,
                const uint8_t *data,
                uint16_t datalen)
{
  if(is_blocked(sender_addr)) {
    LOG_INFO("DEFENSE: blocked attacker ignored (app)\n");
    return;
  }

  LOG_INFO("Received request '%.*s' from ", datalen, (const char *)data);
  LOG_INFO_6ADDR(sender_addr);
  LOG_INFO_("\n");

#if WITH_SERVER_REPLY
  LOG_INFO("Sending response.\n");
  simple_udp_sendto(&app_conn, data, datalen, sender_addr);
#endif
}

/* Receive reconfiguration from honeypot */
static void
ctrl_rx_callback(struct simple_udp_connection *c,
                 const uip_ipaddr_t *sender_addr,
                 uint16_t sender_port,
                 const uip_ipaddr_t *receiver_addr,
                 uint16_t receiver_port,
                 const uint8_t *data,
                 uint16_t datalen)
{
  if(datalen < sizeof(ctrl_msg_t)) {
    return;
  }

  ctrl_msg_t msg;
  memcpy(&msg, data, sizeof(msg));

  if(msg.type == 1) { /* BLOCK */
    memcpy(&blocked_ip, msg.ip, 16);
    attacker_blocked = 1;
    block_until = clock_time() + (msg.seconds * CLOCK_SECOND);

    LOG_INFO("RECONFIG: BLOCK received. Blocking attacker for %u seconds. Attacker=",
             msg.seconds);
    LOG_INFO_6ADDR(&blocked_ip);
    LOG_INFO_("\n");
  }
}

PROCESS(udp_server_reconfig_process, "UDP Server (reconfig)");
AUTOSTART_PROCESSES(&udp_server_reconfig_process);

PROCESS_THREAD(udp_server_reconfig_process, ev, data)
{
  PROCESS_BEGIN();

  /* Start routing root only if you want; for leaf nodes it's ok not to call root_start */
  /* NETSTACK_ROUTING.root_start(); */  /* <-- DO NOT enable on real nodes */

  simple_udp_register(&app_conn, UDP_SERVER_PORT, NULL,
                      UDP_CLIENT_PORT, app_rx_callback);

  simple_udp_register(&ctrl_conn, CTRL_PORT, NULL,
                      CTRL_PORT, ctrl_rx_callback);

  LOG_INFO("REAL NODE READY. App port %u, Ctrl port %u\n", UDP_SERVER_PORT, CTRL_PORT);

  PROCESS_END();
}
