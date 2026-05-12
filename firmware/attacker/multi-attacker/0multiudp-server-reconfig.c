/*
 * udp-server-reconfig.c
 *
 * Real IoT Device - FIXED Multi-Attacker Version
 *
 * FIX: Uses attacker table
 * Entry never removed - permanent flag stays
 * Supports up to MAX_BLOCKED simultaneous attackers
 *
 * Author: Anam Sabah Khan - G202402840
 */

#include "contiki.h"
#include "net/ipv6/simple-udp.h"
#include "net/ipv6/uip.h"
#include "net/routing/routing.h"
#include "sys/log.h"
#include <string.h>
#include <stdint.h>

#define LOG_MODULE "REAL"
#define LOG_LEVEL  LOG_LEVEL_INFO

#define WITH_SERVER_REPLY  1
#define UDP_CLIENT_PORT    8765
#define UDP_SERVER_PORT    5678
#define CTRL_PORT          3000
#define MAX_BLOCKED        5

typedef struct {
  uint8_t      used;
  uint8_t      currently_blocked;
  uint8_t      permanent;
  uip_ipaddr_t ip;
  clock_time_t block_until;
} block_entry_t;

static block_entry_t blocked[MAX_BLOCKED];
static struct simple_udp_connection app_conn;
static struct simple_udp_connection ctrl_conn;

typedef struct {
  uint8_t  type;
  uint8_t  ip[16];
  uint16_t seconds;
} __attribute__((packed)) ctrl_msg_t;

/*─────────────────────────────────────────────────*/
static int8_t
find_entry(const uip_ipaddr_t *ip)
{
  uint8_t i;
  for(i=0;i<MAX_BLOCKED;i++) {
    if(blocked[i].used &&
       uip_ipaddr_cmp(&blocked[i].ip,ip))
      return (int8_t)i;
  }
  return -1;
}

/*─────────────────────────────────────────────────*/
static int8_t
find_or_create(const uip_ipaddr_t *ip)
{
  int8_t idx = find_entry(ip);
  if(idx>=0) return idx;
  uint8_t i;
  for(i=0;i<MAX_BLOCKED;i++) {
    if(!blocked[i].used) {
      blocked[i].used              = 1;
      blocked[i].currently_blocked = 0;
      blocked[i].permanent         = 0;
      uip_ipaddr_copy(&blocked[i].ip, ip);
      return (int8_t)i;
    }
  }
  return -1;
}

/*─────────────────────────────────────────────────*/
static int
is_blocked(const uip_ipaddr_t *sender)
{
  uint8_t i;
  for(i=0;i<MAX_BLOCKED;i++) {
    if(!blocked[i].used) continue;
    if(!uip_ipaddr_cmp(&blocked[i].ip,sender))
      continue;

    /* Permanent never expires */
    if(blocked[i].permanent) return 1;

    /* Temporary - check timer */
    if(blocked[i].currently_blocked) {
      if(clock_time() > blocked[i].block_until) {
        blocked[i].currently_blocked = 0;
        LOG_INFO("STATUS: Block expired "
                 "slot %u - NORMAL resumed\n", i);
        return 0;
      }
      return 1;
    }
  }
  return 0;
}

/*─────────────────────────────────────────────────*/
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
    LOG_INFO("DEFENSE: blocked attacker "
             "ignored (app)\n");
    return;
  }

  LOG_INFO("NORMAL: Received '%.*s' from ",
           datalen,(const char *)data);
  LOG_INFO_6ADDR(sender_addr);
  LOG_INFO_("\n");

#if WITH_SERVER_REPLY
  LOG_INFO("NORMAL: Sending response "
           "(acting as legitimate device)\n");
  simple_udp_sendto(&app_conn,data,datalen,
                    sender_addr);
#endif
}

/*─────────────────────────────────────────────────*/
static void
ctrl_rx_callback(struct simple_udp_connection *c,
                 const uip_ipaddr_t *sender_addr,
                 uint16_t sender_port,
                 const uip_ipaddr_t *receiver_addr,
                 uint16_t receiver_port,
                 const uint8_t *data,
                 uint16_t datalen)
{
  ctrl_msg_t msg;
  if(datalen < sizeof(ctrl_msg_t)) return;
  memcpy(&msg, data, sizeof(msg));
  if(msg.type != 1) return;

  uip_ipaddr_t aip;
  memcpy(&aip, msg.ip, 16);

  int8_t idx = find_or_create(&aip);
  if(idx < 0) {
    LOG_INFO("WARN: Block table full\n");
    return;
  }

  /* Already permanent - ignore */
  if(blocked[idx].permanent) {
    LOG_INFO("INFO: Slot %d already "
             "permanent\n", idx);
    return;
  }

  LOG_INFO("HONEYPOT INSTRUCTION: "
           "BLOCK received slot %d\n", idx);
  LOG_INFO("HONEYPOT INSTRUCTION: "
           "Attacker IP = ");
  LOG_INFO_6ADDR(&aip);
  LOG_INFO_("\n");
  LOG_INFO("HONEYPOT INSTRUCTION: "
           "Duration = %u seconds\n",
           msg.seconds);

  blocked[idx].currently_blocked = 1;
  uip_ipaddr_copy(&blocked[idx].ip, &aip);
  blocked[idx].block_until = clock_time() +
    ((clock_time_t)msg.seconds * CLOCK_SECOND);

  if(msg.seconds >= 65000) {
    blocked[idx].permanent = 1;
    LOG_INFO("RECONFIG: PERMANENT BLOCK "
             "slot %d - NEVER responds again\n",
             idx);
  } else {
    LOG_INFO("RECONFIG: BLOCK slot %d "
             "for %u seconds\n",
             idx, msg.seconds);
  }
}

/*─────────────────────────────────────────────────*/
PROCESS(real_node_proc, "Real Node Multi-Block");
AUTOSTART_PROCESSES(&real_node_proc);

PROCESS_THREAD(real_node_proc, ev, data)
{
  PROCESS_BEGIN();

  uint8_t i;
  for(i=0;i<MAX_BLOCKED;i++) {
    blocked[i].used              = 0;
    blocked[i].currently_blocked = 0;
    blocked[i].permanent         = 0;
  }

  simple_udp_register(&app_conn,
                      UDP_SERVER_PORT,NULL,
                      UDP_CLIENT_PORT,
                      app_rx_callback);
  simple_udp_register(&ctrl_conn,
                      CTRL_PORT,NULL,
                      0,
                      ctrl_rx_callback);

  LOG_INFO("REAL NODE READY. "
           "Ports: App=%u Ctrl=%u\n",
           UDP_SERVER_PORT, CTRL_PORT);
  LOG_INFO("REAL NODE: Multi-block support "
           "(%u attackers)\n", MAX_BLOCKED);
  LOG_INFO("REAL NODE: Permanent block "
           "at Strike 3\n");

  PROCESS_END();
}
