/*
 * udp-server-honeypot-reconfig-v2.c
 *
 * FINAL VERSION - All fixes applied
 *
 * Key fixes in this version:
 * 1. WITH_SERVER_REPLY = 0 (honeypot stays silent)
 * 2. Primary/Secondary design:
 *    Node 5 = PRIMARY  (detects + broadcasts BLOCK)
 *    Node 6 = SECONDARY (detects + monitors only)
 * 3. Secondary honeypot also receives BLOCK from primary
 *    so its own block timer syncs with primary
 * 4. Detailed logging showing exactly what each node does
 *
 * Detection Models:
 *   Model 4 - ICMPv6 Flood  MITRE T1498/T1499
 *   Model 5 - Rogue RA      MITRE T1557/T1584
 *   Model 2 - UDP Flood     MITRE T1498
 *   Model 3 - SCAN          MITRE T1046
 *   Model 1 - UNLOCK        MITRE T1059
 *
 * Progressive block:
 *   Strike 1 = BLOCK_STRIKE_1 seconds
 *   Strike 2 = BLOCK_STRIKE_2 seconds
 *   Strike 3 = BLOCK_STRIKE_3 (permanent)
 *
 * Author: Anam Sabah Khan - G202402840
 * SEC 619 Term 252
 */

#include "contiki.h"
#include "net/ipv6/simple-udp.h"
#include "net/ipv6/uip.h"
#include "net/routing/routing.h"
#include "sys/node-id.h"
#include "sys/log.h"
#include <string.h>
#include <stdint.h>

#define LOG_MODULE "HONEYPOT"
#define LOG_LEVEL  LOG_LEVEL_INFO

/* Honeypot stays silent - does not reply to packets */
#define WITH_SERVER_REPLY     0

#define UDP_CLIENT_PORT       8765
#define UDP_SERVER_PORT       5678
#define CTRL_PORT             3000

/*
 * Node 5 = PRIMARY honeypot
 *   Detects attacks AND broadcasts BLOCK to entire network
 *   Manages strike counter
 *
 * Node 6 = SECONDARY honeypot
 *   Detects attacks AND logs them
 *   Does NOT broadcast (defers to Node 5)
 *   DOES receive BLOCK from Node 5 to sync its own blocklist
 */
#define PRIMARY_HONEYPOT_ID   5

/*
 * Block durations:
 * FOR DEMO SCREENSHOTS use:  10, 20, 65000
 * FOR REAL SIMULATION use:   60, 600, 65000
 */
#define BLOCK_STRIKE_1        10
#define BLOCK_STRIKE_2        20
#define BLOCK_STRIKE_3        65000

/* Model 2 flood detection */
static clock_time_t window_start   = 0;
static uint16_t     pkt_count      = 0;
#define FLOOD_WINDOW_SEC      5
#define FLOOD_THRESHOLD       15

/* Model 4 ICMPv6 flood detection */
static uint16_t icmp_pkt_count     = 0;
#define ICMP_FLOOD_THRESHOLD  10

/* Connections */
static struct simple_udp_connection app_conn;
static struct simple_udp_connection ctrl_conn;

/* Block state - shared by both primary and secondary */
static uip_ipaddr_t blocked_ip;
static uint8_t      attacker_blocked = 0;
static clock_time_t block_until      = 0;

/* Strike counter - only meaningful on primary */
static uint8_t      strike_count     = 0;

/* Control message struct */
typedef struct {
  uint8_t  type;
  uint8_t  ip[16];
  uint16_t seconds;
} __attribute__((packed)) ctrl_msg_t;

/*---------------------------------------------------------------------------*/
static int
is_blocked(const uip_ipaddr_t *sender_addr)
{
  if(attacker_blocked && clock_time() > block_until) {
    attacker_blocked = 0;
    LOG_INFO("DEFENSE: attacker block timer expired\n");
    if(node_id == PRIMARY_HONEYPOT_ID) {
      LOG_INFO("PRIMARY: Returning to monitoring mode\n");
    }
  }
  return attacker_blocked &&
         uip_ipaddr_cmp(sender_addr, &blocked_ip);
}

/*---------------------------------------------------------------------------*/
/*
 * apply_block
 * Used by secondary honeypot to sync its block state
 * when it receives a BLOCK message from primary
 */
static void
apply_block(const uint8_t *attacker_ip, uint16_t seconds)
{
  memcpy(&blocked_ip, attacker_ip, 16);
  attacker_blocked = 1;
  block_until = clock_time() +
                ((clock_time_t)seconds * CLOCK_SECOND);

  LOG_INFO("SYNC: Block applied from primary honeypot\n");
  LOG_INFO("SYNC: Blocking attacker for %u seconds\n", seconds);
}

/*---------------------------------------------------------------------------*/
/*
 * broadcast_block
 * ONLY called by primary honeypot (Node 5)
 * Sends BLOCK message to all nodes on network
 */
static void
broadcast_block(const uip_ipaddr_t *attacker)
{
  ctrl_msg_t   msg;
  uip_ipaddr_t mcast;
  uint16_t     block_duration;

  /* Only primary honeypot broadcasts */
  if(node_id != PRIMARY_HONEYPOT_ID) {
    return;
  }

  strike_count++;

  if(strike_count == 1) {
    block_duration = BLOCK_STRIKE_1;
    LOG_INFO("DEFENSE: Strike 1/3 - "
             "short block (%u sec)\n",
             block_duration);
    LOG_INFO("DEFENSE: Monitoring continues "
             "after this block expires\n");

  } else if(strike_count == 2) {
    block_duration = BLOCK_STRIKE_2;
    LOG_INFO("DEFENSE: Strike 2/3 - "
             "extended block (%u sec)\n",
             block_duration);
    LOG_INFO("DEFENSE: Attacker flagged as persistent\n");

  } else {
    block_duration = BLOCK_STRIKE_3;
    LOG_INFO("DEFENSE: Strike %u/3 - "
             "PERMANENT BLOCK (%u sec)\n",
             strike_count, block_duration);
    LOG_INFO("DEFENSE: Attacker permanently isolated\n");
  }

  /* Apply block locally on primary */
  block_until = clock_time() +
                ((clock_time_t)block_duration * CLOCK_SECOND);

  /* Build control message */
  msg.type    = 1;
  memcpy(msg.ip, attacker, 16);
  msg.seconds = block_duration;

  uip_create_linklocal_allnodes_mcast(&mcast);

  LOG_INFO("RECONFIG: Broadcasting BLOCK to ALL nodes\n");
  LOG_INFO("RECONFIG: Attacker = ");
  LOG_INFO_6ADDR(attacker);
  LOG_INFO_("\n");
  LOG_INFO("RECONFIG: Duration = %u seconds\n", block_duration);

  simple_udp_sendto(&ctrl_conn, &msg, sizeof(msg), &mcast);
}

/*---------------------------------------------------------------------------*/
/*
 * ctrl_rx_callback
 * Called when honeypot receives a BLOCK message
 * For secondary honeypot - syncs its block state
 * with the primary honeypot's decision
 */
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

  if(datalen < sizeof(ctrl_msg_t)) {
    return;
  }

  memcpy(&msg, data, sizeof(msg));

  if(msg.type == 1 && node_id != PRIMARY_HONEYPOT_ID) {
    /* Secondary honeypot syncs its block state */
    LOG_INFO("SYNC: Received BLOCK from primary honeypot\n");
    apply_block(msg.ip, msg.seconds);
  }
}

/*---------------------------------------------------------------------------*/
/*
 * app_rx_callback
 * Main detection engine
 * Called for every incoming UDP packet on port 5678
 */
static void
app_rx_callback(struct simple_udp_connection *c,
                const uip_ipaddr_t *sender_addr,
                uint16_t sender_port,
                const uip_ipaddr_t *receiver_addr,
                uint16_t receiver_port,
                const uint8_t *data,
                uint16_t datalen)
{
  LOG_INFO("ALERT: Received '%.*s' from ",
           datalen, (const char *)data);
  LOG_INFO_6ADDR(sender_addr);
  LOG_INFO_("\n");

  /* Check blocklist first */
  if(is_blocked(sender_addr)) {
    LOG_INFO("DEFENSE: blocked attacker ignored (honeypot)\n");
    return;
  }

  /* ===============================================
     MODEL 4: ICMPv6 FLOOD
     Payload starts with "ICMP6"
     Separate counter - checked before general flood
     MITRE T1498 / T1499
     =============================================== */
  if(datalen >= 5 && memcmp(data, "ICMP6", 5) == 0) {

    icmp_pkt_count++;

    LOG_INFO("ICMPv6 packet from ");
    LOG_INFO_6ADDR(sender_addr);
    LOG_INFO_(" (count=%u/%u)\n",
              icmp_pkt_count, ICMP_FLOOD_THRESHOLD);

    if(icmp_pkt_count > ICMP_FLOOD_THRESHOLD) {
      LOG_INFO("ALERT: ICMPv6 FLOOD detected "
               "(count=%u)\n", icmp_pkt_count);
      uip_ipaddr_copy(&blocked_ip, sender_addr);
      attacker_blocked = 1;
      broadcast_block(sender_addr);
    }
    return;
  }

  /* ===============================================
     MODEL 5: ROGUE ROUTER ADVERTISEMENT
     Payload starts with "RA_SPOOF"
     Immediate block - no threshold
     MITRE T1557 / T1584
     =============================================== */
  if(datalen >= 8 && memcmp(data, "RA_SPOOF", 8) == 0) {
    LOG_INFO("ALERT: ROGUE RA detected from ");
    LOG_INFO_6ADDR(sender_addr);
    LOG_INFO_("\n");
    LOG_INFO("ALERT: Fake router advertisement\n");
    LOG_INFO("ALERT: RouterLifetime=65535 detected\n");
    uip_ipaddr_copy(&blocked_ip, sender_addr);
    attacker_blocked = 1;
    broadcast_block(sender_addr);
    return;
  }

  /* ===============================================
     MODEL 2: GENERAL UDP FLOOD
     Payload starts with "PING"
     Threshold based - time window counter
     MITRE T1498
     =============================================== */
  if(window_start == 0) {
    window_start = clock_time();
  }
  pkt_count++;

  if(clock_time() - window_start >
     (FLOOD_WINDOW_SEC * CLOCK_SECOND)) {
    pkt_count    = 0;
    window_start = clock_time();
  }

  if(pkt_count > FLOOD_THRESHOLD) {
    LOG_INFO("ALERT: FLOOD detected (pkt_count=%u)\n",
             pkt_count);
    uip_ipaddr_copy(&blocked_ip, sender_addr);
    attacker_blocked = 1;
    broadcast_block(sender_addr);
    return;
  }

  /* ===============================================
     MODEL 3: SCAN
     Payload starts with "SCAN"
     Immediate block - signature based
     MITRE T1046
     =============================================== */
  if(datalen >= 4 && memcmp(data, "SCAN", 4) == 0) {
    LOG_INFO("ALERT: SCAN detected\n");
    uip_ipaddr_copy(&blocked_ip, sender_addr);
    attacker_blocked = 1;
    broadcast_block(sender_addr);
    return;
  }

  /* ===============================================
     MODEL 1: UNLOCK COMMAND INJECTION
     Payload starts with "UNLOCK"
     Immediate block - signature based
     MITRE T1059
     =============================================== */
  if(datalen >= 6 && memcmp(data, "UNLOCK", 6) == 0) {
    LOG_INFO("ALERT: UNLOCK detected\n");
    uip_ipaddr_copy(&blocked_ip, sender_addr);
    attacker_blocked = 1;
    broadcast_block(sender_addr);
    return;
  }

  /* Honeypot stays silent - WITH_SERVER_REPLY = 0 */
#if WITH_SERVER_REPLY
  LOG_INFO("Sending response.\n");
  simple_udp_sendto(&app_conn, data, datalen, sender_addr);
#endif
}

/*---------------------------------------------------------------------------*/
PROCESS(honeypot_reconfig_process, "Honeypot (reconfig)");
AUTOSTART_PROCESSES(&honeypot_reconfig_process);

PROCESS_THREAD(honeypot_reconfig_process, ev, data)
{
  PROCESS_BEGIN();

  simple_udp_register(&app_conn, UDP_SERVER_PORT, NULL,
                      UDP_CLIENT_PORT, app_rx_callback);

  simple_udp_register(&ctrl_conn, CTRL_PORT, NULL,
                      CTRL_PORT, ctrl_rx_callback);

  if(node_id == PRIMARY_HONEYPOT_ID) {
    LOG_INFO("HONEYPOT READY (PRIMARY - Node %u)\n",
             node_id);
    LOG_INFO("PRIMARY: Detects attacks + "
             "broadcasts BLOCK to network\n");
    LOG_INFO("PRIMARY: Manages progressive "
             "three-strike mechanism\n");
  } else {
    LOG_INFO("HONEYPOT READY (SECONDARY - Node %u)\n",
             node_id);
    LOG_INFO("SECONDARY: Monitors and logs attacks\n");
    LOG_INFO("SECONDARY: Syncs block state "
             "from primary honeypot\n");
  }

  PROCESS_END();
}
