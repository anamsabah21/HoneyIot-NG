/*
 * udp-server-honeypot-reconfig-v2.c
 *
 * PASSIVE MODE - Detection only, NO broadcast
 * Used for baseline comparison (Condition B)
 *
 * Honeypot detects all attacks and logs them
 * but does NOT send BLOCK to real nodes.
 * Real nodes keep responding to attacker.
 *
 * This isolates the contribution of autonomous
 * reconfiguration in HoneyIoT-NG.
 *
 * Author: Anam Sabah Khan - G202402840
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

#define WITH_SERVER_REPLY     0

#define UDP_CLIENT_PORT       8765
#define UDP_SERVER_PORT       5678
#define CTRL_PORT             3000

#define PRIMARY_HONEYPOT_ID   5

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

/* Block state */
static uip_ipaddr_t blocked_ip;
static uint8_t      attacker_blocked = 0;
static clock_time_t block_until      = 0;

/* Strike counter */
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
 * broadcast_block - PASSIVE MODE
 *
 * Detection and logging still happen fully.
 * Strike counter still increments.
 * Block duration still calculated.
 *
 * ONLY the actual send is disabled.
 * Real nodes will NOT receive BLOCK instruction.
 */
static void
broadcast_block(const uip_ipaddr_t *attacker)
{
  ctrl_msg_t   msg;
  uip_ipaddr_t mcast;
  uint16_t     block_duration;

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

  /* Apply block locally on honeypot only */
  block_until = clock_time() +
                ((clock_time_t)block_duration * CLOCK_SECOND);

  /* Build control message */
  msg.type    = 1;
  memcpy(msg.ip, attacker, 16);
  msg.seconds = block_duration;

  uip_create_linklocal_allnodes_mcast(&mcast);

  /* ================================================
   * PASSIVE MODE - BROADCAST DISABLED
   * Detection happens but real nodes are NOT notified
   * This line is commented out intentionally
   * to simulate passive-only honeypot behaviour
   * ================================================ */
  LOG_INFO("PASSIVE MODE: Detection logged, "
           "broadcast suppressed\n");
  LOG_INFO("RECONFIG: Attacker = ");
  LOG_INFO_6ADDR(attacker);
  LOG_INFO_("\n");
  LOG_INFO("RECONFIG: Duration would be "
           "%u seconds\n", block_duration);

  /* THIS LINE IS DISABLED FOR PASSIVE MODE */
  /* simple_udp_sendto(&ctrl_conn, &msg,
                       sizeof(msg), &mcast);   */
}

/*---------------------------------------------------------------------------*/
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
    LOG_INFO("SYNC: Received BLOCK from primary honeypot\n");
    apply_block(msg.ip, msg.seconds);
  }
}

/*---------------------------------------------------------------------------*/
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

  /* Honeypot itself still blocks after detection */
  if(is_blocked(sender_addr)) {
    LOG_INFO("DEFENSE: blocked attacker "
             "ignored (honeypot)\n");
    return;
  }

  /* MODEL 4: ICMPv6 FLOOD */
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

  /* MODEL 5: ROGUE ROUTER ADVERTISEMENT */
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

  /* MODEL 2: GENERAL UDP FLOOD */
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
    LOG_INFO("ALERT: FLOOD detected "
             "(pkt_count=%u)\n", pkt_count);
    uip_ipaddr_copy(&blocked_ip, sender_addr);
    attacker_blocked = 1;
    broadcast_block(sender_addr);
    return;
  }

  /* MODEL 3: SCAN */
  if(datalen >= 4 && memcmp(data, "SCAN", 4) == 0) {
    LOG_INFO("ALERT: SCAN detected\n");
    uip_ipaddr_copy(&blocked_ip, sender_addr);
    attacker_blocked = 1;
    broadcast_block(sender_addr);
    return;
  }

  /* MODEL 1: UNLOCK COMMAND INJECTION */
  if(datalen >= 6 && memcmp(data, "UNLOCK", 6) == 0) {
    LOG_INFO("ALERT: UNLOCK detected\n");
    uip_ipaddr_copy(&blocked_ip, sender_addr);
    attacker_blocked = 1;
    broadcast_block(sender_addr);
    return;
  }

#if WITH_SERVER_REPLY
  simple_udp_sendto(&app_conn, data, datalen, sender_addr);
#endif
}

/*---------------------------------------------------------------------------*/
PROCESS(honeypot_reconfig_process, "Honeypot (passive)");
AUTOSTART_PROCESSES(&honeypot_reconfig_process);

PROCESS_THREAD(honeypot_reconfig_process, ev, data)
{
  PROCESS_BEGIN();

  simple_udp_register(&app_conn, UDP_SERVER_PORT, NULL,
                      UDP_CLIENT_PORT, app_rx_callback);

  simple_udp_register(&ctrl_conn, CTRL_PORT, NULL,
                      CTRL_PORT, ctrl_rx_callback);

  if(node_id == PRIMARY_HONEYPOT_ID) {
    LOG_INFO("HONEYPOT READY - PASSIVE MODE "
             "(Node %u)\n", node_id);
    LOG_INFO("PASSIVE: Detects attacks and logs only\n");
    LOG_INFO("PASSIVE: Real nodes NOT notified\n");
    LOG_INFO("PASSIVE: Broadcast DISABLED\n");
  } else {
    LOG_INFO("HONEYPOT READY - PASSIVE MODE "
             "SECONDARY (Node %u)\n", node_id);
    LOG_INFO("SECONDARY: Monitors and logs attacks\n");
  }

  PROCESS_END();
}
