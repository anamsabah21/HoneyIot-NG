/*
 * attacker-scan-node8.c
 * Multi-attacker Node 8 - Network Scan
 * Uses same port as original scan attacker
 * Author: Anam Sabah Khan G202402840
 */

#include "contiki.h"
#include "net/ipv6/simple-udp.h"
#include "net/ipv6/uip.h"
#include "sys/log.h"
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#define LOG_MODULE "ATTACKER"
#define LOG_LEVEL  LOG_LEVEL_INFO

#define UDP_CLIENT_PORT   8765
#define UDP_SERVER_PORT   5678
#define SEND_INTERVAL     (CLOCK_SECOND)

static struct simple_udp_connection udp_conn;
static struct etimer               periodic_timer;
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
PROCESS(attacker_scan_n8, "Attacker Node8 SCAN");
AUTOSTART_PROCESSES(&attacker_scan_n8);

PROCESS_THREAD(attacker_scan_n8, ev, data)
{
  static char msg[64];

  PROCESS_BEGIN();

  LOG_INFO("=== Node 8: SCAN attacker ===\n");
  LOG_INFO("Attack: Network Scan (MITRE T1046)\n");
  LOG_INFO("Payload: SCAN | Rate: 1 pkt/sec\n");

  simple_udp_register(&udp_conn,
                      UDP_CLIENT_PORT, NULL,
                      UDP_SERVER_PORT,
                      udp_rx_callback);

  uip_create_linklocal_allnodes_mcast(&dest_ipaddr);
  etimer_set(&periodic_timer, SEND_INTERVAL);

  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(
      etimer_expired(&periodic_timer));

    snprintf(msg, sizeof(msg),
             "SCAN %" PRIu32, tx_count);

    LOG_INFO("Sending '%s' "
             "(Tx=%" PRIu32 " Rx=%" PRIu32 ")\n",
             msg, tx_count, rx_count);

    simple_udp_sendto(&udp_conn, msg,
                      strlen(msg), &dest_ipaddr);
    tx_count++;
    etimer_reset(&periodic_timer);
  }

  PROCESS_END();
}
