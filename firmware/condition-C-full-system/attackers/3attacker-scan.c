/*
 * attacker-scan.c
 *
 * Attack Scenario 2 - Network Discovery / Reconnaissance
 *
 * What this attack does:
 * Sends SCAN-prefixed messages to all nodes on the network
 * to probe and map active devices before a real attack.
 * Reconnaissance is always the first phase of a sophisticated
 * intrusion. In real networks this is done using ICMPv6
 * Neighbour Solicitation messages (Type 135 as validated
 * in Wireshark). In Cooja the SCAN keyword triggers
 * immediate signature-based detection in the honeypot.
 *
 * Detection type: SIGNATURE-BASED (immediate)
 * No threshold needed - any SCAN is suspicious
 * Triggers on the very first packet received
 *
 * MITRE T1046 - Network Service Discovery
 *
 * Author: Anam Sabah Khan - G202402840
 * SEC 619 Term 252
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

/*
 * Send one SCAN probe every 1 second
 * Detection is immediate so rate does not affect
 * how quickly detection triggers
 * After block activates attacker keeps sending to
 * demonstrate persistence - Tx rises Rx stays frozen
 */
#define SEND_INTERVAL  (CLOCK_SECOND)

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
  LOG_INFO("RECEIVED response '%.*s' from ",
           datalen, (const char *)data);
  LOG_INFO_6ADDR(sender_addr);
  LOG_INFO_(" (Tx=%" PRIu32 " Rx=%" PRIu32 ")\n",
            tx_count, rx_count);
}

/*---------------------------------------------------------------------------*/
PROCESS(attacker_scan_process, "Attacker SCAN (multicast)");
AUTOSTART_PROCESSES(&attacker_scan_process);

PROCESS_THREAD(attacker_scan_process, ev, data)
{
  static char msg[64];

  PROCESS_BEGIN();

  LOG_INFO("=== Attacker (Network Scan) started ===\n");
  LOG_INFO("Attack type: Network Discovery / Recon\n");
  LOG_INFO("Detection: SIGNATURE-BASED (immediate)\n");
  LOG_INFO("MITRE: T1046 - Network Service Discovery\n");
  LOG_INFO("Target: ff02::1 (all-nodes multicast)\n");

  simple_udp_register(&udp_conn,
                      UDP_CLIENT_PORT,
                      NULL,
                      UDP_SERVER_PORT,
                      udp_rx_callback);

  uip_create_linklocal_allnodes_mcast(&dest_ipaddr);

  etimer_set(&periodic_timer, SEND_INTERVAL);

  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer));

    snprintf(msg, sizeof(msg), "SCAN %" PRIu32, tx_count);

    LOG_INFO("Sending '%s' to ff02::1 "
             "(Tx=%" PRIu32 " Rx=%" PRIu32 ")\n",
             msg, tx_count, rx_count);

    simple_udp_sendto(&udp_conn, msg, strlen(msg),
                      &dest_ipaddr);
    tx_count++;
    etimer_reset(&periodic_timer);
  }

  PROCESS_END();
}
