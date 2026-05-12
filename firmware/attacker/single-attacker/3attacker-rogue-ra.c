/*
 * attacker-rogue-ra.c
 *
 * Attack Scenario 5 - Rogue Router Advertisement
 *
 * What this attack does:
 * Broadcasts fake Router Advertisement messages claiming
 * to be the default router with maximum RouterLifetime
 * of 65535 seconds. All IoT devices on the network
 * automatically update their routing tables to send
 * all traffic through the attacker (Man-in-the-Middle).
 *
 * This is the most sophisticated attack in the simulation.
 * Unlike other attacks that target individual functions,
 * ONE single Rogue RA packet can redirect ALL network
 * traffic from ALL devices simultaneously.
 *
 * This attack was validated in Wireshark using Scapy
 * generating real ICMPv6 Type 134 Router Advertisement
 * packets. Wireshark clearly showed RouterLifetime=65535
 * which is the definitive indicator of a Rogue RA attack
 * as documented in RFC 6104.
 *
 * Detection type: SIGNATURE-BASED (immediate)
 * No threshold - even ONE rogue RA is dangerous
 * Triggers on the very first packet received
 * This achieves the lowest attacker Rx of all attacks
 *
 * MITRE T1557 - Adversary-in-the-Middle
 * MITRE T1584 - Compromise Infrastructure
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
 * Send one Rogue RA every 1 second
 * Detection is immediate on first packet
 * Rate does not affect detection speed
 * After block attacker keeps sending to show
 * persistence - Tx rises but Rx stays frozen
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
  LOG_INFO("RECEIVED '%.*s' from ",
           datalen, (const char *)data);
  LOG_INFO_6ADDR(sender_addr);
  LOG_INFO_(" (Tx=%" PRIu32 " Rx=%" PRIu32 ")\n",
            tx_count, rx_count);
}

/*---------------------------------------------------------------------------*/
PROCESS(attacker_rogue_ra_process, "Attacker Rogue RA");
AUTOSTART_PROCESSES(&attacker_rogue_ra_process);

PROCESS_THREAD(attacker_rogue_ra_process, ev, data)
{
  static char msg[64];

  PROCESS_BEGIN();

  LOG_INFO("=== Attacker (Rogue RA) started ===\n");
  LOG_INFO("Attack type: Rogue Router Advertisement\n");
  LOG_INFO("Detection: SIGNATURE-BASED (immediate)\n");
  LOG_INFO("Protocol layer: Network/NDP\n");
  LOG_INFO("MITRE: T1557/T1584\n");
  LOG_INFO("RouterLifetime: 65535 (maximum - attack indicator)\n");
  LOG_INFO("Target: ff02::1 (all-nodes multicast)\n");
  LOG_INFO("WARNING: One packet compromises entire network\n");

  simple_udp_register(&udp_conn,
                      UDP_CLIENT_PORT,
                      NULL,
                      UDP_SERVER_PORT,
                      udp_rx_callback);

  uip_create_linklocal_allnodes_mcast(&dest_ipaddr);

  etimer_set(&periodic_timer, SEND_INTERVAL);

  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer));

    /*
     * RA_SPOOF payload triggers Model 5 in honeypot
     * Represents real ICMPv6 Type 134 Router Advertisement
     * with RouterLifetime=65535 and spoofed prefix fd00::/64
     * Validated in Wireshark: rogue_ra.pcap
     * Shows RouterLifetime=65535 highlighted in packet details
     */
    snprintf(msg, sizeof(msg),
             "RA_SPOOF %" PRIu32, tx_count);

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
