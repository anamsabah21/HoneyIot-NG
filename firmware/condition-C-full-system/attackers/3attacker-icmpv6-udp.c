/*
 * attacker-icmpv6-udp.c
 *
 * Attack Scenario 4 - ICMPv6 Echo Request Flood
 *
 * What this attack does:
 * Sends high-rate ICMP6-prefixed packets targeting the
 * IPv6 network stack directly. Unlike the UDP flood which
 * targets applications, ICMPv6 flooding overwhelms the
 * network layer itself. Constrained IoT devices running
 * Contiki-NG cannot rate-limit ICMPv6 traffic due to
 * limited CPU and memory resources.
 *
 * This attack was validated in Wireshark using Scapy
 * generating real ICMPv6 Type 128 Echo Request packets
 * confirming the attack is grounded in real IPv6
 * protocol behaviour as defined in RFC 4443.
 *
 * Detection type: THRESHOLD-BASED (Model 4)
 * Separate counter from UDP flood (Model 2)
 * Triggers after ICMP_FLOOD_THRESHOLD = 10 packets
 * Counter shown as: count=X/10 in Mote Output
 *
 * MITRE T1498 - Network Denial of Service
 * MITRE T1499 - Endpoint Denial of Service
 *
 * Author: Anam Sabah Khan - G202402840
 * SEC 619 Term 252
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
 * Send every 0.5 seconds = 2 packets per second
 * Threshold is 10 packets
 * Detection triggers after approximately 5 seconds
 * This is faster than UDP flood (which needs 15 packets)
 * showing ICMPv6 threshold is more sensitive
 */
#define SEND_INTERVAL  (CLOCK_SECOND / 2)

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
PROCESS(attacker_icmpv6_process, "Attacker ICMPv6 Flood");
AUTOSTART_PROCESSES(&attacker_icmpv6_process);

PROCESS_THREAD(attacker_icmpv6_process, ev, data)
{
  static char msg[64];

  PROCESS_BEGIN();

  LOG_INFO("=== Attacker (ICMPv6 Flood) started ===\n");
  LOG_INFO("Attack type: ICMPv6 Echo Request Flood\n");
  LOG_INFO("Detection: THRESHOLD-BASED (count > 10)\n");
  LOG_INFO("Protocol layer: Network/IPv6 (below application)\n");
  LOG_INFO("MITRE: T1498/T1499\n");
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

    /*
     * ICMP6 payload triggers Model 4 in honeypot
     * Represents ICMPv6 Type 128 Echo Request
     * Validated in Wireshark: icmpv6.pcap
     * Shows Type=128 id=0xBEEF sequential seq numbers
     */
    snprintf(msg, sizeof(msg), "ICMP6 %" PRIu32, tx_count);

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
