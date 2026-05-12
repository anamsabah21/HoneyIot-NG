/*
 * udp-server-reconfig.c
 *
 * Real IoT Device Simulation
 * Nodes 2, 3, 4 — Smart Lock, Thermostat, Lighting
 *
 * FIXED: Control connection now accepts BLOCK messages
 * from any remote port (changed UDP_CLIENT_PORT to 0)
 * This ensures honeypot BLOCK messages are received
 * and real nodes actually enforce the block
 *
 * Author: Anam Sabah Khan - G202402840
 * SEC 619 Term 252
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

/* Connections */
static struct simple_udp_connection app_conn;
static struct simple_udp_connection ctrl_conn;

/* Block state */
static uip_ipaddr_t blocked_ip;
static uint8_t      attacker_blocked   = 0;
static clock_time_t block_until        = 0;
static uint16_t     block_duration_sec = 0;

/* Statistics */
static uint32_t requests_received  = 0;
static uint32_t requests_responded = 0;
static uint32_t requests_blocked   = 0;

/* Control message from honeypot */
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
    LOG_INFO("STATUS: Block expired after %u seconds\n",
             block_duration_sec);
    LOG_INFO("STATUS: Returning to NORMAL operation\n");
    LOG_INFO("STATS: received=%lu responded=%lu "
             "blocked=%lu\n",
             (unsigned long)requests_received,
             (unsigned long)requests_responded,
             (unsigned long)requests_blocked);
  }
  return attacker_blocked &&
         uip_ipaddr_cmp(sender_addr, &blocked_ip);
}

/*---------------------------------------------------------------------------*/
/*
 * app_rx_callback
 * Handles incoming attack/application traffic on port 5678
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
  requests_received++;

  /* Check if this sender is blocked */
  if(is_blocked(sender_addr)) {
    requests_blocked++;
    LOG_INFO("DEFENSE: blocked attacker ignored (app)\n");
    return;
  }

  /* Not blocked - respond normally as legitimate IoT device */
  LOG_INFO("NORMAL: Received request '%.*s' from ",
           datalen, (const char *)data);
  LOG_INFO_6ADDR(sender_addr);
  LOG_INFO_("\n");

#if WITH_SERVER_REPLY
  LOG_INFO("NORMAL: Sending response to ");
  LOG_INFO_6ADDR(sender_addr);
  LOG_INFO_(" (acting as legitimate device)\n");
  simple_udp_sendto(&app_conn, data, datalen, sender_addr);
  requests_responded++;
#endif
}

/*---------------------------------------------------------------------------*/
/*
 * ctrl_rx_callback
 * Handles BLOCK control messages from honeypot on port 3000
 * This is how real nodes know to start blocking the attacker
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
    LOG_INFO("CTRL: Received malformed control message\n");
    return;
  }

  memcpy(&msg, data, sizeof(msg));

  if(msg.type == 1) {
    /* BLOCK instruction from honeypot */
    LOG_INFO("HONEYPOT INSTRUCTION: BLOCK received\n");
    LOG_INFO("HONEYPOT INSTRUCTION: Attacker IP = ");
    LOG_INFO_6ADDR((uip_ipaddr_t *)msg.ip);
    LOG_INFO_("\n");
    LOG_INFO("HONEYPOT INSTRUCTION: "
             "Block duration = %u seconds\n", msg.seconds);

    /* Apply the block */
    memcpy(&blocked_ip, msg.ip, 16);
    attacker_blocked    = 1;
    block_duration_sec  = msg.seconds;
    block_until = clock_time() +
                  ((clock_time_t)msg.seconds * CLOCK_SECOND);

    LOG_INFO("RECONFIG: BLOCK received. "
             "Blocking attacker for %u seconds\n",
             msg.seconds);
    LOG_INFO("RECONFIG: All traffic from attacker "
             "will now be ignored\n");
  }
}

/*---------------------------------------------------------------------------*/
PROCESS(udp_server_reconfig_process, "UDP Server (reconfig)");
AUTOSTART_PROCESSES(&udp_server_reconfig_process);

PROCESS_THREAD(udp_server_reconfig_process, ev, data)
{
  PROCESS_BEGIN();

  simple_udp_register(&app_conn, UDP_SERVER_PORT, NULL,
                      UDP_CLIENT_PORT, app_rx_callback);

  /*
   * CRITICAL FIX: Use 0 as remote port filter
   * This accepts BLOCK messages from any port
   * Previously UDP_CLIENT_PORT (8765) was used which
   * blocked honeypot control messages (sent from port 3000)
   */
  simple_udp_register(&ctrl_conn, CTRL_PORT, NULL,
                      0, ctrl_rx_callback);

  LOG_INFO("REAL NODE READY. "
           "App port %u, Ctrl port %u\n",
           UDP_SERVER_PORT, CTRL_PORT);
  LOG_INFO("REAL NODE: Operating as legitimate IoT device\n");
  LOG_INFO("REAL NODE: Listening for BLOCK instructions "
           "from honeypot on port %u\n", CTRL_PORT);

  PROCESS_END();
}
