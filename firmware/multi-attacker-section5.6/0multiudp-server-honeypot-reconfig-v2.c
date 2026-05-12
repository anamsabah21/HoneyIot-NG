/*
 * udp-server-honeypot-reconfig-v2.c
 *
 * HIGH-INTERACTION IoT HONEYPOT
 * FINAL FIXED VERSION - Multi-Attacker Support
 *
 * FIXES:
 * 1. Blocklist entries NEVER removed after expiry
 *    Strikes accumulate correctly across cycles
 * 2. Strike counter per attacker reaches 3 properly
 * 3. After Strike 3 permanent=1 never unblocks
 * 4. Multiple attackers tracked independently
 *
 * Author: Anam Sabah Khan - G202402840
 * SEC 619 Term 252 - KFUPM
 */

#include "contiki.h"
#include "net/ipv6/simple-udp.h"
#include "net/ipv6/uip.h"
#include "net/routing/routing.h"
#include "sys/node-id.h"
#include "sys/log.h"
#include <string.h>
#include <stdint.h>
#include <stdio.h>

#define LOG_MODULE "HONEYPOT"
#define LOG_LEVEL  LOG_LEVEL_INFO

#define WITH_SERVER_REPLY     0
#define UDP_CLIENT_PORT       8765
#define UDP_SERVER_PORT       5678
#define CTRL_PORT             3000
#define PRIMARY_HONEYPOT_ID   5
#define MAX_ATTACKERS         5

/* Adaptive block durations */
#define SCAN_S1    30
#define SCAN_S2    90
#define SCAN_S3    65000
#define FLOOD_S1   60
#define FLOOD_S2   120
#define FLOOD_S3   65000
#define ICMPV6_S1  60
#define ICMPV6_S2  120
#define ICMPV6_S3  65000
#define UNLOCK_S1  120
#define UNLOCK_S2  600
#define UNLOCK_S3  65000
#define ROGUE_S1   300
#define ROGUE_S2   3600
#define ROGUE_S3   65000

/* Trust */
#define TRUST_INITIAL       100
#define TRUST_SCAN_PEN      30
#define TRUST_FLOOD_PEN     20
#define TRUST_ICMPV6_PEN    20
#define TRUST_UNLOCK_PEN    50
#define TRUST_ROGUE_PEN     100
static int16_t global_trust = TRUST_INITIAL;

/* Attack types */
#define ATTACK_NONE   0
#define ATTACK_FLOOD  1
#define ATTACK_SCAN   2
#define ATTACK_UNLOCK 3
#define ATTACK_ICMPV6 4
#define ATTACK_ROGUE  5

/* Prediction */
static uint8_t last_attack       = ATTACK_NONE;
static uint8_t predictions_made  = 0;
static uint8_t predictions_right = 0;

/* Threat level */
#define THREAT_LOW      1
#define THREAT_MEDIUM   2
#define THREAT_HIGH     3
#define THREAT_CRITICAL 4
static uint8_t threat_level  = 0;
static uint8_t scan_seen     = 0;
static uint8_t flood_seen    = 0;
static uint8_t unlock_seen   = 0;
static uint8_t icmpv6_seen   = 0;
static uint8_t rogue_seen    = 0;

/* Forensic log */
#define MAX_LOG 10
typedef struct {
  uint8_t  type;
  uint8_t  strike;
  uint32_t time_sec;
} log_entry_t;
static log_entry_t forensic_log[MAX_LOG];
static uint8_t     log_count = 0;

/* Flood detection */
static clock_time_t win_start = 0;
static uint16_t     pkt_count = 0;
#define FLOOD_WIN_SEC 5
#define FLOOD_THRESH  15

/* ICMPv6 detection */
static uint16_t icmp_count = 0;
#define ICMP_THRESH 10

/*
 * ATTACKER ENTRY
 * used = 1 means this slot has an attacker entry
 * used never goes back to 0 once set
 * This ensures strikes accumulate correctly
 *
 * currently_blocked = 1 means block is active now
 * permanent = 1 means Strike 3 reached - never unblock
 * strikes = count of detections (max 3)
 */
typedef struct {
  uint8_t      used;
  uint8_t      currently_blocked;
  uint8_t      permanent;
  uint8_t      strikes;
  uip_ipaddr_t ip;
  clock_time_t block_until;
} attacker_entry_t;

static attacker_entry_t attackers[MAX_ATTACKERS];

/* Connections */
static struct simple_udp_connection app_conn;
static struct simple_udp_connection ctrl_conn;

/* Control message */
typedef struct {
  uint8_t  type;
  uint8_t  ip[16];
  uint16_t seconds;
} __attribute__((packed)) ctrl_msg_t;

/*─────────────────────────────────────────────────────────
  find_attacker
  Finds existing entry for IP
  Returns index or -1 if not found
─────────────────────────────────────────────────────────*/
static int8_t
find_attacker(const uip_ipaddr_t *ip)
{
  uint8_t i;
  for(i = 0; i < MAX_ATTACKERS; i++) {
    if(attackers[i].used &&
       uip_ipaddr_cmp(&attackers[i].ip, ip)) {
      return (int8_t)i;
    }
  }
  return -1;
}

/*─────────────────────────────────────────────────────────
  find_or_add_attacker
  Finds existing or creates new entry
  Returns index or -1 if table full
─────────────────────────────────────────────────────────*/
static int8_t
find_or_add_attacker(const uip_ipaddr_t *ip)
{
  int8_t idx = find_attacker(ip);
  if(idx >= 0) return idx;

  /* Find unused slot */
  uint8_t i;
  for(i = 0; i < MAX_ATTACKERS; i++) {
    if(!attackers[i].used) {
      attackers[i].used              = 1;
      attackers[i].currently_blocked = 0;
      attackers[i].permanent         = 0;
      attackers[i].strikes           = 0;
      attackers[i].block_until       = 0;
      uip_ipaddr_copy(&attackers[i].ip, ip);
      LOG_INFO("BLOCKLIST: New attacker "
               "added at slot %u\n", i);
      return (int8_t)i;
    }
  }
  LOG_INFO("BLOCKLIST: Table full\n");
  return -1;
}

/*─────────────────────────────────────────────────────────
  is_blocked
  Returns 1 if sender is currently blocked
  Handles permanent and temporary blocks
  NEVER removes used entries
─────────────────────────────────────────────────────────*/
static int
is_blocked(const uip_ipaddr_t *sender)
{
  int8_t idx = find_attacker(sender);
  if(idx < 0) return 0;

  /* Permanent block never expires */
  if(attackers[idx].permanent) {
    return 1;
  }

  /* Temporary block - check timer */
  if(attackers[idx].currently_blocked) {
    if(clock_time() > attackers[idx].block_until) {
      /*
       * Block expired but entry STAYS
       * Only clear currently_blocked flag
       * strikes and used remain unchanged
       * This is the key fix
       */
      attackers[idx].currently_blocked = 0;
      LOG_INFO("DEFENSE: Block expired "
               "for attacker slot %d "
               "(strikes=%u)\n",
               idx, attackers[idx].strikes);
      LOG_INFO("PRIMARY: Monitoring this "
               "attacker - will re-detect\n");
      return 0;
    }
    return 1;
  }

  return 0;
}

/*─────────────────────────────────────────────────────────
  get_block_duration
─────────────────────────────────────────────────────────*/
static uint16_t
get_block_duration(uint8_t atype, uint8_t strike)
{
  switch(atype) {
    case ATTACK_SCAN:
      return strike==1?SCAN_S1:strike==2?SCAN_S2:SCAN_S3;
    case ATTACK_FLOOD:
      return strike==1?FLOOD_S1:strike==2?FLOOD_S2:FLOOD_S3;
    case ATTACK_ICMPV6:
      return strike==1?ICMPV6_S1:strike==2?ICMPV6_S2:ICMPV6_S3;
    case ATTACK_UNLOCK:
      return strike==1?UNLOCK_S1:strike==2?UNLOCK_S2:UNLOCK_S3;
    case ATTACK_ROGUE:
      return strike==1?ROGUE_S1:strike==2?ROGUE_S2:ROGUE_S3;
    default: return 60;
  }
}

/*─────────────────────────────────────────────────────────
  update_trust
─────────────────────────────────────────────────────────*/
static void
update_trust(uint8_t atype)
{
  int16_t p = 0;
  switch(atype) {
    case ATTACK_SCAN:   p = TRUST_SCAN_PEN;   break;
    case ATTACK_FLOOD:  p = TRUST_FLOOD_PEN;  break;
    case ATTACK_ICMPV6: p = TRUST_ICMPV6_PEN; break;
    case ATTACK_UNLOCK: p = TRUST_UNLOCK_PEN; break;
    case ATTACK_ROGUE:  p = TRUST_ROGUE_PEN;  break;
    default: break;
  }
  global_trust -= p;
  if(global_trust < 0) global_trust = 0;

  LOG_INFO("TRUST: Score=%d/100 (penalty=%d)\n",
           (int)global_trust, (int)p);

  if(global_trust == 0) {
    LOG_INFO("TRUST: ZERO - network under "
             "persistent attack\n");
  } else if(global_trust <= 30) {
    LOG_INFO("TRUST: CRITICAL\n");
  } else if(global_trust <= 60) {
    LOG_INFO("TRUST: LOW\n");
  }
}

/*─────────────────────────────────────────────────────────
  update_threat_level
─────────────────────────────────────────────────────────*/
static void
update_threat_level(void)
{
  uint8_t types =
    (scan_seen?1:0)+(flood_seen?1:0)+
    (unlock_seen?1:0)+(icmpv6_seen?1:0)+
    (rogue_seen?1:0);

  uint8_t nl =
    types>=4?THREAT_CRITICAL:
    types>=3?THREAT_HIGH:
    types>=2?THREAT_MEDIUM:THREAT_LOW;

  if(nl != threat_level) {
    threat_level = nl;
    if(threat_level==THREAT_LOW)
      LOG_INFO("THREAT LEVEL: LOW\n");
    else if(threat_level==THREAT_MEDIUM)
      LOG_INFO("THREAT LEVEL: MEDIUM - "
               "coordinated attack possible\n");
    else if(threat_level==THREAT_HIGH)
      LOG_INFO("THREAT LEVEL: HIGH - "
               "multi-vector attack\n");
    else
      LOG_INFO("THREAT LEVEL: CRITICAL\n");
  }
}

/*─────────────────────────────────────────────────────────
  make_prediction
─────────────────────────────────────────────────────────*/
static void
make_prediction(uint8_t current)
{
  const char *n[]={"NONE","FLOOD","SCAN",
                   "UNLOCK","ICMPV6","ROGUE_RA"};

  if(last_attack != ATTACK_NONE) {
    uint8_t ok=0;
    if(last_attack==ATTACK_SCAN &&
       (current==ATTACK_FLOOD||
        current==ATTACK_UNLOCK)) ok=1;
    else if((last_attack==ATTACK_FLOOD||
             last_attack==ATTACK_ICMPV6)&&
            current==ATTACK_ROGUE) ok=1;

    if(ok) {
      predictions_right++;
      LOG_INFO("PREDICTION: CORRECT - "
               "%s followed %s\n",
               n[current],n[last_attack]);
    } else {
      LOG_INFO("PREDICTION: New pattern - "
               "%s after %s\n",
               n[current],n[last_attack]);
    }
    if(predictions_made>0)
      LOG_INFO("PREDICTION: Accuracy=%u/%u\n",
               predictions_right,predictions_made);
  }

  if(current==ATTACK_SCAN) {
    LOG_INFO("PREDICTION: SCAN - likely "
             "next: FLOOD or UNLOCK\n");
    predictions_made++;
  } else if(current==ATTACK_FLOOD) {
    LOG_INFO("PREDICTION: FLOOD - likely "
             "next: ROGUE_RA\n");
    predictions_made++;
  } else if(current==ATTACK_ICMPV6) {
    LOG_INFO("PREDICTION: ICMPv6 - likely "
             "next: ROGUE_RA\n");
    predictions_made++;
  }
  last_attack=current;
}

/*─────────────────────────────────────────────────────────
  log_forensic
─────────────────────────────────────────────────────────*/
static void
log_forensic(uint8_t atype, uint8_t strike)
{
  const char *n[]={"NONE","FLOOD","SCAN",
                   "UNLOCK","ICMPV6","ROGUE_RA"};
  if(log_count>=MAX_LOG) {
    uint8_t i;
    for(i=0;i<MAX_LOG-1;i++)
      forensic_log[i]=forensic_log[i+1];
    log_count=MAX_LOG-1;
  }
  forensic_log[log_count].type=atype;
  forensic_log[log_count].strike=strike;
  forensic_log[log_count].time_sec=
    (uint32_t)(clock_time()/CLOCK_SECOND);
  log_count++;

  LOG_INFO("FORENSIC [%u]: Attack=%s "
           "Strike=%u Time=%lus\n",
           log_count,n[atype],strike,
           (unsigned long)
           forensic_log[log_count-1].time_sec);

  uint8_t i;
  for(i=0;i<log_count;i++) {
    LOG_INFO("  HISTORY [%u]: %s "
             "Strike=%u at %lus\n",
             i+1,n[forensic_log[i].type],
             forensic_log[i].strike,
             (unsigned long)
             forensic_log[i].time_sec);
  }
}

/*─────────────────────────────────────────────────────────
  send_deception
─────────────────────────────────────────────────────────*/
static void
send_deception(const uip_ipaddr_t *ip, uint8_t atype)
{
  char fake[128];
  switch(atype) {
    case ATTACK_SCAN:
      snprintf(fake,sizeof(fake),
               "DEVICE:THERMOSTAT,TEMP:22.5C,"
               "HUMIDITY:45%%,STATUS:ONLINE");
      LOG_INFO("DECEPTION: Fake thermostat data\n");
      break;
    case ATTACK_UNLOCK:
      snprintf(fake,sizeof(fake),
               "UNLOCK:SUCCESS,DOOR:OPEN,"
               "AUTH:GRANTED");
      LOG_INFO("DECEPTION: Fake UNLOCK success\n");
      break;
    case ATTACK_FLOOD:
      snprintf(fake,sizeof(fake),
               "PONG:OK,STATUS:ALIVE,LOAD:12%%");
      LOG_INFO("DECEPTION: Fake ping response\n");
      break;
    case ATTACK_ICMPV6:
      snprintf(fake,sizeof(fake),
               "ECHO:REPLY,ID:0xBEEF,TTL:64");
      LOG_INFO("DECEPTION: Fake ICMPv6 reply\n");
      break;
    case ATTACK_ROGUE:
      snprintf(fake,sizeof(fake),
               "RA:ACCEPTED,PREFIX:fd00::/64");
      LOG_INFO("DECEPTION: Fake RA acceptance\n");
      break;
    default:
      snprintf(fake,sizeof(fake),
               "STATUS:OK,DEVICE:IOT_NODE");
      break;
  }
  simple_udp_sendto(&app_conn,fake,strlen(fake),ip);
  LOG_INFO("DECEPTION: False data sent - "
           "attacker being misled\n");
}

/*─────────────────────────────────────────────────────────
  broadcast_block
  Sends BLOCK control message to all nodes
─────────────────────────────────────────────────────────*/
static void
broadcast_block(const uip_ipaddr_t *attacker_ip,
                uint16_t duration)
{
  ctrl_msg_t   msg;
  uip_ipaddr_t mcast;

  msg.type    = 1;
  memcpy(msg.ip, attacker_ip, 16);
  msg.seconds = duration;

  uip_create_linklocal_allnodes_mcast(&mcast);

  LOG_INFO("RECONFIG: Broadcasting BLOCK "
           "for attacker = ");
  LOG_INFO_6ADDR(attacker_ip);
  LOG_INFO_("\n");
  LOG_INFO("RECONFIG: Duration = "
           "%u seconds\n", duration);

  simple_udp_sendto(&ctrl_conn,
                    &msg, sizeof(msg), &mcast);
}

/*─────────────────────────────────────────────────────────
  do_block
  Core blocking function - PRIMARY only
  Manages per-attacker strike counter correctly
  Strikes accumulate because entry is never removed
─────────────────────────────────────────────────────────*/
static void
do_block(const uip_ipaddr_t *attacker_ip,
         uint8_t atype)
{
  if(node_id != PRIMARY_HONEYPOT_ID) {
    LOG_INFO("MONITOR: Deferring to "
             "primary (Node %u)\n",
             PRIMARY_HONEYPOT_ID);
    return;
  }

  int8_t idx = find_or_add_attacker(attacker_ip);
  if(idx < 0) {
    LOG_INFO("BLOCKLIST: Full\n");
    return;
  }

  /* Already permanent - just re-apply */
  if(attackers[idx].permanent) {
    LOG_INFO("DEFENSE: Slot %d already "
             "permanent - re-applying\n", idx);
    attackers[idx].currently_blocked = 1;
    attackers[idx].block_until = clock_time() +
      ((clock_time_t)SCAN_S3 * CLOCK_SECOND);
    broadcast_block(attacker_ip, SCAN_S3);
    return;
  }

  /*
   * Increment strike for this attacker
   * Entry was KEPT when block expired so
   * strikes correctly accumulate to 3
   */
  attackers[idx].strikes++;
  if(attackers[idx].strikes > 3) {
    attackers[idx].strikes = 3;
  }

  uint8_t  strike   = attackers[idx].strikes;
  uint16_t duration = get_block_duration(atype,
                                         strike);

  if(strike == 1) {
    LOG_INFO("DEFENSE: Slot %d - "
             "Strike 1/3 - block %u sec\n",
             idx, duration);
    LOG_INFO("DEFENSE: Monitoring continues "
             "after block expires\n");

  } else if(strike == 2) {
    LOG_INFO("DEFENSE: Slot %d - "
             "Strike 2/3 - extended %u sec\n",
             idx, duration);
    LOG_INFO("DEFENSE: Attacker flagged "
             "as persistent\n");

  } else {
    /* Strike 3 - permanent */
    attackers[idx].permanent = 1;
    LOG_INFO("DEFENSE: Slot %d - "
             "Strike 3/3 - PERMANENT BLOCK\n",
             idx);
    LOG_INFO("DEFENSE: Attacker permanently "
             "isolated - counter capped at 3\n");
  }

  /* Apply block */
  attackers[idx].currently_blocked = 1;
  attackers[idx].block_until = clock_time() +
    ((clock_time_t)duration * CLOCK_SECOND);

  broadcast_block(attacker_ip, duration);
}

/*─────────────────────────────────────────────────────────
  handle_detection
  Runs all features then blocks the attacker
─────────────────────────────────────────────────────────*/
static void
handle_detection(const uip_ipaddr_t *sender,
                 uint8_t atype,
                 const char *alert_msg,
                 const char *adaptive_msg)
{
  /* Save IP first - critical */
  uip_ipaddr_t saved;
  uip_ipaddr_copy(&saved, sender);

  LOG_INFO("%s\n", alert_msg);

  /* Deception */
  if(node_id == PRIMARY_HONEYPOT_ID) {
    send_deception(&saved, atype);
  }

  /* Prediction */
  make_prediction(atype);

  /* Trust */
  update_trust(atype);

  /* Threat level */
  update_threat_level();

  /* Forensic */
  int8_t idx = find_or_add_attacker(&saved);
  uint8_t ns = (idx>=0)?
    (attackers[idx].strikes+1):1;
  if(ns>3) ns=3;
  log_forensic(atype, ns);

  /* Adaptive message */
  if(adaptive_msg) LOG_INFO("%s\n", adaptive_msg);

  /* Block */
  do_block(&saved, atype);
}

/*─────────────────────────────────────────────────────────
  ctrl_rx_callback
  Secondary syncs block state from primary
─────────────────────────────────────────────────────────*/
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

  if(msg.type==1 &&
     node_id != PRIMARY_HONEYPOT_ID) {
    uip_ipaddr_t aip;
    memcpy(&aip, msg.ip, 16);

    int8_t idx = find_or_add_attacker(&aip);
    if(idx < 0) return;

    LOG_INFO("SYNC: Block from primary "
             "for slot %d\n", idx);

    attackers[idx].currently_blocked = 1;
    attackers[idx].block_until = clock_time() +
      ((clock_time_t)msg.seconds * CLOCK_SECOND);

    if(msg.seconds >= 65000) {
      attackers[idx].permanent = 1;
      LOG_INFO("SYNC: PERMANENT block "
               "slot %d\n", idx);
    } else {
      LOG_INFO("SYNC: Blocking slot %d "
               "for %u sec\n", idx, msg.seconds);
    }
  }
}

/*─────────────────────────────────────────────────────────
  app_rx_callback - Detection engine
─────────────────────────────────────────────────────────*/
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

  if(is_blocked(sender_addr)) {
    LOG_INFO("DEFENSE: blocked attacker "
             "ignored (honeypot)\n");
    return;
  }

  /* MODEL 4: ICMPv6 */
  if(datalen>=5 && memcmp(data,"ICMP6",5)==0) {
    icmp_count++;
    LOG_INFO("ICMPv6 packet (count=%u/%u)\n",
             icmp_count,ICMP_THRESH);
    if(icmp_count>ICMP_THRESH) {
      icmpv6_seen=1;
      char m[64];
      snprintf(m,sizeof(m),
               "ALERT: ICMPv6 FLOOD (count=%u)",
               icmp_count);
      handle_detection(sender_addr,ATTACK_ICMPV6,m,
                       "ADAPTIVE: ICMPv6 medium block");
    }
    return;
  }

  /* MODEL 5: ROGUE RA */
  if(datalen>=8 && memcmp(data,"RA_SPOOF",8)==0) {
    LOG_INFO("ALERT: ROGUE RA detected\n");
    LOG_INFO("ALERT: Fake router advertisement\n");
    LOG_INFO("ALERT: RouterLifetime=65535\n");
    rogue_seen=1;
    handle_detection(sender_addr,ATTACK_ROGUE,
                     "ALERT: Routing attack",
                     "ADAPTIVE: Rogue RA MAXIMUM block");
    return;
  }

  /* MODEL 2: FLOOD */
  if(win_start==0) win_start=clock_time();
  pkt_count++;
  if(clock_time()-win_start>
     (FLOOD_WIN_SEC*CLOCK_SECOND)) {
    pkt_count=0;
    win_start=clock_time();
  }
  if(pkt_count>FLOOD_THRESH) {
    char m[64];
    snprintf(m,sizeof(m),
             "ALERT: FLOOD (pkt_count=%u)",
             pkt_count);
    flood_seen=1;
    handle_detection(sender_addr,ATTACK_FLOOD,m,
                     "ADAPTIVE: Flood medium block");
    return;
  }

  /* MODEL 3: SCAN */
  if(datalen>=4 && memcmp(data,"SCAN",4)==0) {
    scan_seen=1;
    handle_detection(sender_addr,ATTACK_SCAN,
                     "ALERT: SCAN detected",
                     "ADAPTIVE: Scan shorter block");
    return;
  }

  /* MODEL 1: UNLOCK */
  if(datalen>=6 && memcmp(data,"UNLOCK",6)==0) {
    LOG_INFO("ALERT: Physical security threat\n");
    unlock_seen=1;
    handle_detection(sender_addr,ATTACK_UNLOCK,
                     "ALERT: UNLOCK detected",
                     "ADAPTIVE: UNLOCK LONG block");
    return;
  }

#if WITH_SERVER_REPLY
  simple_udp_sendto(&app_conn,data,datalen,
                    sender_addr);
#endif
}

/*─────────────────────────────────────────────────────────
  PROCESS
─────────────────────────────────────────────────────────*/
PROCESS(honeypot_proc, "Honeypot Final");
AUTOSTART_PROCESSES(&honeypot_proc);

PROCESS_THREAD(honeypot_proc, ev, data)
{
  PROCESS_BEGIN();

  uint8_t i;
  for(i=0;i<MAX_ATTACKERS;i++) {
    attackers[i].used              = 0;
    attackers[i].currently_blocked = 0;
    attackers[i].permanent         = 0;
    attackers[i].strikes           = 0;
  }

  simple_udp_register(&app_conn,
                      UDP_SERVER_PORT,NULL,
                      UDP_CLIENT_PORT,
                      app_rx_callback);
  simple_udp_register(&ctrl_conn,
                      CTRL_PORT,NULL,
                      CTRL_PORT,
                      ctrl_rx_callback);

  if(node_id==PRIMARY_HONEYPOT_ID) {
    LOG_INFO("HONEYPOT READY (PRIMARY %u)\n",
             node_id);
    LOG_INFO("MAX ATTACKERS: %u\n",MAX_ATTACKERS);
    LOG_INFO("FIX: Strikes accumulate correctly\n");
    LOG_INFO("FIX: Permanent block at Strike 3\n");
  } else {
    LOG_INFO("HONEYPOT READY (SECONDARY %u)\n",
             node_id);
  }

  PROCESS_END();
}
