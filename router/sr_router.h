/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "sr_protocol.h"
#include "sr_arpcache.h"

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ##args)
#define DebugMAC(x)                        \
  do                                       \
  {                                        \
    int ivyl;                              \
    for (ivyl = 0; ivyl < 5; ivyl++)       \
      printf("%02x:",                      \
             (unsigned char)(x[ivyl]));    \
    printf("%02x", (unsigned char)(x[5])); \
  } while (0)
#else
#define Debug(x, args...) \
  do                      \
  {                       \
  } while (0)
#define DebugMAC(x) \
  do                \
  {                 \
  } while (0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024

/*my preprocessor define*/
#define MY_DEBUG 1

#if MY_DEBUG == 1
/*#define DEBUG_INTERFACE*/
#define DEBUG_ETHERNET
#define DEBUG_ETHERTYPE
#define DEBUG_ARP
#define DEBUG_IP
#define DEBUG_ICMP
/*#define DEBUG_ROUTING_TABLE*/
#endif

#define CHECKSUM_ERROR 1
#define CHECKSUM_CORRECT 0

/*-----------------------------------------------------------------------------*/

/* forward declare */
struct sr_if;
struct sr_rt;

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

struct sr_instance
{
  int sockfd;        /* socket to server */
  char user[32];     /* user name */
  char host[32];     /* host name */
  char template[30]; /* template name if any */
  unsigned short topo_id;
  struct sockaddr_in sr_addr;  /* address to server */
  struct sr_if *if_list;       /* list of interfaces */
  struct sr_rt *routing_table; /* routing table */
  struct sr_arpcache cache;    /* ARP cache */
  pthread_attr_t attr;
  FILE *logfile;
};

/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance *sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance *, uint8_t *, unsigned int, const char *);
int sr_connect_to_server(struct sr_instance *, unsigned short, char *);
int sr_read_from_server(struct sr_instance *);

/* -- sr_router.c -- */
void sr_init(struct sr_instance *);
void sr_handlepacket(struct sr_instance *, uint8_t *, unsigned int, char *);

/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance *, const char *);
void sr_set_ether_ip(struct sr_instance *, uint32_t);
void sr_set_ether_addr(struct sr_instance *, const unsigned char *);
void sr_print_if_list(struct sr_instance *);

/*my function*/
struct sr_if *compare_target_ip_address_with_current_interface_list(struct sr_instance *sr, sr_arp_hdr_t *received_request);
struct sr_if *compare_packet_destination_ip_with_current_interface_list(struct sr_instance *sr, sr_ip_hdr_t *IP_packet);
void construct_and_send_ARP_based_in_ether_frame(struct sr_instance *sr, uint8_t *packet);
int check_correct_IP_packet_checksum(sr_ip_hdr_t *IP_Packet);
int check_correct_ICMP_checksum(sr_icmp_hdr_t *ICMP_header);
uint8_t find_matched_bits(struct sr_rt *entry, sr_ip_hdr_t *received_packet);
struct sr_rt *check_routing_table(struct sr_instance *sr, sr_ip_hdr_t *received_packet);
void create_and_send_ICMP_net_unreachable_based_on_IP_packet(struct sr_instance *sr, uint8_t *packet, char *interface);

#endif /* SR_ROUTER_H */
