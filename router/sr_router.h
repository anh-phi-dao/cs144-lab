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
#define IPV4_ADDR_LEN 4

#define MY_DEBUG 0

#if MY_DEBUG == 0
/*#define DEBUG_MESSAGE*/
#define ETHER_TYPE
#define IP_TYPE
#define DEBUG_TTL
/*#define DEBUG_INTERFACE*/
/*#define DEBUG_ETHERNET*/
/*#define DEBUG_ETHERTYPE*/
/*#define DEBUG_ARP*/
/*#define DEBUG_ARP_REPLY*/
/*#define DEBUG_ARP_REQUEST*/
/*#define DEBUG_IP*/
#define DEBUG_ICMP
/*#define DEBUG_ROUTING_TABLE*/
/*#define DEBUG_PACKET*/
/*#define DEBUG_ERROR*/
#endif

#define CHECKSUM_ERROR 1
#define CHECKSUM_CORRECT 0

/*-----------------------------------------------------------------------------*/

/*Types of ICMP*/
#define ECHO_REPLY UINT16_C(0 << 8 | 0)
#define DESTINATION_NETWORK_UNREACHABLE UINT16_C(3 << 8 | 0)
#define DESTINATION_HOST_UNREACHABLE UINT16_C(3 << 8 | 1)
#define DESTINATION_PROTOCOL_UNREACHABLE UINT16_C(3 << 8 | 2)
#define DESTINATION_PORT_UNREACHABLE UINT16_C(3 << 8 | 3)
#define DESTINATION_NETWORK_UNKNOW UINT16_C(3 << 8 | 6)
#define DESTINATION_HOST_UNKNOW UINT16_C(3 << 8 | 7)
#define SOURCE_QUENCH UINT16_C(4 << 8 | 0)
#define ECHO_REQUEST UINT16_C(8 << 8 | 0)
#define ROUTER_DISCOVERY UINT16_C(10 << 8 | 0)
#define TTL_EXPIRED UINT16_C(11 << 8 | 0)
#define IP_HEADER_BAD UINT16_C(12 << 8 | 0)
/*-------------*/

#define GET_ICMP_TYPE(type, code) UINT16_C(type << 8 | code)

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
  struct sr_packet *packets;   /*store packet that need to be transmitted*/
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
/**
 * @brief find the interface based on received target ip address of ARP message
 * @return address of the interface data structure
 * @note Do not delete the returned structure
 */
struct sr_if *compare_target_ip_address_with_current_interface_list(struct sr_instance *sr, sr_arp_hdr_t *received_request);
/**
 * @brief find the interface based on destination IP address inside and IP packet
 * @return address of the interface data structure
 * @note Do not delete the returned structure
 */
struct sr_if *compare_packet_destination_ip_with_current_interface_list(struct sr_instance *sr, sr_ip_hdr_t *IP_packet);
/**
 * @brief find the interface based on the interface name
 * @return address of the interface data structure
 * @note Do not delete the returned structure
 */
struct sr_if *find_interface_entry(struct sr_instance *sr, char *interface);
/**
 * @brief based on an ARP request to the router, create a ARP reply and sen back to sender host
 */
void construct_and_send_ARP_reply_based_in_ether_frame(struct sr_instance *sr, uint8_t *packet);
/**
 * @brief Check correct checksum of IP packet
 * @return CHECKSUM_ERROR=1 CHECKSUM_CORRECT=0
 */
int check_correct_IP_packet_checksum(sr_ip_hdr_t *IP_Packet);
/**
 * @brief Check correct checksum of ICMP packet
 * @return CHECKSUM_ERROR=1 CHECKSUM_CORRECT=0
 */
int check_correct_ICMP_checksum(sr_icmp_hdr_t *ICMP_header);
void compute_checksum_of_IP_Packet(sr_ip_hdr_t *IP_Packet);
void compute_checksum_of_ICMP_Packet(sr_icmp_hdr_t *ICMP_Packet);
/** */
uint8_t find_matched_bits(struct sr_rt *entry, sr_ip_hdr_t *received_packet);
/**
 * @brief check routing table that correponsding to destination address of an ip packet
 * @return address of the interface data structure
 * @note Do not delete the returned structure
 */
struct sr_rt *check_routing_table(struct sr_instance *sr, sr_ip_hdr_t *received_packet);

/**
 * @brief create and send ARP request to request queue, each 1 second ARP requests inside cache will be sent to corresponding host
 */
void create_ARP_request_and_send_to_ARP_cache_based_on_IP_packet(struct sr_instance *sr, uint8_t *packet, struct sr_rt *entry);
void forwarding_the_packet_without_create_ARP_request(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_arpentry *cache, char *iface);
void create_and_send_ICMP(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface, unsigned short types);
/**
 * @brief cache IP to MAC mapping to ARP table(ARP cache)
 */
void cache_IP_and_MAC_from_ARP_reply(struct sr_instance *sr, uint8_t *packet);

/*function for ICMP_packet linkest list*/
void add_packet_to_linkest_list(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *iface);
void delete_packet_out_of_linkest_list(struct sr_instance *sr, struct sr_packet *depacket);
void delele_all_packet(struct sr_instance *sr);
void print_all_packet_inside_linked_list(struct sr_instance *sr);
#endif /* SR_ROUTER_H */
