/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance *sr)
{
  /* REQUIRES */
  assert(sr);

  /* Initialize cache and cache cleanup thread */
  sr_arpcache_init(&(sr->cache));

  pthread_attr_init(&(sr->attr));
  pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
  pthread_t thread;

  pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

  /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance *sr,
                     uint8_t *packet /* lent */,
                     unsigned int len,
                     char *interface /* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n", len);

  /* fill in code here */
  sr_ethernet_hdr_t *ether_packet_header = (sr_ethernet_hdr_t *)packet;
#ifdef DEBUG_ETHERNET
  print_hdr_eth((uint8_t *)ether_packet_header);
  printf("%s\n", interface);
#endif
  /*recevie an ARP packet*/
  if (ntohs(ether_packet_header->ether_type) == ethertype_arp)
  {
    sr_arp_hdr_t *apr_packet = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    if (ntohs(apr_packet->ar_op) == arp_op_reply)
    {
    }
    else if (ntohs(apr_packet->ar_op) == arp_op_request)
    {
      construct_and_send_ARP_based_in_ether_frame(sr, packet);
    }
  }
  /*recevie an ip packet*/
  else if (ntohs(ether_packet_header->ether_type) == ethertype_ip)
  {
    sr_ip_hdr_t *ip_packet_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
#ifdef DEBUG_IP
    print_hdr_ip((uint8_t *)ip_packet_hdr);
#endif
    if (check_correct_IP_packet_checksum(ip_packet_hdr) == CHECKSUM_ERROR)
    {
#ifdef DEBUG_IP
      printf("This IP packet has an error");
#endif
      return;
    }
    ip_packet_hdr->ip_ttl--;
    if (ip_packet_hdr->ip_ttl == 0)
    {
      /*send ICMP ttl expired*/
      return;
    }

    struct sr_if *current_interface = compare_packet_destination_ip_with_current_interface_list(sr, ip_packet_hdr);
    /*it is for me as router*/

    if (current_interface != NULL)
    {
      if (ip_packet_hdr->ip_p == ip_protocol_icmp)
      {
        sr_icmp_hdr_t *icmp_header = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        if (check_correct_ICMP_checksum(icmp_header) == CHECKSUM_ERROR)
        {
#ifdef DEBUG_ICMP
          printf("There is error in ICMP packet\n");
#endif
          return;
        }
      }
    }
    /*it is for other host*/
    else
    {
      struct sr_rt *matched_entry = check_routing_table(sr, ip_packet_hdr);
      if (matched_entry != NULL)
      {
        /*check ARP_cache*/
        struct sr_arpentry *arp_inside_cache = sr_arpcache_lookup(&sr->cache, ip_packet_hdr->ip_dst);
        if (arp_inside_cache != NULL)
        {
          sr_send_packet(sr, packet, len, arp_inside_cache->mac);
        }
        else
        {
        }
        free(arp_inside_cache);
      }
      else
      {
        create_and_send_ICMP_net_unreachable_based_on_IP_packet(sr, packet, interface);
      }
    }
  }

} /* end sr_ForwardPacket */

/*my function*/
struct sr_if *compare_target_ip_address_with_current_interface_list(struct sr_instance *sr, sr_arp_hdr_t *received_request)
{
  struct sr_if *interface_list = sr->if_list;
  while (interface_list != NULL)
  {
    if (ntohl(interface_list->ip) == ntohl(received_request->ar_tip))
    {
      return interface_list;
    }
    interface_list = interface_list->next;
  }
  return NULL;
}

struct sr_if *compare_packet_destination_ip_with_current_interface_list(struct sr_instance *sr, sr_ip_hdr_t *IP_packet)
{
  struct sr_if *interface_list = sr->if_list;
  while (interface_list != NULL)
  {
    if (ntohl(interface_list->ip) == ntohl(IP_packet->ip_dst))
    {
      return interface_list;
    }
    interface_list = interface_list->next;
  }
  return NULL;
}

struct sr_if *find_interface_entry(struct sr_instance *sr, char *interface)
{
  struct sr_if *interface_list = sr->if_list;
  while (interface_list != NULL)
  {
    if (memcmp(interface, interface_list->name, 32) == 0)
    {
      return interface_list;
    }
    interface_list = interface_list->next;
  }
  return NULL;
}

void construct_and_send_ARP_based_in_ether_frame(struct sr_instance *sr, uint8_t *packet)
{
  uint8_t *send_packet = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
  memset(send_packet, 0, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
  sr_ethernet_hdr_t *receive_ether_hdr = (sr_ethernet_hdr_t *)(packet);
  sr_ethernet_hdr_t *send_ether_hdr = (sr_ethernet_hdr_t *)(send_packet);
  sr_arp_hdr_t *receive_arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  sr_arp_hdr_t *send_arp_hdr = (sr_arp_hdr_t *)(send_packet + sizeof(sr_ethernet_hdr_t));

  send_ether_hdr->ether_type = htons(ethertype_arp);

  struct sr_if *interface = compare_target_ip_address_with_current_interface_list(sr, receive_arp_hdr);
  if (interface != NULL)
  {
    memcpy(send_ether_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN);
    memcpy(send_ether_hdr->ether_dhost, receive_ether_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(send_arp_hdr, receive_arp_hdr, sizeof(sr_arp_hdr_t));
    memcpy(send_arp_hdr->ar_sha, interface->addr, ETHER_ADDR_LEN);
    send_arp_hdr->ar_sip = interface->ip;
    memcpy(send_arp_hdr->ar_tha, receive_arp_hdr->ar_sha, ETHER_ADDR_LEN);
    send_arp_hdr->ar_tip = receive_arp_hdr->ar_sip;
    send_arp_hdr->ar_op = htons(arp_op_reply);
#ifdef DEBUG_ARP
    print_hdrs(send_packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
#endif
    sr_send_packet(sr, send_packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), interface->name);
  }

  free(send_packet);
  send_packet = NULL;
}

int check_correct_IP_packet_checksum(sr_ip_hdr_t *IP_Packet)
{
  uint16_t packet_checksum = IP_Packet->ip_sum;
  IP_Packet->ip_sum = 0;
  int result;
  if (cksum(IP_Packet, sizeof(sr_ip_hdr_t)) != packet_checksum)
  {
    result = CHECKSUM_ERROR;
  }
  else
  {
    result = CHECKSUM_CORRECT;
  }
  IP_Packet->ip_sum = packet_checksum;
  return result;
}

int check_correct_ICMP_checksum(sr_icmp_hdr_t *ICMP_header)
{
  uint16_t header_checksum = ICMP_header->icmp_sum;
  ICMP_header->icmp_sum = 0;
  int result;
  if (cksum(ICMP_header, sizeof(sr_icmp_hdr_t)) != header_checksum)
  {
    result = CHECKSUM_ERROR;
  }
  else
  {
    result = CHECKSUM_CORRECT;
  }
  ICMP_header->icmp_sum = header_checksum;
  return result;
}

uint8_t find_matched_bits(struct sr_rt *entry, sr_ip_hdr_t *received_packet)
{
  uint8_t count = 0;
  uint32_t entry_address = entry->dest.s_addr;
  uint32_t destionation_address = received_packet->ip_dst;
  int i;
  for (i = 31; i >= 0; i--)
  {
    if (((entry_address >> i) ^ (destionation_address >> i)) == 0)
    {
      count++;
    }
    else
    {
      break;
    }
  }
  return count;
}

struct sr_rt *check_routing_table(struct sr_instance *sr, sr_ip_hdr_t *received_packet)
{
  struct sr_rt *entry = sr->routing_table;
  uint8_t max_prefix_match = 0;
  unsigned int track_entry = 1;
  unsigned int track_max_entry = 0;
#ifdef DEBUG_ROUTING_TABLE
  printf("Value of destination address = %x\n", received_packet->ip_dst);
#endif
  while (entry != NULL)
  {
#ifdef DEBUG_ROUTING_TABLE
    printf("Value of routing entry address = %x\n", entry->dest.s_addr);
    print_addr_ip(entry->dest);
#endif
    uint8_t prefix_match = find_matched_bits(entry, received_packet);
    if (prefix_match > max_prefix_match)
    {
      max_prefix_match = prefix_match;
      track_max_entry = track_entry;
    }
    track_entry++;
    entry = entry->next;
  }
  if (track_max_entry == 0)
  {
    return NULL;
  }
#ifdef DEBUG_ROUTING_TABLE
  printf("Max entry value = %d\n", track_max_entry);
#endif
  entry = sr->routing_table;
  unsigned int i;
  for (i = 1; i < track_max_entry; i++)
  {
    entry = entry->next;
  }
  return entry;
}

void create_and_send_ICMP_net_unreachable_based_on_IP_packet(struct sr_instance *sr, uint8_t *packet, char *interface)
{
  uint8_t *send_packet = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t));
  memset(send_packet, 0, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t));
  sr_ethernet_hdr_t *receive_ether_hdr = (sr_ethernet_hdr_t *)(packet);
  sr_ethernet_hdr_t *send_ether_hdr = (sr_ethernet_hdr_t *)(send_packet);
  sr_ip_hdr_t *receive_ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  sr_ip_hdr_t *send_ip_hdr = (sr_ip_hdr_t *)(send_packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_hdr_t *send_icmp_hdr = (sr_icmp_hdr_t *)(send_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_icmp_hdr_t));

  struct sr_if *received_packet_interface = find_interface_entry(sr, interface);

  if (received_packet_interface != NULL)
  {
    memcpy(send_ether_hdr->ether_shost, received_packet_interface->addr, ETHER_ADDR_LEN);
    memcpy(send_ether_hdr->ether_dhost, receive_ether_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(send_ip_hdr, receive_ip_hdr, sizeof(sr_ip_hdr_t));
    send_ip_hdr->ip_p = ip_protocol_icmp;

    send_ip_hdr->ip_len = htons(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t));

    send_icmp_hdr->icmp_type = 3;
    send_icmp_hdr->icmp_code = 0;
    send_icmp_hdr->icmp_sum = cksum(send_icmp_hdr, sizeof(sr_icmp_hdr_t));

#ifdef DEBUG_ARP
    print_hdrs(send_packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
#endif
    sr_send_packet(sr, send_packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), received_packet_interface->name);
  }
  free(send_packet);
  send_packet = NULL;
}

void create_ARP_request_and_send_to_ARP_cache_based_on_IP_packet(struct sr_instance *sr)
{
}