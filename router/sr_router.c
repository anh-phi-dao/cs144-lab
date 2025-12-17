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
  sr->packets = NULL;
  sr_print_if_list(sr);

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

  printf("*** -> Received packet of length %d from %s \n", len, interface);

/* fill in code here */
#ifdef DEBUG_MESSAGE
  print_hdrs(packet, len);
#endif
  sr_ethernet_hdr_t *ether_packet_header = (sr_ethernet_hdr_t *)packet;

#ifdef DEBUG_ETHERNET
  print_hdr_eth((uint8_t *)ether_packet_header);
  printf("%s\n", interface);
#endif
  /*if recevie an ARP packet*/
  if (ntohs(ether_packet_header->ether_type) == ethertype_arp)
  {
    sr_arp_hdr_t *apr_packet = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
#ifdef DEBUG_ARP
    print_hdr_arp((uint8_t *)apr_packet);
#endif
    /*if this packet is ARP reply*/
    /*cache sender ip address and its corresponding MAC address to ARP table*/
    if (ntohs(apr_packet->ar_op) == arp_op_reply)
    {
#ifdef DEBUG_ARP_REPLY
      printf("Reply from other host\n");
#endif

      /*you should only cache the entry if the target IP address is one of your router's IP addresses*/
      struct sr_arpentry *entry_cache = sr_arpcache_lookup(&sr->cache, apr_packet->ar_sip);
      if (entry_cache == NULL)
      {
        cache_IP_and_MAC_from_ARP_reply(sr, packet);
      }
      else
      {
        free(entry_cache);
        entry_cache = NULL;
      }
    }
    /*if receive ARP request to router's IP addresses*/
    /*send an ARP reply back to the sender host*/
    else if (ntohs(apr_packet->ar_op) == arp_op_request)
    {
#ifdef DEBUG_ARP_REQUEST
      printf("Receive request\n");
#endif
      construct_and_send_ARP_reply_based_in_ether_frame(sr, packet);
    }
  }
  /*if router receive an ip packet*/
  else if (ntohs(ether_packet_header->ether_type) == ethertype_ip)
  {
    sr_ip_hdr_t *ip_packet_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
#ifdef DEBUG_IP
    print_hdr_ip((uint8_t *)ip_packet_hdr);
#endif
    /*checksum to make sure IP header is not corrupted*/
    if (check_correct_IP_packet_checksum(ip_packet_hdr) == CHECKSUM_ERROR)
    {
#ifdef DEBUG_IP
      printf("This IP packet has an error");
#endif
      return;
    }
    /*decrease time to live, if time to live drop to 0, drop this packet*/
    ip_packet_hdr->ip_ttl--;
    if (ip_packet_hdr->ip_ttl == 0)
    {
      /*send ICMP ttl expired*/
      create_and_send_ICMP(sr, packet, len, interface, TTL_EXPIRED);
      return;
    }
    compute_checksum_of_IP_Packet(ip_packet_hdr);
    /*check if the destination IP is one of router's IP addresses*/
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
        /*if the packet is ICMP echo request, send back an echo reply*/
        if (GET_ICMP_TYPE(icmp_header->icmp_type, icmp_header->icmp_code) == ECHO_REQUEST)
        {
          create_and_send_ICMP(sr, packet, len, interface, ECHO_REPLY);
        }
      }
      /*if the packet is a normal TCP/UDP, send ICMP port unreachable*/
      else
      {
        create_and_send_ICMP(sr, packet, len, interface, DESTINATION_PORT_UNREACHABLE);
      }
    }
    /*if it is for other host*/
    else
    {
      /*check routing table with destination IP address*/
      struct sr_rt *matched_entry = check_routing_table(sr, ip_packet_hdr);
      /*if there is a entry that match with destination IP*/
      if (matched_entry != NULL)
      {
        /*check ARP_cache*/
        struct sr_arpentry *arp_inside_cache = sr_arpcache_lookup(&sr->cache, ip_packet_hdr->ip_dst);
        /*if IP->MAC mapping exist, forwarding the  packet based on IP->MAC mapping inside cache*/
        if (arp_inside_cache != NULL)
        {
#ifdef DEBUG_IP
          printf("Forwarding imediately to %s without creating ARP request\n", matched_entry->interface);
#endif
          forwarding_the_packet_without_create_ARP_request(sr, packet, len, arp_inside_cache, matched_entry->interface);
          free(arp_inside_cache);
        }
        else
        {
/*send ARP request to cache*/
#ifdef DEBUG_IP
          printf("Creating ARP request because\n");
          print_addr_ip_int(ntohl(ip_packet_hdr->ip_dst));
          printf("does not exist \n");
#endif
          create_ARP_request_and_send_to_ARP_cache_based_on_IP_packet(sr, packet, matched_entry);
          add_packet_to_linkest_list(sr, packet, len, matched_entry->interface);
#ifdef DEBUG_PACKET
          printf("The packet that being stored inside router\n");
          print_all_packet_inside_linked_list(sr);
#endif
        }
      }
      /*if there is no router that fix to destination address, send ICMP net unreachable*/
      else
      {
        create_and_send_ICMP(sr, packet, len, interface, DESTINATION_NETWORK_UNREACHABLE);
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
    if (memcmp(interface, interface_list->name, sr_IFACE_NAMELEN) == 0)
    {
      return interface_list;
    }
    interface_list = interface_list->next;
  }
  return NULL;
}

void construct_and_send_ARP_reply_based_in_ether_frame(struct sr_instance *sr, uint8_t *packet)
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

void compute_checksum_of_IP_Packet(sr_ip_hdr_t *IP_Packet)
{
  IP_Packet->ip_sum = 0;
  IP_Packet->ip_sum = cksum(IP_Packet, sizeof(sr_ip_hdr_t));
}

void compute_checksum_of_ICMP_Packet(sr_icmp_hdr_t *ICMP_Packet)
{
  ICMP_Packet->icmp_sum = 0;
  ICMP_Packet->icmp_sum = cksum(ICMP_Packet, sizeof(sr_icmp_hdr_t));
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

void create_ARP_request_and_send_to_ARP_cache_based_on_IP_packet(struct sr_instance *sr, uint8_t *packet, struct sr_rt *entry)
{
  unsigned short packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t *send_packet = malloc(packet_len);
  sr_ethernet_hdr_t *send_ether_hdr = (sr_ethernet_hdr_t *)(send_packet);
  sr_arp_hdr_t *send_arp_hdr = (sr_arp_hdr_t *)(send_packet + sizeof(sr_ethernet_hdr_t));
  sr_ip_hdr_t *receive_ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  struct sr_if *matched_interface = find_interface_entry(sr, entry->interface);

  if (matched_interface != NULL)
  {
    memcpy(send_ether_hdr->ether_shost, matched_interface->addr, ETHER_ADDR_LEN);
    int i;
    for (i = 0; i < ETHER_ADDR_LEN; i++)
    {
      send_ether_hdr->ether_dhost[i] = 0xff;
    }
    send_ether_hdr->ether_type = htons(ethertype_arp);
    send_arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
    send_arp_hdr->ar_pro = htons(ethertype_ip);
    send_arp_hdr->ar_hln = ETHER_ADDR_LEN;
    send_arp_hdr->ar_pln = IPV4_ADDR_LEN;
    send_arp_hdr->ar_op = htons(arp_op_request);
    memcpy(send_arp_hdr->ar_sha, matched_interface->addr, ETHER_ADDR_LEN);
    send_arp_hdr->ar_sip = matched_interface->ip;
    for (i = 0; i < ETHER_ADDR_LEN; i++)
    {
      send_arp_hdr->ar_tha[i] = 0;
    }
    send_arp_hdr->ar_tip = receive_ip_hdr->ip_dst;
#ifdef DEBUG_ARP
    print_hdr_arp((uint8_t *)send_arp_hdr);
#endif
    sr_arpcache_queuereq(&sr->cache, receive_ip_hdr->ip_dst, send_packet, packet_len, matched_interface->name);
  }

  free(send_packet);
  send_packet = NULL;
}

void forwarding_the_packet_without_create_ARP_request(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_arpentry *cache, char *iface)
{
  uint8_t *send_packet = malloc(len);
  memset(send_packet, 0, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t));
  memcpy(send_packet, packet, len);
  sr_ethernet_hdr_t *send_ether_hdr = (sr_ethernet_hdr_t *)(send_packet);
  struct sr_if *corresponding_iface = find_interface_entry(sr, iface);
  if (corresponding_iface != NULL)
  {
    memcpy(send_ether_hdr->ether_dhost, cache->mac, ETHER_ADDR_LEN);
    memcpy(send_ether_hdr->ether_shost, corresponding_iface->addr, ETHER_ADDR_LEN);
    sr_send_packet(sr, send_packet, len, iface);
  }

  free(send_packet);
  send_packet = NULL;
}

void create_and_send_ICMP(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface, unsigned short types)
{
  uint8_t *send_packet = malloc(len);
  memset(send_packet, 0, len);
  memcpy(send_packet, packet, len);

  sr_ethernet_hdr_t *receive_ether_hdr = (sr_ethernet_hdr_t *)(packet);
  sr_ethernet_hdr_t *send_ether_hdr = (sr_ethernet_hdr_t *)(send_packet);
  sr_ip_hdr_t *receive_ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  sr_ip_hdr_t *send_ip_hdr = (sr_ip_hdr_t *)(send_packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_hdr_t *send_icmp_hdr = (sr_icmp_hdr_t *)(send_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  struct sr_if *send_interface = find_interface_entry(sr, interface);
  if (send_interface != NULL)
  {
    memcpy(send_ether_hdr->ether_dhost, receive_ether_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(send_ether_hdr->ether_shost, send_interface->addr, ETHER_ADDR_LEN);
    send_ip_hdr->ip_src = receive_ip_hdr->ip_dst;
    send_ip_hdr->ip_dst = receive_ip_hdr->ip_src;
    compute_checksum_of_IP_Packet(send_ip_hdr);
    send_icmp_hdr->icmp_code = (uint8_t)(types & 0xff);
    send_icmp_hdr->icmp_type = (uint8_t)(types >> 8);
    compute_checksum_of_ICMP_Packet(send_icmp_hdr);
    sr_send_packet(sr, send_packet, len, send_interface->name);
  }
  free(send_packet);
  send_packet = NULL;
}

void cache_IP_and_MAC_from_ARP_reply(struct sr_instance *sr, uint8_t *packet)
{
  sr_arp_hdr_t *receive_arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  struct sr_if *router_interface = compare_target_ip_address_with_current_interface_list(sr, receive_arp_hdr);
  if (router_interface != NULL)
  {
    sr_arpcache_insert(&sr->cache, receive_arp_hdr->ar_sha, receive_arp_hdr->ar_sip);
  }
}

/*function for adding ICMP packet*/
void add_packet_to_linkest_list(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *iface)
{
  struct sr_packet *list = sr->packets;
  struct sr_packet *new_packect = malloc(sizeof(struct sr_packet));
  new_packect->buf = malloc(len);
  memset(new_packect->buf, 0, len);
  memcpy(new_packect->buf, packet, len);

  new_packect->len = len;
#ifdef DEBUG_PACKET
  printf("Lenght of stored packet %d\n", new_packect->len);
#endif
  new_packect->iface = malloc(sr_IFACE_NAMELEN * sizeof(char));
  memcpy(new_packect->iface, iface, sr_IFACE_NAMELEN);
  new_packect->next = NULL;
  while (list != NULL)
  {
    if (list->next == NULL)
    {
      list->next = new_packect;
      return;
    }
    list = list->next;
  }
  sr->packets = new_packect;
}

void delete_packet_out_of_linkest_list(struct sr_instance *sr, struct sr_packet *depacket)
{
  struct sr_packet *list = sr->packets;
  struct sr_packet *next = NULL;
  struct sr_packet *previous = NULL;
  while (list != NULL)
  {
    if (list == depacket)
    {
      next = list->next;
      break;
    }
    previous = list;
    list = list->next;
  }
  free(list->buf);
  list->buf = NULL;
  free(list->iface);
  list->iface = NULL;
  free(list);
  list = NULL;
  if (previous != NULL)
  {
    previous->next = next;
  }
  else
  {
    sr->packets = next;
  }
}

void delele_all_packet(struct sr_instance *sr)
{
  struct sr_packet *list = sr->packets;
  struct sr_packet *temp;
  while (list != NULL)
  {
    temp = list;
    list = list->next;
    free(temp->buf);
    temp->buf = NULL;
    free(temp->iface);
    temp->iface = NULL;
    free(temp);
    temp = NULL;
  }
  sr->packets = NULL;
}

void print_all_packet_inside_linked_list(struct sr_instance *sr)
{
  struct sr_packet *list = sr->packets;
  while (list != NULL)
  {
    print_hdrs(list->buf, list->len);
    list = list->next;
  }
}
