#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"

/*
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr)
{
    /* Fill this in */
    struct sr_arpreq *arp_request_list = sr->cache.requests;
    while (arp_request_list != NULL)
    {
#ifdef DEBUG_ARP
        printf("Finding this address \n");
        print_addr_ip_int(ntohl(arp_request_list->ip));
#endif
        struct sr_arpentry *arp_inside_cache = sr_arpcache_lookup(&sr->cache, arp_request_list->ip);
        if (arp_inside_cache != NULL)
        {
            struct sr_arpreq *temp_arp_request = arp_request_list;
            arp_request_list = arp_request_list->next;
#ifdef DEBUG_ARP
            printf("Destroying the arp request\n\n");
#endif
            sr_arpreq_destroy(&sr->cache, temp_arp_request);
            continue;
        }

        if (send_ARP_packet_to_other_host(sr, arp_request_list) == INVALID_REQUEST)
        {
            struct sr_arpreq *temp_arp_request = arp_request_list;
            arp_request_list = arp_request_list->next;
            sr_arpreq_destroy(&sr->cache, temp_arp_request);
        }
        else
        {
            arp_request_list = arp_request_list->next;
        }
    }
    send_packet_in_linkest_list_to_other_host(sr);
}

int send_ARP_packet_to_other_host(struct sr_instance *sr, struct sr_arpreq *arp_requests)
{
    arp_requests->sent = time(NULL);
    if (arp_requests->times_sent >= 5)
    {
/*create ICMP host unreachable*/
#ifdef DEBUG_ARP
        printf("*** ->Request has become invalid\n");
#endif
        return INVALID_REQUEST;
    }
    struct sr_packet *arp_packet = arp_requests->packets;
    while (arp_packet != NULL)
    {
#ifdef DEBUG_ARP
        printf("*** ->Prepare sending the packet and that packets is\n");
        print_hdrs(arp_packet->buf, arp_packet->len);
#endif
        sr_send_packet(sr, arp_packet->buf, arp_packet->len, arp_packet->iface);
        arp_packet = arp_packet->next;
    }
    arp_requests->sent = time(NULL);
    arp_requests->times_sent++;
    return VALID_REQUEST;
}

void send_packet_in_linkest_list_to_other_host(struct sr_instance *sr)
{
    struct sr_packet *packet_track = sr->packets;
    struct sr_packet *packet_temp;
    while (packet_track != NULL)
    {

        sr_ethernet_hdr_t *ether_hdr = (sr_ethernet_hdr_t *)(packet_track->buf);
        sr_ip_hdr_t *ip_packet_hdr = (sr_ip_hdr_t *)(packet_track->buf + sizeof(sr_ethernet_hdr_t));
        struct sr_arpentry *arp_inside_cache = sr_arpcache_lookup(&sr->cache, ip_packet_hdr->ip_dst);
        if (arp_inside_cache != NULL)
        {
            memcpy(ether_hdr->ether_dhost, arp_inside_cache->mac, ETHER_ADDR_LEN);
            struct sr_if *coresponding_interface = find_interface_entry(sr, packet_track->iface);
            if (coresponding_interface == NULL)
            {
                return;
            }
            memcpy(ether_hdr->ether_shost, coresponding_interface->addr, ETHER_ADDR_LEN);
#ifdef DEBUG_IP
            printf("Forwarding the %d bytes packet to %s with MAC:\n", packet_track->len, coresponding_interface->name);
            print_addr_eth(coresponding_interface->addr);
            print_hdrs(packet_track->buf, packet_track->len);
#endif
            sr_send_packet(sr, packet_track->buf, packet_track->len, packet_track->iface);
            packet_temp = packet_track;
            packet_track = packet_track->next;
            delete_packet_out_of_linkest_list(sr, packet_temp);
#ifdef DEBUG_PACKET
            printf("The remaining packet inside router\n");
            print_all_packet_inside_linked_list(sr);
#endif
            free(arp_inside_cache);
        }
        else
        {
            packet_track = packet_track->next;
        }
    }
}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));

    struct sr_arpentry *entry = NULL, *copy = NULL;

    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++)
    {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip))
        {
            entry = &(cache->entries[i]);
        }
    }

    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry)
    {
        copy = (struct sr_arpentry *)malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }

    pthread_mutex_unlock(&(cache->lock));

    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.

   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet, /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));

    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next)
    {
        if (req->ip == ip)
        {
            break;
        }
    }

    /* If the IP wasn't found, add it */
    if (!req)
    {
        req = (struct sr_arpreq *)calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }

    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface)
    {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));

        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
        new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }

    pthread_mutex_unlock(&(cache->lock));

    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));

    struct sr_arpreq *req, *prev = NULL, *next = NULL;
    for (req = cache->requests; req != NULL; req = req->next)
    {
        if (req->ip == ip)
        {
            if (prev)
            {
                next = req->next;
                prev->next = next;
            }
            else
            {
                next = req->next;
                cache->requests = next;
            }

            break;
        }
        prev = req;
    }

    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++)
    {
        if (!(cache->entries[i].valid))
            break;
    }

    if (i != SR_ARPCACHE_SZ)
    {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }

    pthread_mutex_unlock(&(cache->lock));

    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry)
{
    pthread_mutex_lock(&(cache->lock));

    if (entry)
    {
        struct sr_arpreq *req, *prev = NULL, *next = NULL;
        for (req = cache->requests; req != NULL; req = req->next)
        {
            if (req == entry)
            {
                if (prev)
                {
                    next = req->next;
                    prev->next = next;
                }
                else
                {
                    next = req->next;
                    cache->requests = next;
                }

                break;
            }
            prev = req;
        }

        struct sr_packet *pkt, *nxt;

        for (pkt = entry->packets; pkt; pkt = nxt)
        {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }

        free(entry);
    }

    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache)
{
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");

    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++)
    {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }

    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache)
{
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));

    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;

    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));

    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache)
{
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr)
{
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);

    while (1)
    {
        sleep(1.0);

        pthread_mutex_lock(&(cache->lock));

        time_t curtime = time(NULL);

        int i;
        for (i = 0; i < SR_ARPCACHE_SZ; i++)
        {
            if ((cache->entries[i].valid) && (difftime(curtime, cache->entries[i].added) > SR_ARPCACHE_TO))
            {
                cache->entries[i].valid = 0;
            }
        }

        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }

    return NULL;
}
