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
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"


/*forwarding logic : obtain the routing table entry with the longest prefix matching to the input ip address */
struct sr_rt* entry_with_longest_prefix(struct sr_instance* sr,uint32_t ip)
{
	assert(sr);
		
	struct sr_rt* iter = sr->routing_table;
	struct sr_rt* res = NULL;	
	uint16_t max = 0;
	uint32_t masked =0;	

	/*iterate through the routing table*/
	while (iter)
	{
		/*if masked input address = masked routing table address */	
		if ((ip & iter->mask.s_addr) == (iter->dest.s_addr & iter->mask.s_addr))
		{
			/*network long to host long byte order*/
			masked = ntohl((iter->mask).s_addr);
			if (masked > max) /*compare with longest masked address*/
			{
				max = masked;
				res = iter;
			}
			
		}
		iter = iter->next;
	}
	return res;

}
/*---------------------------------------------------------------------
 * Method: send_icmp_packet(
    struct sr_instance* sr,
    uint8_t type, uint8_t code,
    uint32_t ip,
    uint8_t* payload,
    char* interface)
	// ip should be in network byte order 
 * Scope:  Global
 *
 * function to send the icmp_packet
 *
 *---------------------------------------------------------------------*/
int send_icmp_packet(
    struct sr_instance* sr,
    uint8_t type, uint8_t code,
    uint32_t ip, 
    uint8_t* payload,
    char* interface) {

  assert(sr);
  assert(payload);
  assert(interface);
  int etherLen = sizeof(sr_ethernet_hdr_t); //ethernet header size
  int ipLen = sizeof(sr_ip_hdr_t); //ip header length
  int arpLen  = sizeof(sr_arp_hdr_t); //arp header length
  if (type != 3 && type != 11) {
    printf("ICMP wasn't type 3 or 11.  Stopping send\n");
    return -1;
  }

  unsigned int icmp_start = etherLen + ipLen;
  unsigned int response_length = icmp_start + sizeof(sr_icmp_t3_hdr_t);

  // Create ethernet packet with ICMP Type 3 
  uint8_t* response_packet = (uint8_t *)malloc(response_length);

  // Populate ICMP Message 
  sr_icmp_t3_hdr_t* response_icmp = (sr_icmp_t3_hdr_t *)(response_packet +icmp_start);
  response_icmp->icmp_type = type;
  response_icmp->icmp_code = code;

  response_icmp->unused = 0;
  response_icmp->next_mtu = 0;

  // Copy over IP Header + 8 bytes 
  memcpy(response_icmp->data, payload, ICMP_DATA_SIZE);

  // Generate ICMP checksum 
  response_icmp->icmp_sum = 0;  // Clear just in case
  response_icmp->icmp_sum = cksum(response_packet + icmp_start,sizeof(sr_icmp_t3_hdr_t));

  // Populate respone IP Packet 
  sr_ip_hdr_t* response_ip = (sr_ip_hdr_t *)(response_packet +etherLen);

  //Get interface 
  struct sr_if* sender = sr_get_interface(sr, interface);

  // Set src and dst addresses 
  response_ip->ip_dst = ip;
  response_ip->ip_src = sender->ip;

  // Set IP Headers 
  response_ip->ip_v = 4;
  response_ip->ip_hl = 5;
  response_ip->ip_tos = 0;
  response_ip->ip_len = htons(response_length - etherLen);
  response_ip->ip_id = htons(0);
  response_ip->ip_off = htons(IP_DF);
  response_ip->ip_ttl = 100;
  response_ip->ip_p = ip_protocol_icmp;

  // Generate IP checksum 
  response_ip->ip_sum = 0;
  response_ip->ip_sum = cksum(response_packet + etherLen,ipLen);

  // Generate ethernet packet 
  sr_ethernet_hdr_t* response_eth = (sr_ethernet_hdr_t *)(response_packet);

  response_eth->ether_type = htons(ethertype_ip);

  // Find a route to destination IP address 
  struct sr_rt* route = sr_find_rt_entry(sr, ip);
  if (route == NULL) {
    fprintf(stderr, "(Unreachable) Could not find route to original sender\n");
    return -1;
  }

  if (send_packet_to_ip_addr(
      sr, response_packet, response_length, ip, route->interface) == -1) {
    fprintf(stderr, "Error sending packet\n");
    return -1;
  }
  printf("Packet sent (%d)\n", response_length);

  free(response_packet);

  return 0;
}
/*---------------------------------------------------------------------
 * Method: process_ip_packet(
    struct sr_instance* sr,
    uint8_t* packet_buffer,
    unsigned int len,
    char* interface)
 * Scope:  Global
 *
 * function to process the arp packet
 *
 *---------------------------------------------------------------------*/
int process_ip_packet(
    struct sr_instance* sr,
    uint8_t* packet_buffer,
    unsigned int len,
    char* interface) {

  assert(sr);
  assert(packet_buffer);
  assert(interface);

  // Start of next header: add to packet head 
  unsigned int etherLen = sizeof(sr_ethernet_hdr_t);
  int ipLen = sizeof(sr_ip_hdr_t); //ip header length
  int arpLen  = sizeof(sr_arp_hdr_t); //arp header length
  if (len < etherLen + ipLen) {
    fprintf(stderr, "IP header: insufficient length\n");
    return -1;
  }

  printf("Processing IP Packet\n");
  // DEBUG only print_hdr_ip(packet + etherLen); 

  // Create request IP Packet 
  sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(packet_buffer + etherLen);

  uint16_t req_cksum = ip_header->ip_sum;
  ip_header->ip_sum = 0;

  if (cksum(packet_buffer + etherLen, ipLen) != req_cksum) {
    fprintf(stderr, "Error: IP header - invalid checksum\n");
    return -1;
  }

  // Check if in router's interfaces
  struct sr_if* my_interface = sr_find_interface(sr, ip_header->ip_dst);

  if (my_interface) {
    //Interface exists 

    etherLen += ipLen;

    if (ip_header->ip_p == ip_protocol_icmp) { // ICMP 
      if (len < etherLen + sizeof(sr_icmp_hdr_t)) {
        fprintf(stderr, "Error: ICMP header - insufficient length\n");
        return -1;
      }
      printf("Processing ICMP Packet\n");

      // Create ICMP Packet 
      sr_icmp_hdr_t* req_icmp = (sr_icmp_hdr_t *)(packet_buffer + etherLen);

      uint16_t req_icmp_cksum = req_icmp->icmp_sum;
      req_icmp->icmp_sum = 0;

      if (cksum(packet_buffer + etherLen, len - etherLen) != req_icmp_cksum) {
        fprintf(stderr, "Error: ICMP header - invalid checksum\n");
        return -1;
      }

      // Process ICMP message 
      if (req_icmp->icmp_type != 8 || req_icmp->icmp_code != 0) {
        // Drop packet if not echo request 
        printf("ICMP wasn't type echo.  Dropping packet\n");
        return -1;
      }

      // Set response length equal to request's 
      uint16_t reply_pkt_len = len;

      
      //construct icmp echo reply packet
      uint8_t* reply_buf = (uint8_t *)malloc(reply_pkt_len);

      // copy icmp data + icmp header
      memcpy(reply_buf + etherLen, packet_buffer + etherLen,reply_pkt_len - etherLen);

      
      //  Populate ICMP Message
      
      sr_icmp_hdr_t* response_icmp = (sr_icmp_hdr_t *)(reply_buf +etherLen);

      // Format echo reply 
      response_icmp->icmp_type = 0;
      response_icmp->icmp_code = 0;

      // Generate ICMP checksum 
      response_icmp->icmp_sum = 0;  //initially 0
      response_icmp->icmp_sum = cksum(reply_buf + etherLen,reply_pkt_len - etherLen);

      // construct icmp echo reply ip header
      sr_ip_hdr_t* reply_ip_hdr = (sr_ip_hdr_t *)(reply_buf + etherLen);

      // simply swap src and dst addresses 
      reply_ip_hdr->ip_dst = ip_header->ip_src;
      reply_ip_hdr->ip_src = ip_header->ip_dst;

      // Set IP Headers 
      reply_ip_hdr->ip_v = 4;
      reply_ip_hdr->ip_hl = 5;
      reply_ip_hdr->ip_tos = 0;
      reply_ip_hdr->ip_len = htons(reply_pkt_len -etherLen); //header + icmp header
      reply_ip_hdr->ip_id = htons(0);
      reply_ip_hdr->ip_off = htons(IP_DF);
      reply_ip_hdr->ip_ttl = 100;
      reply_ip_hdr->ip_p = ip_protocol_icmp;

      // Generate IP checksum 
      reply_ip_hdr->ip_sum = 0;
      reply_ip_hdr->ip_sum = cksum(reply_buf + etherLen,ipLen);

      // Modify Ethernet packet 
      sr_ethernet_hdr_t* response_eth = (sr_ethernet_hdr_t *)(reply_buf);
      response_eth->ether_type = htons(ethertype_ip);

      printf("Sending ICMP ping reply\n");
      if (send_packet_to_ip_addr(sr, reply_buf, reply_pkt_len,
          reply_ip_hdr->ip_dst, interface) == -1) {
        fprintf(stderr, "Error sending packet\n");
        return -1;
      }
      printf("Packet sent (%d)\n", reply_pkt_len);

      free(reply_buf);

    } else if (ip_header->ip_p == 6 || ip_header->ip_p == 17) {
      // TCP or UDP 
      printf("TCP or UDP found.  Sending back ICMP type 3, code 3\n");

      if (send_icmp_packet(
          sr, 3, 3, ip_header->ip_src, (uint8_t *)ip_header, interface) == -1) {
        fprintf(stderr, "Error: Failure sending ICMP message (3,3)\n");
        return -1;
      }

    } else {
      // Drop packet if other protocol 
      printf("Protocol not found.  Dropping packet\n");
      return -1;
    }

  } else {
    // Forward the Packet 
    printf("Forwarding Process Initiated\n");

    // Routing Table lookup 
    struct sr_rt* route = sr_find_rt_entry(sr, ip_header->ip_dst);

    // Make sure there is a next route. 
    if (route == NULL) {
      printf("Route does not exist.  Forwarding terminated\n");

      if (send_icmp_packet(
          sr, 3, 0, ip_header->ip_src, (uint8_t *)ip_header, interface) == -1) {
        fprintf(stderr, "Error: Failure sending ICMP message (3,0)\n");
        return -1;
      }

      return -2;
    }

    // Decrement the TTL 
    ip_header->ip_ttl--;
    if (ip_header->ip_ttl == 0) {
      // Send back ICMP time exceeded 
      printf("Packet TTL expired.\n");
      if (send_icmp_packet(
          sr, 11, 0, ip_header->ip_src, (uint8_t *)ip_header, interface) == -1) {
        fprintf(stderr, "Error: Failure sending ICMP message (11,0)\n");
        return -1;
      }
      return 0;
    }
	
    // Update the checksum 
    ip_header->ip_sum = 0;
    ip_header->ip_sum = cksum((uint8_t*) ip_header, ipLen);

    // Send the packet to the correct IP 
    if (send_packet_to_ip_addr(sr, packet_buffer, len, route->gw.s_addr,
        route->interface) != 0) {
      fprintf(stderr, "Error: Failure from send_packet_to_ip_addr\n");
      return -1;
    }
    printf("Packet forwarded\n");
  }

  return 0;
}
/*---------------------------------------------------------------------
 * Method: process_arp_packet(struct sr_instance* sr,
    uint8_t *packet_buffer,
    unsigned int len,
    char* interface) 
 * Scope:  Global
 *
 * function to process the arp packet
 *
 *---------------------------------------------------------------------*/
int process_arp_packet(
    struct sr_instance* sr,
    uint8_t *packet_buffer,
    unsigned int len,
    char* interface) {

  assert(sr);
  assert(packet_buffer);
  assert(interface);
  int etherLen = sizeof(sr_ethernet_hdr_t); //ethernet header size
  int ipLen = sizeof(sr_ip_hdr_t); //ip header length
  int arpLen  = sizeof(sr_arp_hdr_t); //arp header length
  if (len <  etherLen + arpLen) {
    fprintf(stderr, "Error: ARP header - insufficient length\n");
    return -1;
  }
  printf("ARP Packet Processing Initiated\n");
  // print_hdr_arp(packet + sizeof(sr_ethernet_hdr_t));

  // Create ARP Header and find interface
  sr_arp_hdr_t* arp_header = (sr_arp_hdr_t*)(packet_buffer +  etherLen);
  struct sr_if* my_interface = sr_find_interface(sr, arp_header->ar_tip);

  if (my_interface) {
    printf("Found Interface: ");
    sr_print_if(my_interface);

    if (strcmp(my_interface->name, interface) == 0) {
      printf("Interface name's match up\n");
      unsigned short op_code = ntohs(arp_header->ar_op);

      if (op_code == arp_op_reply) { // Process ARP Reply 
        printf("Processing ARP Reply\n");

        // See if there's an ARP request in the queue. 
        struct sr_arpreq* req = sr_arpcache_insert(
            &(sr->cache), arp_header->ar_sha, arp_header->ar_sip);

        // Forward all packets waiting on req if req exists. 
        struct sr_packet* pckt = req ? req->packets : NULL;
        for (; pckt != NULL; pckt = pckt->next) {
          eth_frame_send_with_mac(
              sr, pckt->buf, pckt->len, arp_header->ar_sha, pckt->iface);
        }
      } else if (op_code == arp_op_request) { // Process ARP Request 
        printf("Processing ARP Request\n");

        // Set the target to the incoming ARP source. 
        memcpy(arp_header->ar_tha, arp_header->ar_sha, ETHER_ADDR_LEN);
        arp_header->ar_tip = arp_header->ar_sip;

        // Set the source to this interface. 
        memcpy(arp_header->ar_sha, my_interface->addr, ETHER_ADDR_LEN);
        arp_header->ar_sip = my_interface->ip;

        // Set ethernet frame MAC information 
        sr_ethernet_hdr_t* ethernet_hdr = (sr_ethernet_hdr_t*)(packet_buffer);
        memcpy(ethernet_hdr->ether_dhost, arp_header->ar_tha, ETHER_ADDR_LEN);
        memcpy(ethernet_hdr->ether_shost, arp_header->ar_sha, ETHER_ADDR_LEN);

        // Send the packet back on it's way. 
        arp_header->ar_op = htons(arp_op_reply);
        printf("Sending out ARP Reply\n");
        sr_send_packet(sr, packet_buffer, len, interface);
      } else {
        fprintf(stderr, "ARP Op Code Unknown: (%d)\n", arp_header->ar_op);
        return -1;
      }
    } else {
      fprintf(stderr, "ARP interface names didn't match: %s, %s\n",
          my_interface->name, interface);
      return -1;
    }
  } else {
    printf("ARP interface not found\n");
  }

  return 0;
}

/*---------------------------------------------------------------------
 * Method: eth_frame_send_with_mac(struct sr_instance* sr,
    uint8_t* packet,
    unsigned int len,
    unsigned char* mac,
    char* iface)
 * Scope:  Global
 *
 * send the ethernet frame
 *
 *---------------------------------------------------------------------*/
int eth_frame_send_with_mac(
    struct sr_instance* sr,
    uint8_t* packet,
    unsigned int len,
    unsigned char* mac,
    char* iface) {

  printf("Sending Packet\n");

  // Cast the packet in order to update fields. 
  sr_ethernet_hdr_t* e_packet = (sr_ethernet_hdr_t *)(packet);
  struct sr_if* interface = sr_get_interface(sr, iface);

  // Set fields 
  memcpy(e_packet->ether_dhost, mac, ETHER_ADDR_LEN);
  memcpy(e_packet->ether_shost, interface->addr, ETHER_ADDR_LEN);

  // Send the packet
  print_hdrs(packet, len);
  sr_send_packet(sr, packet, len, iface);
  return 0;
}
/*---------------------------------------------------------------------
 * Method: send_packet_to_ip_addr(struct sr_instance* sr,
    uint8_t* packet,
    unsigned int len,
    uint32_t dest_ip,
    char* iface)
 * Scope:  Global
 *
 * send the packet to the ip address. First consult the cache if not.
 *
 *---------------------------------------------------------------------*/
int send_packet_to_ip_addr(struct sr_instance* sr,
    uint8_t* packet,
    unsigned int len,
    uint32_t dest_ip,
    char* iface) {
  struct sr_arpentry* arp_entry = sr_arpcache_lookup(&(sr->cache), dest_ip);

  if (arp_entry) {
    printf("ARP Cache Hit\n");
    // Forward the packet 
    eth_frame_send_with_mac(sr, packet, len, arp_entry->mac, iface);

    // Free ARP entry
    free(arp_entry);
  } else {
    printf("ARP Cache Miss\n");
    struct sr_arpreq* req = sr_arpcache_queuereq(
        &(sr->cache), dest_ip, packet, len, iface);
    req->interface = iface;
    handle_arpreq(sr, req);
  }

  return 0;
}



/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/



void sr_init(struct sr_instance* sr)
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
	
    /*adding interfaces in the routing table to sr instance. */
/*    struct sr_rt* rt_walker = sr->routing_table;
    while (rt_walker)
    {
 	sr_add_interface(sr,rt_walker->interface);	
	rt_walker = rt_walker->next;
	
    }*/
    /*everything else in sr_instance struct is initialized in main.c */   

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

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("Received packet of length %d \n",len);

  /* fill in code here */
 
  /*initializing key variables*/
  uint8_t* packet_buffer; /*packet buffer*/
  /*struct sr_if* iface;*/ /*interface struct*/
  uint16_t checksum,ether_type; /*checksum bit*/
  unsigned int packet_len,minlength; /*packet length*/
  int ipLen,etherLen,arpLen;
 
  packet_buffer = packet;
  packet_len = len;
  minlength = sizeof(sr_ethernet_hdr_t);
  etherLen = sizeof(sr_ethernet_hdr_t); /*ethernet header size*/
  ipLen = sizeof(sr_ip_hdr_t); /*ip header length*/
  arpLen  = sizeof(sr_arp_hdr_t); /*arp header length*/

  if (len > IP_MAXPACKET)
  {
    	perror("Error: invalid packet size");
	exit(1);
  }
  if (len < minlength)
  {
        perror("Error: packet size too small");
	exit(1);
  }
  /*obtain interface information*/
  /*iface = sr_get_interface(sr,interface);*/

  
  /*examining each layer of header*/  
  
  /*examine ethernet header*/
  sr_ethernet_hdr_t* ether_header = (sr_ethernet_hdr_t*) packet_buffer;  
  ether_type = ethertype(packet_buffer); 
 
  if (ether_type == ethertype_ip) /*IP*/
  {
	if (process_ip_packet(sr, packet, len, interface)  < 0) {
      fprintf(stderr, "Error processing IP datagram\n");
    }
  }

  else if (ether_type == ethertype_arp) /*ARP*/
  {
	if (process_arp_packet(sr, packet, len, interface)  <0) {
      fprintf(stderr, "Error processing ARP packet\n");
    }
  }
  else {
    fprintf(stderr, "Error: Unrecognized Ethernet Type: %d\n", ether_type);
  }
  
}/* end sr_ForwardPacket */

