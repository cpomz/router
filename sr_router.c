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
#include <time.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"


//**********************************************************//
//*** helper function set to obtain longest prefix match ***//
//**********************************************************//

//declaring a new struct to contain destination addresses in the router
//that matches packet's destination ip address

struct addr_in
{  
   uint32_t maskedAddr;
   uint32_t destAddr; 
   struct addr_in* next;
   int common_len;
};

//build a linked-list of destination address and corresponding masked address
void addr_in_set(struct addr_in ** in,uint32_t addr_mask,uint32_t dest_addr)
{
	if (*in == NULL)
	{
		*in = (struct addr_in*)malloc(sizeof(struct addr_in));
		(*in)->maskedAddr = addr_mask;
   		(*in)->destAddr = dest_addr;
		(*in)->next == NULL;		
	}
	
	else
	{
		struct addr_in* naddr = (struct addr_in*)malloc(sizeof(struct addr_in));
		naddr->maskedAddr = addr_mask;
		naddr->destAddr = dest_addr;
		naddr->next = *in;
		*in = naddr;		

	}

}

//function to determine address with the longest prefix
uint32_t longest_prefix_dest_addr(struct addr_in** in,uint32_t ip_dest)
{

   struct addr_in* iter = *in;
   int i,snum;
   while (iter)
   {
     snum = 0; //number of matching bits
     //compare each bit in the ip destination address and the router's masked
     //destination address, starting from the highest bit
     for (i = 0; i < 32; i++)
     {
	uint32_t addr_bit1 = (ip_dest >> 31-i) & 0x0001;
	uint32_t addr_bit2 = (iter->maskedAddr >> 31-i) & 0x0001;
	if (addr_bit1 == addr_bit2)
	{ snum++;}
     } 
     iter->common_len = snum;
     iter = iter->next; 
   }
   
   struct addr_in *iter2 = *in;
   uint32_t longest_addr;
   uint32_t max = 0;
   
   //find the destination address with the longest prefix match 
   while (iter2)
   {
	if (snum > max)
	{ 
		max = snum;
		longest_addr = iter2->destAddr;
	}
	iter2 = iter2->next;

   }	 
   return longest_addr; 
   

}

//helper function to find the name of the interface given its MAC address
const char* find_interface(struct sr_instance* sr,char addr[ETHER_ADDR_LEN])
{
	struct sr_if* iter = sr->if_list;
	while (iter)
	{	
		//found the address
		if (strcmp(addr,iter->addr) == 0)
		{ return iter->name;}
		iter = iter->next;
	}	

	return 0; //interface not found
}

void handle_arpreq(struct sr_instance* sr,struct sr_arpreq* request)
{
	time_t now = time(0); //get system time
	if (difftime(now,request->sent) > 1.0)
	{
	   if(request->times_sent >= 5)
	   {
		//send icmp host unreachable to source addr of all pkts
		//waiting on this request
		struct sr_packet* iter = request->packets;
		
		while(iter) //for each packet in the packet list
		{

		   //find the ethernet header field of the packet to extract the source address
		   sr_ethernet_hdr_t* ether_header = (sr_ethernet_hdr_t*) (iter->buf);
		   char srcAddr[ETHER_ADDR_LEN];
		   memcpy(srcAddr,ether_header->ether_shost,ETHER_ADDR_LEN);
		   char iname[sr_IFACE_NAMELEN];
		   strcpy(iname,find_interface(sr,srcAddr));		
		 
		   //find ip_header field of the packet
		   sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*) (iter->buf+sizeof(sr_ethernet_hdr_t));
		   ip_header->ip_p |= ip_protocol_icmp; //set protocol type to icmp
		   int headerLen = sizeof(sr_ip_hdr_t);
		   ip_header->ip_ttl--; //decrement ttl value
		   ip_header->ip_sum = cksum(ip_header,headerLen); //recompute checksum
		  
		   sr_icmp_t3_hdr_t* icmp3 = (sr_icmp_t3_hdr_t*) (iter->buf+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
		   icmp3->icmp_type = 3; //icmp type3
		   icmp3->icmp_code = 1; //destination host unreachable
		   int icmp_len = sizeof(sr_icmp_t3_hdr_t);
		   //also check the checksum of icmp protocol to see
		   //that data has not been corrupted
		   int checksum = cksum(icmp3->icmp_sum,icmp_len);
		   if ((checksum & 0xffff) != 0xffff)
		   { perror("Error: data has been corrupted");}
		   //now send packet to the source address
		   sr_send_packet(sr,iter->buf,iter->len,iname);
 
		   iter = iter->next;
		}
		//destroy the request
		sr_arpreq_destroy(&(sr->cache),request);
	   }

	   else
	   {
		//send arp request

		//build a packet
                unsigned int packet_len = sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t);
		uint8_t* packet_buf = (uint8_t*) malloc(packet_len);
	 	sr_ethernet_hdr_t* ether_header = (sr_ethernet_hdr_t*) (packet_buf);
		int i;
 		for (i = 0; i < ETHER_ADDR_LEN; i++)
		{
			//broadcast address 
			ether_header->ether_dhost[i] = 0xff;
		}	

		//finding source hardware / ip address
		struct sr_if* iface = sr_get_interface(sr,sr->host);
		//source hardware address
		memcpy(ether_header->ether_shost,iface->addr,ETHER_ADDR_LEN);
		ether_header->ether_type |= ethertype_arp; //arp type 	
				
		sr_arp_hdr_t* arp_header = (sr_arp_hdr_t*) (packet_buf+sizeof(sr_ethernet_hdr_t));
		arp_header->ar_tip = request->ip; //next hop ip address
		memcpy(arp_header->ar_tha,ether_header->ether_dhost,ETHER_ADDR_LEN); 		//destination hardware address (should be ff-ff-ff-ff-ff-ff)
		arp_header->ar_sip = iface->ip;
		memcpy(arp_header->ar_sha,ether_header->ether_shost,ETHER_ADDR_LEN);		//source hardware address
		arp_header->ar_op |= arp_op_request; //operation is request
		arp_header->ar_hrd = 1; //ethernet
		arp_header->ar_pro |=  0x0800; //IPv4
		arp_header->ar_hln = 6; //length of ethernet address
		arp_header->ar_pln = 4; //length of IPv4 address

		//send the ARP request to all the available interfaces
		struct sr_if* if_walker = sr->if_list;
		while (if_walker)
		{	
			sr_send_packet(sr,packet_buf,packet_len,if_walker->name);		
			if_walker = if_walker->next;
 		} 
		request->sent = now; //reset time
                request->times_sent++;  //increment # times sent

           }
	}	




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
	
    //adding interfaces in the routing table to sr instance.
    struct sr_rt* rt_walker = sr->routing_table;
    while (rt_walker)
    {
 	sr_add_interface(sr,rt_walker->interface);	
	rt_walker = rt_walker->next;
	
    }
    //everything else in sr_instance struct is initialized in main.c   

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

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */
 
  //initializing key variables
  uint8_t* packet_buffer; //packet buffer
  struct sr_if* iface; //interface struct
  uint16_t checksum,ether_type; //checksum bit
  unsigned int packet_len,minlength; //packet length
  uint32_t maskedAddr,dest_longest; 
  int ip_headerLen;

  packet_buffer = packet;
  packet_len = len;
  minlength = sizeof(sr_ethernet_hdr_t);
  if (len > IP_MAXPACKET)
  {
    	perror("Error: invalid packet size");
  }
  if (len < minlength)
  {
        perror("Error: packet size too small");
  }
  //obtain interface information
  iface = sr_get_interface(sr,interface);

  //performing checksum on the packet
  checksum = cksum(packet_buffer,packet_len);
  if ((checksum & 0xffff) != 0xffff) //data has been corrupted
  {
 	perror("Error: data has been corrupted");
  } 
  
  //examining each layer of header//  
  
  //examine ethernet header
  sr_ethernet_hdr_t* ether_header = (sr_ethernet_hdr_t*) packet_buffer;  
  ether_type = ethertype(packet_buffer); //examine ethernet subheader type
   
  if (ether_type == ethertype_ip) //ip
  {
	sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*) (packet_buffer+sizeof(sr_ethernet_hdr_t)); //obtain ip_header
        ip_header->ip_ttl--; //decrement TTL field
        ip_headerLen = sizeof(sr_ip_hdr_t); //find ip header length
        ip_header->ip_sum = cksum(ip_header,ip_headerLen); //recompute checksum over ip header
	
        //now performing longest-prefix-matching 

	struct sr_rt* rt_walker = sr->routing_table;
	struct addr_in* destAddrSet = NULL;
        //obtaining list of destination addresses and their corresponding subnet masked addresses in the routing table
	while (rt_walker)
	{
		//maskedAddr
		maskedAddr = rt_walker->dest.s_addr & rt_walker->mask.s_addr;
		addr_in_set(&destAddrSet,maskedAddr,rt_walker->dest.s_addr);
		rt_walker = rt_walker->next;		

	}		
	//find destination address with the longest prefix match
        dest_longest = longest_prefix_dest_addr(&destAddrSet,ip_header->ip_dst);
	
	//look up an IP->MAC mapping in the cache
        struct sr_arpentry * mapping_entry = sr_arpcache_lookup(&(sr->cache),dest_longest);
	if (mapping_entry) //if there is a mapping
        {

		char* out_iface = find_interface(sr,mapping_entry->mac);
		sr_send_packet(sr,packet_buffer,len,out_iface);
	
 	}

	else 
	{
		struct sr_arpreq* request = sr_arpcache_queuereq(&(sr->cache),dest_longest,packet,len,interface);		

	}	 
	
  }

  else if (ether_type == ethertype_arp) //arp
  {
	sr_arp_hdr_t *arp_header = (sr_arp_hdr_t*) (packet_buffer + sizeof(sr_ethernet_hdr_t));
		

  }
  
}/* end sr_ForwardPacket */

