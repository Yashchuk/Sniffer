/*
 * snif_parser.c
 *
 *  Created on: 31 Jul 2013
 *      Author: ivan ivanets
 */


#include "snif_parser.h"

#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

snif_list_item* snif_parse_packet(const unsigned char* packet)
{
	snif_list_item* new_item = (snif_list_item*) malloc( sizeof(snif_list_item) );
	snif_link_layer *ethernet = (snif_link_layer*) packet;

	new_item->MAC_data = (snif_link_layer*) malloc( sizeof(snif_link_layer) );
	memcpy(new_item->MAC_data, ethernet, sizeof(snif_link_layer));
	new_item->count_packet = 1;

	unsigned char* p = (char*) &new_item->MAC_data->MAC_protocol;
	unsigned char tmp = *p;
	*p = *(p+1);
	*(p+1) = tmp;

	if(new_item->MAC_data->MAC_protocol == ETHERTYPE_IP) {
		struct iphdr* ip_header = (struct iphdr*) (packet + ETHER_HDR_LEN);

		new_item->IP_data = (snif_network_layer*) malloc( sizeof(snif_network_layer) );
		memcpy(new_item->IP_data->IP_source, &ip_header->saddr, IP_LEN);
		memcpy(new_item->IP_data->IP_dest, &ip_header->daddr, IP_LEN);
		new_item->IP_data->IP_protocol = ip_header->protocol;

		if(new_item->IP_data->IP_protocol == IPPROTO_TCP) {
			new_item->count_TCP = 1;
			new_item->count_UDP = 0;
		}
		else if(new_item->IP_data->IP_protocol == IPPROTO_UDP) {
			new_item->count_TCP = 0;
			new_item->count_UDP = 1;
		}
	}
	else {
		new_item->IP_data = NULL;
	}

	return new_item;
}
