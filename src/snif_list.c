/*
 * snif_list.c
 *
 *  Created on: 31 Jul 2013
 *      Author: ivan ivanets
 */

#include "snif_list.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

snif_list* snif_list_init()
{
	snif_list* list;
	list = (snif_list*) malloc( sizeof(snif_list) );
	list->first_MAC_item = NULL;
	list->last_MAC_item = NULL;
	list->first_IP_item = NULL;
	list->last_IP_item = NULL;

	return list;
}

void snif_list_add_item(snif_list* list, snif_list_item* new_item)
{
	snif_list_item* tmp = list->first_MAC_item;

	while(tmp &&
			( memcmp(tmp->MAC_data->MAC_source,
					new_item->MAC_data->MAC_source,
					MAC_ADDR_LEN) ||
			memcmp(tmp->MAC_data->MAC_dest,
					new_item->MAC_data->MAC_dest,
					MAC_ADDR_LEN) ) ) {

		tmp = tmp->nextItem;
	}

	if(tmp) {
		tmp->count_packet += new_item->count_packet;
		free( new_item->MAC_data );
		new_item->MAC_data = NULL;
	}
	else if(list->last_MAC_item) {
		snif_list_item* next_item = (snif_list_item*) malloc( sizeof(snif_list_item) );
		memcpy( next_item, new_item, sizeof(snif_list_item) );
		new_item->MAC_data = NULL;
		list->last_MAC_item->nextItem = next_item;
		list->last_MAC_item = list->last_MAC_item->nextItem;
	}
	else {
		snif_list_item* next_item = (snif_list_item*) malloc( sizeof(snif_list_item) );
		memcpy( next_item, new_item, sizeof(snif_list_item) );
		new_item->MAC_data = NULL;
		list->first_MAC_item = next_item;
		list->last_MAC_item = list->first_MAC_item;
	}

	list->last_MAC_item->nextItem = NULL;

	if( !new_item->IP_data ) {
		return;
	}

	tmp = list->first_IP_item;
	while(tmp &&
			( memcmp(tmp->IP_data->IP_source,
					new_item->IP_data->IP_source,
					IP_LEN) ||
			memcmp(tmp->IP_data->IP_dest,
					new_item->IP_data->IP_dest,
					IP_LEN) ) ) {

		tmp = tmp->nextItem;
	}

	if( tmp ) {
		tmp->count_TCP += new_item->count_TCP;
		tmp->count_UDP += new_item->count_UDP;
		free( new_item->IP_data );
		new_item->IP_data = NULL;
		if(new_item->MAC_data == NULL)
			free( new_item );
	}
	else if(list->last_IP_item) {
		list->last_IP_item->nextItem = new_item;
		list->last_IP_item = list->last_IP_item->nextItem;
	}
	else {
		list->first_IP_item = new_item;
		list->last_IP_item = list->first_IP_item;
	}
	list->last_IP_item->nextItem = NULL;
}


void snif_list_print(snif_list *list)
{
	snif_list_item* tmp = list->first_MAC_item;
	unsigned char* mac;
	unsigned char* ip;

	system("clear");
	printf("source MAC\t\tdest.MAC\t\tpackets\n");

	while( tmp ) {
		mac = tmp->MAC_data->MAC_source;
		printf("%x:%x:%x:%x:%x:%x\t", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
		mac = tmp->MAC_data->MAC_dest;
		printf("%x:%x:%x:%x:%x:%x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
		printf("\t%d\n", tmp->count_packet);
		tmp = tmp->nextItem;
	}

	tmp = list->first_IP_item;
	printf("\n\nsource IP\t\tdest.IP\t\t\tTCP\tUDP\n");

	while( tmp ) {
		ip = tmp->IP_data->IP_source;
		printf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
		ip = tmp->IP_data->IP_dest;
		printf("\t\t%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
		printf("\t\t%d\t%d\n", tmp->count_TCP, tmp->count_UDP);
		tmp = tmp->nextItem;
	}

}

void snif_list_free(snif_list* list)
{
	snif_list_item* p = list->first_MAC_item;
	snif_list_item* tmp;

	while(p) {
		tmp = p;
		p = p->nextItem;
		free( tmp->MAC_data );
		free( tmp );
	}

	p = list->first_IP_item;
	while(p) {
		tmp = p;
		p = p->nextItem;
		free( tmp->IP_data );
		free( tmp );
	}
}
