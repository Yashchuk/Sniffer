/*
 * snif_list.h
 *
 *  Created on: 31 Jul 2013
 *      Author: ivan ivanets
 */

#ifndef SNIF_LIST_H_
#define SNIF_LIST_H_

#define MAC_ADDR_LEN 	6
#define IP_LEN			4

typedef struct snif_link_layer {
	unsigned char MAC_dest[MAC_ADDR_LEN];
	unsigned char MAC_source[MAC_ADDR_LEN];
	unsigned short MAC_protocol;
} snif_link_layer;


typedef struct snif_network_layer {
	unsigned char IP_source[IP_LEN];
	unsigned char IP_dest[IP_LEN];
	unsigned char IP_protocol;
} snif_network_layer;


typedef struct snif_list_item {
	snif_link_layer* MAC_data;
	unsigned int count_packet;
	snif_network_layer* IP_data;
	unsigned int count_TCP;
	unsigned int count_UDP;
	struct snif_list_item *nextItem;
} snif_list_item;


typedef struct snif_list {
	snif_list_item* first_MAC_item;
	snif_list_item* last_MAC_item;

	snif_list_item* first_IP_item;
	snif_list_item* last_IP_item;
} snif_list;


/*
 * Function:  snif_list_init
 * --------------------------------
 * creates and initializes new list
 *
 *  returns: pointer to empty list
 */
snif_list* snif_list_init();


/*
 * Function:  snif_list_add_item
 * --------------------------------
 * add new item to list
 *
 *  list:		list to add to it the new item
 *  new_item:	new item
 */
void snif_list_add_item(snif_list* list, snif_list_item* new_item);


/*
 * Function:  snif_list_print
 * --------------------------------
 * prints on display all data from the list like a table
 *
 *  list:		list with added items
 */
void snif_list_print(snif_list *list);


/*
 * Function:  snif_list_free
 * --------------------------------
 * destroys and frees memory within the list
 *
 *  list:		list with added items
 */
void snif_list_free(snif_list* list);

#endif /* SNIF_LIST_H_ */
