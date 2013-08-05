/*
 * snif_parser.h
 *
 *  Created on: 31 Jul 2013
 *      Author: ivan ivanets
 */

#ifndef SNIF_PARSER_H_
#define SNIF_PARSER_H_

#include "snif_list.h"

/*
 * Function:  snif_parse_packet
 * --------------------------------
 * parse packet
 *
 *  packet:		packet which was captured be pcap_loop()
 *
 *  returns: new list item with parsed data from packet
 */
snif_list_item* snif_parse_packet(const unsigned char* packet);


#endif /* SNIF_PARSER_H_ */
