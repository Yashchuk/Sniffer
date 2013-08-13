/*
 * sniffer.c
 *
 *  Created on: 31 Jul 2013
 *      Author: ivan ivanets
 */

#include "sniffer.h"
#include "snif_list.h"
#include "snif_parser.h"

#include <stdio.h>
#include <stdlib.h>

pcap_t* snif_init_session( char* interface, const char* expr_filter, char** err_buff )
{
	pcap_t* handle;
	*err_buff = (char*) calloc( PCAP_ERRBUF_SIZE, sizeof(char) );

	if( !interface ) {
		interface = pcap_lookupdev(*err_buff);
		if ( !interface ) {
			return SNIF_RESULT_FAIL;
		}
	}

	handle = pcap_open_live(interface, BUFSIZ, DEVICE_PROMISCUOUS_MODE, DEVICE_READ_TIME_OUT, *err_buff);
	if( !handle ) {
		return SNIF_RESULT_FAIL;
	}

	if( pcap_datalink( handle ) != DLT_EN10MB ) {
		pcap_close(handle);
		sprintf(*err_buff, "Interface \"%s\" doesn't provide Ethernet headers - not supported\n", interface);
		return SNIF_RESULT_FAIL;
	}

	if( expr_filter ) {
		bpf_u_int32 mask;
		bpf_u_int32 net;
		struct bpf_program packet_filter;

		if( pcap_lookupnet(interface, &net, &mask, *err_buff) == -1 ) {
			pcap_close(handle);
			return SNIF_RESULT_FAIL;
		}

		if( pcap_compile(handle, &packet_filter, expr_filter, 0, net) == -1 ) {
			*err_buff = pcap_geterr(handle);
			pcap_close(handle);
			return SNIF_RESULT_FAIL;
		}

		if( pcap_setfilter(handle, &packet_filter) == -1 ) {
			*err_buff = pcap_geterr(handle);
			pcap_close(handle);
			return SNIF_RESULT_FAIL;
		}
	}

	printf("\n\t\tUSING INTERFACE: \"%s\"\n\n", interface);
	free(*err_buff);
	return handle;
}


int snif_loop_session( pcap_t* handle, int count_packet )
{
	int result;
	snif_list* list = snif_list_init();

	do {
		result = pcap_loop(handle, 1, snif_got_packet, (u_char*) list );
		if(count_packet > 0) {
			--count_packet;
		}

	} while( result != -1 && result != -2 && count_packet );

	snif_list_free(list);

	if(!count_packet) {
		return SNIF_RESULT_SUCCESSFUL;
	}

	return SNIF_RESULT_FAIL;
}


static void snif_got_packet ( u_char* arg,
		const struct pcap_pkthdr* header,
		const u_char* packet )
{
	snif_list* list = (snif_list*) arg;

	snif_list_item* new_item = snif_parse_packet( packet );
	snif_list_add_item(list, new_item);
	snif_list_print(list);
}
