/*
 * sniffer.h
 *
 *  Created on: 31 Jul 2013
 *      Author: ivan ivanets
 */

#ifndef SNIFFER_H_
#define SNIFFER_H_

#include <pcap/pcap.h>

#define SNIF_RESULT_FAIL 		0
#define SNIF_RESULT_SUCCESSFUL	1

#define DEVICE_PROMISCUOUS_MODE 	1
#define DEVICE_NO_PROMISCUOUS_MODE 0

#define DEVICE_READ_NO_TIME_OUT 	0
#define DEVICE_READ_TIME_OUT 		1000


/*
 * Function:  snif_init_session
 * --------------------------------
 * creates and initializes new session
 *
 *  device:		name of device that be used for capturing packets
 *  expr_filter:	selects which packets will  be  dumped
 *  err_buff:	the string with a description of the error of init
 *
 *  returns: session handler or fail inform
 */
pcap_t* snif_init_session( char* interface, const char* expr_filter, char** err_buff );


/*
 * Function:  snif_loop_session
 * --------------------------------
 * start the loop which capture packets and parse their
 *
 *  handle:		session handler
 *  count_packet:	count of packets that must be captured and then exit loop
 *
 *  returns: information on how loop ended - successfully or with an error
 */
int snif_loop_session( pcap_t* handle, int count_packet );


/*
 * Function:  snif_got_packet
 * --------------------------------
 * callback function for pcap_loop()
 *
 *  arg:		corresponds to the last argument of pcap_loop()
 *  header:		pcap header, which contains information about when the packet was sniffed, how large it is
 *  packet:		packet that be captured by pcap_loop()
 */
static void snif_got_packet ( u_char* arg,
		const struct pcap_pkthdr* header,
		const u_char* packet );

#endif /* SNIFFER_H_ */
