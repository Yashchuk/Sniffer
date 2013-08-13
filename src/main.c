/*
 * main.c
 *
 *  Created on: 31 Jul 2013
 *      Author: Ivan Ivanets
 */

#include "sniffer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define FILTER_MAX_LINE		512

#define HELP_DATA	"sniffer version 1.0.0\n\
Usage: sniffer  [ -h ] [ -c count packets ]\n\
\t\t[ -i name interface ] [ expression ]\n\
\
[ expression ]\t-\tselects which packets will  be  dumped.   If  no  expression  is \
given,  all  packets on the net will be dumped.  Otherwise, only \
packets for which expression is `true' will be dumped. \
For the expression syntax, see pcap-filter(7).\n\n"

int main( int argc, char* argv[] )
{
	char* error_buf;
	char* interface = NULL;
	char* expr_filter = NULL;
	int count = -1, c, i;

    opterr = 0;
    while( (c = getopt (argc, argv, "c:i:h")) != -1) {
        switch (c) {
        case 'c':
            count = atoi(optarg);
            break;
    	case 'i':
    		interface = strdup(optarg);
            break;
    	case 'h':
            printf( HELP_DATA );
            free(interface);
            free(expr_filter);
            return 0;
          default:
            abort ();
        }
    }


    for( i = optind; i < argc; ++i ) {
		if(!expr_filter) {
			expr_filter = strdup(argv[i]);
		}
		else {
			strcat(expr_filter, " ");
			strcat(expr_filter, argv[i]);
		}
    }

	pcap_t* handler = snif_init_session( interface, expr_filter, &error_buf );
	if(handler == SNIF_RESULT_FAIL) {
		printf("error: %s\n", error_buf);
		return 0;
	}

	if( snif_loop_session(handler, count) == SNIF_RESULT_SUCCESSFUL ) {
		printf("\nSUCCESSFUL\n");
	}
	else {
		printf("\nFAIL\n");
	}

	pcap_close(handler);

	free(interface);
	free(expr_filter);

	return 0;
}
