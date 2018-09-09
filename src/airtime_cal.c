#include <stdio.h>
#include <errno.h>
#include <pcap.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include "cfg80211.h" //radiotap parser
#include "ieee80211_radiotap.h"
#include "endian_converter.h"
#include "packet_analyzer.h"
/*
//channel flags in radiotap
#define CHANNEL_FLAG_TURBO  4
#define CHANNEL_FLAG_CCK  5
#define CHANNEL_FLAG_OFDM  6
#define CHANNEL_FLAG_2GHZ  7
#define CHANNEL_FLAG_5GHZ  8
#define CHANNEL_FLAG_PASSIVE 9
#define CHANNEL_FLAG_CCK_OFDM 10
#define CHANNEL_FLAG_GFSK 11
#define CHANNEL_FLAG_GSM 12
#define CHANNEL_FLAG_STATIC_TURBO 13
#define CHANNEL_FLAG_10MHZ 14
#define CHANNEL_FLAG_5MHZ 15

//flags in radiotaps
#define FLAGS_CFP 0
#define FLAGS_PREAMBLE 1
#define FLAGS_WEP 2
#define FLAGS_FRAGMENTATION 3
#define FLAGS_FCS_END 4
#define FLAGS_DATA_PAD 5
#define FLAGS_BAD_FCS 6
#define FLAGS_SHORT_GI 7

//Present Known MCS info
#define KNOWN_MCS_BANDWIDTH 0
#define KNOWN_MCS_MCS_INDEX 1
#define KNOWN_MCS_GI 2
#define KNOWN_MCS_FORMAT 3
#define KNOWN_MCS_FEC_TYPE 4
#define KNOWN_MCS_STBC_STREAMS 5
#define KNOWN_MCS_N_EXT_SPATIAL_STREAMS 6
*/

pcap_t *handler = NULL;

void alarm_handler(int sig){
	pcap_breakloop(handler);
}


int main(int argc, char *argv[]){

	struct arguments args = {.dumper = NULL, .airtime = 0};
	char *dev = argv[1];
	char *filter_exp = argv[2];
	unsigned int capture_duration = atoi(argv[3]);
	char *file_save = argv[4];
	char errbuf[PCAP_ERRBUF_SIZE]; //save error message when opening a device

	//open handler to capture live packets
	handler = pcap_open_live(dev, BUFSIZ, 0, 0, errbuf);
	if (handler == NULL) {
		fprintf(stderr,"err: %s\n", errbuf);
		return 1;
	}

	//set filter
	struct bpf_program fp;
	
	if (pcap_compile(handler, &fp, filter_exp, 0, 0) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		filter_exp, pcap_geterr(handler));
		return 2;
	}
	if (pcap_setfilter(handler, &fp) == -1) {
		 fprintf(stderr, "Couldn't install filter %s: %s\n",
		 filter_exp, pcap_geterr(handler));
		 return(2);
	}

	//open file to write packets
	args.dumper = pcap_dump_open(handler, file_save);

	//set alarm to stop capture after capture_duration seconds
	alarm(capture_duration);
	signal(SIGALRM, alarm_handler);
	//loop through packets
	pcap_loop(handler, 0, got_packet, (u_char*)&args);

	pcap_dump_close(args.dumper);
	pcap_close(handler);

	fprintf(stderr,"final airtime: %u\n", args.airtime);
	printf("%u\n", args.airtime);

	return 0;
}
