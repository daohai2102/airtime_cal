#include <stdio.h>
#include <errno.h>
#include <pcap.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "cfg80211.h" //radiotap parser
#include "ieee80211_radiotap.h"
#include "endian_converter.h"
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


struct preamble_conditions {
	uint8_t cck:1;
	uint8_t ofdm:1;
	uint8_t short_preamble:1;
	uint8_t mcs_present:1;
};
typedef struct preamble_conditions preamble_conditions;

typedef struct ieee80211_radiotap_header rtap_hdr;

struct Channel_radiotap_header {
	__be16 frequency;	//channel frequency
	__be16 flags;		//channel flags
};
typedef struct Channel_radiotap_header rtap_chan;

struct MCS_radiotap_header {
	uint8_t known;			//Known MCS information
	uint8_t flags;			//MCS flags
	uint8_t mcs;			//MCS index
};
typedef struct MCS_radiotap_header rtap_mcs;

struct arguments{
	pcap_dumper_t *dumper;
	float airtime;
};
typedef struct arguments arguments;

typedef struct ieee80211_radiotap_iterator rtap_iter;

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
uint8_t get_bit(uint32_t value, uint8_t bit);
uint8_t get_sub_value(uint32_t value, uint32_t mask);
float calculate_data_rate(uint8_t mcs, uint8_t bandwidth, uint8_t short_gi);



int main(int argc, char *argv[]){

	char *dev = argv[1];
	char *filter_exp = argv[2];
	char *file_save = argv[3];
	char errbuf[PCAP_ERRBUF_SIZE]; //save error message when opening a device
	pcap_t *handler;

	//open handler to capture live packets
	handler = pcap_open_live(dev, BUFSIZ, 0, 0, errbuf);
// 	handler = pcap_open_offline("/home/sea/tmp/airtime.pcap", errbuf);
	if (handler == NULL) {
		printf("err: %s\n", errbuf);
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
	pcap_dumper_t *dumper = pcap_dump_open(handler, file_save);

		
	arguments args = {.dumper = NULL, .airtime = 0};
	args.dumper = dumper;
	//loop through packets
	int tmp = pcap_loop(handler, 10, got_packet, (u_char*)&args);
	//int tmp = pcap_loop(handler, 0, got_packet, NULL);

	pcap_dump_close(dumper);
	pcap_close(handler);

	printf("final airtime: %f\n", args.airtime);

	return 0;
}

void got_packet(u_char *argv, const struct pcap_pkthdr *header, const u_char *packet){
	arguments *args = (arguments*)argv;
	u_char *dumper = (u_char*)(args->dumper);
	pcap_dump(dumper, header, packet);

	rtap_hdr *hdr;
	hdr = (rtap_hdr*)(packet);
	//convert to the local endian
	u_int16_t rtap_hdr_len = le2local16(hdr->it_len);

	
	printf("time: %ld =======================================\n", header->ts.tv_sec);
	printf("len: %u\n", header->len);
	printf("present bits: %u\n", hdr->it_present);
	printf("rtap header length: %u\n", rtap_hdr_len);

	float rate = 0;
	rtap_mcs *mcsInfo = NULL;
	rtap_chan *chanInfo = NULL;
	uint8_t flags;
	uint8_t bandwidth;
	preamble_conditions pre = {.cck = 0, .mcs_present = 0,
								.short_preamble = 0, .ofdm = 0};
	uint8_t short_gi;

	rtap_iter iter;
	int ret = ieee80211_radiotap_iterator_init(&iter, hdr, hdr->it_len, NULL);

	while (ret == 0) {

		ret = ieee80211_radiotap_iterator_next(&iter);

		if (ret)
			continue;

		int this_arg_index = iter.this_arg_index;
		int this_arg_size = iter.this_arg_size;

		if (this_arg_index == IEEE80211_RADIOTAP_RATE){
			rate = *(iter.this_arg) * 0.5f;
			
			printf("rate -------------------\n");
			printf("rate: %f\n", rate);
			
		}
		else if (this_arg_index == IEEE80211_RADIOTAP_CHANNEL){
			//radiotap channel info
			chanInfo = (rtap_chan*)(iter.this_arg);
			//convert to local endian
			u_int16_t frequency = le2local16(chanInfo->frequency);
			u_int16_t flags = le2local16(chanInfo->flags);

			pre.cck = get_sub_value(flags, IEEE80211_CHAN_CCK);
			pre.ofdm = get_sub_value(flags, IEEE80211_CHAN_OFDM);
			
			printf("channel info ----------------------\n");
			printf("frequency: %u\n", frequency);
			printf("CCK: %u\n", pre.cck);
			printf("OFDM: %u\n", pre.ofdm);
			
		}
		else if (this_arg_index == IEEE80211_RADIOTAP_MCS){
			//radiotap mcs info
			mcsInfo = (rtap_mcs*)(iter.this_arg);
			short_gi = get_sub_value(mcsInfo->flags, IEEE80211_RADIOTAP_MCS_SGI);
			bandwidth = get_sub_value(mcsInfo->flags, IEEE80211_RADIOTAP_MCS_BW_MASK);
			rate = calculate_data_rate(mcsInfo->mcs, bandwidth, short_gi);
			pre.mcs_present = 1;
		
			printf("mcs info -----------------------\n");
			printf("mcs: %u\n", mcsInfo->mcs);
			printf("short GI: %u\n", short_gi);
			printf("bandwidth: %u\n", bandwidth);
			printf("rate: %f\n", rate);
			
		}
		else if (this_arg_index == IEEE80211_RADIOTAP_FLAGS){
			//radiotap flags info
			flags = *(iter.this_arg);
			pre.short_preamble = get_sub_value(flags, IEEE80211_RADIOTAP_F_SHORTPRE);
			
			printf("flags info -----------------------\n");
			printf("short preamble: %u\n", pre.short_preamble);
			
		}
	}

	if (ret != -ENOENT){
		printf("max_length error %d\n", ret);
		return;
	}

	int preamble = 0;

	if (pre.ofdm == 0 && pre.cck == 1)
		// b standard
		if (pre.short_preamble)
			preamble = 96;
		else
			preamble = 192;
	else if (pre.mcs_present == 0)
		// OFDM only
		preamble = 20;
	else if (pre.mcs_present && mcsInfo->mcs <= 7)
		// mix n and g with 1 spatial stream
		preamble = 36;
	else if (pre.mcs_present && mcsInfo->mcs <= 15)
		// mix n and g with 2 spatial streams
		preamble = 40;
	else if (pre.mcs_present && mcsInfo->mcs <= 23)
		// mix n and g with 3 spatial streams
		preamble = 44;
	else
		// only to debug
		preamble = 0;
	
	printf("preamble length -------------------\n");
	printf("preamble length: %d\n", preamble);
	
	
	uint32_t pkt_length = header->len - rtap_hdr_len;
	args->airtime += pkt_length * 8 / rate;

	printf("airtime: %f\n", args->airtime);

}

uint8_t get_bit(uint32_t value, uint8_t bit){
	uint32_t mask = 1 << bit;
	return (value & mask) >> bit;
}

uint8_t get_sub_value(uint32_t value, uint32_t mask){
	uint32_t res = value & mask;
	if (res == 0)
		return res;
	while ( (res & 0x1) == 0 ) res >>= 1;
	return res;
}

float calculate_data_rate(uint8_t mcs, uint8_t bandwidth, uint8_t short_gi){
	if (mcs < 0 || mcs > 31 || 
		bandwidth < 0 || bandwidth > 1 || 
		short_gi < 0 || short_gi > 1) 
	{
		printf("invalid arguments calculate_data_rate\n");
		exit(1);
	}
	float rates[] = {6.5, 7.2, 13.5, 15, 
					13, 14.4, 27, 30, 
					19.5, 21.7, 40.5, 45, 
					26, 28.9, 54, 60, 
					39, 43.3, 81, 90, 
					52, 57.8, 108, 120,
					58.5, 65, 121.5, 135, 
					65, 72.2, 135, 150, 
					13, 14.4, 27, 30, 
					26, 28.9, 54, 60, 
					39, 43.3, 81, 90, 
					52, 57.8, 108, 120, 
					78, 86.7, 162, 180, 
					104, 115.6, 216, 240, 
					117, 130.3, 243, 270, 
					130, 144.4, 270, 300, 
					19.5, 21.7, 40.5, 45, 
					39, 43.3, 81, 90, 
					58.5, 65, 121.5, 135, 
					78, 86.7, 162, 180, 
					117, 130, 243, 270, 
					156, 173.3, 324, 360, 
					175.5, 195, 364.5, 405, 
					195, 216.7, 405, 450, 
					26, 28.9, 54, 60, 
					52, 57.8, 108, 120, 
					78, 86.7, 162, 180, 
					104, 115.6, 216, 240, 
					156, 173.3, 324, 360, 
					208, 231.1, 432, 480, 
					234, 260, 486, 540, 
					260, 288.9, 540, 600};
	return rates[4*mcs + short_gi + 2*bandwidth];
}
