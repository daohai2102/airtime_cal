#ifndef _PACKET_ANALYZER_H
#define _PACKET_ANALYZER_H

#include <pcap.h>
#include "ieee80211.h"

struct A_MPDU_radiotap_header {
	u_int32_t reference_num;
	u_int16_t flags;
	u_int8_t delimiter_crc;
	u_int8_t reserved;
};

struct channel_radiotap_header {
	u_int16_t frequency;	//channel frequency
	u_int16_t flags;		//channel flags
};

struct MCS_radiotap_header {
	u_int8_t known;			//Known MCS information
	u_int8_t flags;			//MCS flags
	u_int8_t mcs;			//MCS index
};

struct arguments{
	pcap_dumper_t *dumper;
	unsigned int airtime;
	int duration; //duration to capture
	time_t start; //time to start capturing
	pcap_t *handler;
};


/* previous frame details, for aggregate detection */
struct previous_frame_info {
	u_int8_t has_tsf_timestamp:1;
	u_int64_t tsf_timestamp;
	unsigned int phy;
	union ieee_802_11_phy_info phy_info;
	unsigned int prev_length; 
	//struct wlan_radio *radio_info;
	unsigned int duration;
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

u_int8_t get_bit(u_int32_t value, u_int8_t bit);

u_int8_t get_sub_value(u_int32_t value, u_int32_t mask);


static u_int8_t in_ampdu(const struct ieee_802_11_phdr *phdr);


#endif
