#include <errno.h>
#include <time.h>
#include <stdlib.h>
#include "packet_analyzer.h"
#include "ieee80211_radiotap.h"
#include "endian_converter.h"
#include "cfg80211.h"
#include "ieee80211.h"

#define MAXUINT64 0xffffffffffffffff
static struct previous_frame_info prev_frame;
static u_int8_t current_aggregate = 0;
static u_int8_t is_first_frame = 1; /* use to identify the first captured frame */
static u_int8_t is_second_subframe = 0; /* use to identify the second subframe
										   in an aggregate */
static unsigned int pkt_no = 0; /* packet number */

/**
 * got_packet - callback function that will be put in to pcap_loop()
 * Identify physical info of the packet, calculate frame length,
 * call to duration calculation function.
 * @argv: pointer to user's arguments.
 * @header: pointer to pcap packet header.
 * @packet: pointer to real packet (include radiotap header).
 */
void got_packet(u_char *argv, const struct pcap_pkthdr *header, const u_char *packet){
	struct arguments *args = (struct arguments*)argv;
	u_char *dumper = (u_char*)(args->dumper);
	pcap_dump(dumper, header, packet);

	struct ieee80211_radiotap_header *hdr;
	hdr = (struct ieee80211_radiotap_header*)(packet);
	//convert to the local endian
	u_int16_t rtap_hdr_len = le2local16(hdr->it_len);

	pkt_no++;	
	fprintf(stderr,"No: %u =======================================\n", pkt_no);
	fprintf(stderr,"len: %u\n", header->len);
	fprintf(stderr,"present bits: %u\n", hdr->it_present);
	fprintf(stderr,"rtap header length: %u\n", rtap_hdr_len);

	if (is_first_frame){
		/* This is the first frame of the capturing.
		 * An aggregate is identifiable only from the second subframe.*/
		is_first_frame = 0;
		fprintf(stderr, "This is the first frame\n");
	}
	struct MCS_radiotap_header *mcsInfo = NULL;
	struct channel_radiotap_header *chanInfo = NULL;
	u_int8_t bandwidth;
	u_int8_t flags_rtap = 0;

	struct ieee_802_11_phdr phdr = {.fcs_len = 0, .phy = 0, .has_channel = 0,
									.has_frequency = 0, .has_data_rate = 0,
									.has_signal_percent = 0, .has_noise_percent = 0,
									.has_signal_dbm = 0, .has_noise_dbm = 0, 
									.has_tsf_timestamp = 0, .has_aggregate_info = 0,
									.has_zero_length_psdu_type = 0};
	phdr.phy = PHDR_802_11_PHY_UNKNOWN;

	struct {
		u_int8_t has_fhss:1;
		u_int8_t is_2ghz:1;
		u_int8_t is_5ghz:1;
		u_int8_t is_ofdm:1;
		u_int8_t is_cck:1;
		u_int8_t cck_ofdm:1; //dynamic CCK or OFDM in mixed environment
		u_int8_t has_mcs:1;
		u_int8_t has_vht:1;
		u_int8_t short_preamble:1;
		u_int8_t short_gi:1;
		u_int8_t fcs_at_end:1;
	} checker = {.has_fhss = 0, .is_2ghz = 0, .is_5ghz = 0, .is_ofdm = 0,
					.has_mcs = 0, .has_vht = 0, .cck_ofdm = 0, .short_gi = 0,
					.short_preamble = 0, .fcs_at_end = 0};


	struct ieee80211_radiotap_iterator iter;
	int ret = ieee80211_radiotap_iterator_init(&iter, hdr, hdr->it_len, NULL);

	while (ret == 0) {

		ret = ieee80211_radiotap_iterator_next(&iter);

		if (ret)
			continue;

		int this_arg_index = iter.this_arg_index;
		//int this_arg_size = iter.this_arg_size;

		if (this_arg_index == IEEE80211_RADIOTAP_RATE){
			phdr.has_data_rate = 1;
			phdr.data_rate = *(iter.this_arg);
			
			fprintf(stderr,"rate -------------------\n");
			fprintf(stderr, "rate: %d\n", phdr.data_rate);	
		}
		else if (this_arg_index == IEEE80211_RADIOTAP_FHSS){
			checker.has_fhss = 1;
			/* TODO: parse FHSS info */
		}
		else if (this_arg_index == IEEE80211_RADIOTAP_CHANNEL){
			//radiotap channel info
			chanInfo = (struct channel_radiotap_header*)(iter.this_arg);
			//convert to local endian
			u_int16_t frequency = le2local16(chanInfo->frequency);
			u_int16_t chan_flags = le2local16(chanInfo->flags);

			checker.is_ofdm = get_sub_value(chan_flags, IEEE80211_CHAN_OFDM);
			checker.is_cck = get_sub_value(chan_flags, IEEE80211_CHAN_CCK);
			
			checker.is_2ghz = get_sub_value(chan_flags, IEEE80211_CHAN_2GHZ);
			checker.is_5ghz = get_sub_value(chan_flags, IEEE80211_CHAN_5GHZ);
			checker.cck_ofdm = get_sub_value(chan_flags, IEEE80211_CHAN_DYN);

			fprintf(stderr,"channel info ----------------------\n");
			fprintf(stderr,"frequency: %u\n", frequency);
			fprintf(stderr,"CCK: %u\n", checker.is_cck);
			fprintf(stderr,"OFDM: %u\n", checker.is_ofdm);
			fprintf(stderr, "is_2ghz: %u\n", checker.is_2ghz);
			fprintf(stderr, "is_5ghz: %u\n", checker.is_5ghz);
			fprintf(stderr, "cck_ofdm: %u\n", checker.cck_ofdm);
		}
		else if (this_arg_index == IEEE80211_RADIOTAP_TSFT){
			/* Time synchronization function info */
			phdr.has_tsf_timestamp = 1;
			phdr.tsf_timestamp = le2local64(*(iter.this_arg));

			fprintf(stderr, "TSFT info ------------------------\n");
			fprintf(stderr, "tsf timestamp: %ld\n", phdr.tsf_timestamp);
		}
		else if (this_arg_index == IEEE80211_RADIOTAP_AMPDU_STATUS){
			/* A-MPDU info */
			phdr.has_aggregate_info = 1;
			struct A_MPDU_radiotap_header *ampdu 
					= (struct A_MPDU_radiotap_header*)(iter.this_arg);
			phdr.aggregate_flags = ampdu->flags;
			phdr.aggregate_id = le2local32(ampdu->reference_num);

			fprintf(stderr, "AMPDU status ------------------------\n");
			fprintf(stderr, "aggregate flags: %u\n", phdr.aggregate_flags);
			fprintf(stderr, "aggregate id: %u\n", phdr.aggregate_id);
		}
		else if (this_arg_index == IEEE80211_RADIOTAP_MCS){
			//radiotap mcs info
			mcsInfo = (struct MCS_radiotap_header*)(iter.this_arg);
			checker.short_gi = get_sub_value(mcsInfo->flags, IEEE80211_RADIOTAP_MCS_SGI);
			checker.has_mcs = 1;
		
			fprintf(stderr,"mcs info -----------------------\n");
			fprintf(stderr,"mcs: %u\n", mcsInfo->mcs);
			fprintf(stderr,"short GI: %u\n", checker.short_gi);
		}
		else if (this_arg_index == IEEE80211_RADIOTAP_FLAGS){
			//radiotap flags info
			flags_rtap = *(iter.this_arg);
			checker.short_preamble = get_sub_value(flags_rtap, IEEE80211_RADIOTAP_F_SHORTPRE);
			checker.fcs_at_end = get_sub_value(flags_rtap, IEEE80211_RADIOTAP_F_FCS);

			fprintf(stderr,"flags info -----------------------\n");
			fprintf(stderr,"short preamble: %u\n", checker.short_preamble);
			fprintf(stderr, "fcs at end: %u\n", checker.fcs_at_end);
			
		}
		else if (this_arg_index == IEEE80211_RADIOTAP_VHT){
			checker.has_vht = 1;	
			/* TODO: parse VHT */
		}
	}


	if (ret != -ENOENT){
		fprintf(stderr,"max_length error %d\n", ret);
		return;
	}

	unsigned int frame_length = header->len - rtap_hdr_len;

	if (!checker.fcs_at_end)
		frame_length += 4;

	u_int8_t can_calculate = 1; /* use with A-MPDU,
								   accummulate A-MPDU length,
								   calculate duration at once
								   at the arival of the last subframe */
	u_int8_t in_aggregate = 0;

	/* determine physical type.
	 * prepare physical info */
	if (checker.has_fhss){
		//802.11 FHSS
		phdr.phy = PHDR_802_11_PHY_11_FHSS;
		phdr.phy_info.info_11_fhss.has_hop_index = 0;
		phdr.phy_info.info_11_fhss.has_hop_set = 0;
		phdr.phy_info.info_11_fhss.has_hop_pattern = 0;
	}
	else if (checker.is_cck || phdr.data_rate == 2 || phdr.data_rate == 4 ||
			phdr.data_rate == 11 || phdr.data_rate == 22){
		//802.11b
		phdr.phy = PHDR_802_11_PHY_11B;
		phdr.phy_info.info_11b.has_short_preamble = 0;
		if (flags_rtap != 0){
			phdr.phy_info.info_11b.has_short_preamble = 1;	//present
			phdr.phy_info.info_11b.short_preamble = checker.short_preamble;		//value	
		}
	}
	/*
	else if (phdr.has_data_rate && (phdr.data_rate == 2 || phdr.data_rate == 4))
		//802.11 DSSS
		phdr.phy = PHDR_802_11_PHY_11_DSSS;
	*/
	else if (checker.is_5ghz && checker.is_ofdm && 
			!checker.has_mcs && !checker.has_vht) {
		//802.11a
		phdr.phy = PHDR_802_11_PHY_11A;
		phdr.phy_info.info_11a.has_channel_type = 0;
		phdr.phy_info.info_11a.has_turbo_type = 0;
	}
	else if ((checker.is_2ghz && (checker.is_ofdm || checker.cck_ofdm) &&
			!checker.has_mcs) || 
			(phdr.has_data_rate && (phdr.data_rate == 12 ||
									phdr.data_rate == 18 ||
									phdr.data_rate == 24 ||
									phdr.data_rate == 36 ||
									phdr.data_rate == 48 || 
									phdr.data_rate == 72 ||
									phdr.data_rate == 96 ||
									phdr.data_rate == 108))) {
		//802.11g
		phdr.phy = PHDR_802_11_PHY_11G;
		phdr.phy_info.info_11g.has_mode = 0;
		phdr.phy_info.info_11g.has_short_preamble = 0;

		if (flags_rtap != 0){
			phdr.phy_info.info_11g.has_short_preamble = 1;	
			phdr.phy_info.info_11g.short_preamble = 1;
		}
	}
	else if (checker.has_mcs && !checker.has_vht){
		//802.11n
		fprintf(stderr, "802.11n info .-.-.-.-.-..-.-.-.-.-.-.-.-\n");

		phdr.phy = PHDR_802_11_PHY_11N;
		phdr.phy_info.info_11n.has_bandwidth = 0;
		phdr.phy_info.info_11n.has_short_gi = 0;
		phdr.phy_info.info_11n.has_stbc_streams = 0;
		phdr.phy_info.info_11n.has_fec = 0;
		phdr.phy_info.info_11n.has_ness = 0;
		phdr.phy_info.info_11n.has_greenfield = 0;
		phdr.phy_info.info_11n.has_mcs_index = 0;

		struct ieee_802_11n *_n = &(phdr.phy_info.info_11n);
		if (get_sub_value(mcsInfo->known, IEEE80211_RADIOTAP_MCS_HAVE_MCS)){
			_n->has_mcs_index = 1;
			_n->mcs_index = mcsInfo->mcs;
			fprintf(stderr, "mcs index: %u\n", _n->mcs_index);
		}
		if (get_sub_value(mcsInfo->known, IEEE80211_RADIOTAP_MCS_HAVE_BW)){
			_n->has_bandwidth = 1;
			_n->bandwidth = get_sub_value(mcsInfo->flags, IEEE80211_RADIOTAP_MCS_BW_MASK);
			fprintf(stderr, "bandwidth: %u\n", _n->bandwidth);
		}
		if (get_sub_value(mcsInfo->known, IEEE80211_RADIOTAP_MCS_HAVE_GI)){
			_n->has_short_gi = 1;
			_n->short_gi = get_sub_value(mcsInfo->flags, IEEE80211_RADIOTAP_MCS_SGI);
			fprintf(stderr, "short_gi: %u\n", _n->short_gi);
		}
		if (get_sub_value(mcsInfo->known, IEEE80211_RADIOTAP_MCS_HAVE_FMT)){
			_n->has_greenfield = 1;
			_n->greenfield = get_sub_value(mcsInfo->flags, IEEE80211_RADIOTAP_MCS_FMT_GF);	
			fprintf(stderr, "greenfield: %u\n", _n->greenfield);
		}
		if (get_sub_value(mcsInfo->known, IEEE80211_RADIOTAP_MCS_HAVE_FEC)){
			_n->has_fec = 1;
			_n->fec = get_sub_value(mcsInfo->flags, IEEE80211_RADIOTAP_MCS_FEC_LDPC);
			fprintf(stderr, "fec: %u\n", _n->fec);
		}
		if (get_sub_value(mcsInfo->known, IEEE80211_RADIOTAP_MCS_HAVE_STBC)){
			_n->has_stbc_streams = 1;
			_n->stbc_streams = get_sub_value(mcsInfo->flags, IEEE80211_RADIOTAP_MCS_STBC_MASK);
			fprintf(stderr, "stbc_streams: %u\n", _n->stbc_streams);
		}
		if (get_sub_value(mcsInfo->known, 0x40)){
			/* extension spatial streams */
			_n->has_ness = 1;
			_n->ness = get_sub_value(mcsInfo->flags, 0x80);
			fprintf(stderr, "ness: %u\n", _n->ness);
		}

		if (!is_first_frame) {
			/* An aggregate is identifiable only from the second subframe.*/
			in_aggregate = in_ampdu(&phdr);

			if (in_aggregate){
				/* This frame is a part of the A-MPDU */
				/* add A-MPDU delimiter */
				frame_length += 4;

				if (is_second_subframe){
					/* This is the second frame of the A-MPDU
					 * -> need to add padding to the first frame if neccessary.
					 * add delimiter for the first frame*/
					prev_frame.prev_length = (prev_frame.prev_length | 3) + 1;
					prev_frame.prev_length += 4;

					/* The first frame (identified as non A-MPDU) duration
					 * has been added to the total airtime,
					 * so subtract it's duration from the total airtime
					 * so that we can calculate it's duration
					 * as a part of the A-MPDU */
					args->airtime -= prev_frame.duration;

					/* re-calculate the first subframe duration */
					prev_frame.duration = calculate_duration(&phdr, prev_frame.prev_length, 1, 1);
					args->airtime += prev_frame.duration;
					fprintf(stderr, "####### prev_frame duration #######\n");
					fprintf(stderr, "#       duration: %u             #\n", prev_frame.duration);
					fprintf(stderr, "###################################\n");
				}
				
				frame_length = (frame_length | 3) + 1;	
			}
		}
	}
	else if (checker.has_vht){
		//802.11ac
		phdr.phy = PHDR_802_11_PHY_11AC;
		phdr.phy_info.info_11ac.has_stbc = 0;
		phdr.phy_info.info_11ac.has_short_gi = 0;
		phdr.phy_info.info_11ac.has_partial_aid = 0;
		phdr.phy_info.info_11ac.has_txop_ps_not_allowed = 0;
		phdr.phy_info.info_11ac.has_ldpc_extra_ofdm_symbol = 0;
		phdr.phy_info.info_11ac.has_short_gi_nsym_disambig = 0;
		phdr.phy_info.info_11ac.has_fec = 0;
		phdr.phy_info.info_11ac.has_bandwidth = 0;
		phdr.phy_info.info_11ac.has_group_id = 0;
		phdr.phy_info.info_11ac.has_beamformed = 0;
		/* TODO: fill in phy_info.info_11ac */
	}
	/* else: radiotap cannot generate requisite info */



	unsigned int duration = 0;

	duration = calculate_duration(&phdr, frame_length, in_aggregate, 0);
	fprintf(stderr, "DURATION: %u\n", duration);
	prev_frame.duration = duration;
	prev_frame.prev_length = frame_length;
	args->airtime += duration;


	prev_frame.has_tsf_timestamp = phdr.has_tsf_timestamp;
	prev_frame.tsf_timestamp = phdr.tsf_timestamp;
	prev_frame.phy = phdr.phy;
	prev_frame.phy_info = phdr.phy_info;
}

u_int8_t get_bit(u_int32_t value, u_int8_t bit){
	u_int32_t mask = 1 << bit;
	return (value & mask) >> bit;
}

/**
 * get_sub_value - get sub value using bit mask
 * @value: value from which you get sub value
 * @mask: bit mask
 *
 * Return: sub value from value.
 */

u_int8_t get_sub_value(u_int32_t value, u_int32_t mask){
	u_int32_t res = value & mask;
	if (res == 0)
		return res;
	while ( (res & 0x1) == 0 ) res >>= 1;
	return res;
}

/*
float calculate_80211n_data_rate(u_int8_t mcs, u_int8_t bandwidth, u_int8_t short_gi){
	if (mcs < 0 || mcs > 31 || 
		bandwidth < 0 || bandwidth > 1 || 
		short_gi < 0 || short_gi > 1) 
	{
		fprintf(stderr,"invalid arguments calculate_data_rate\n");
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
*/



/**
 * in_ampdu - check if this current frame is in an A-MPDU,
 * This function must only be called once for each frame.
 * @phdr: physical header info
 * @prev_frame: static variable from packet_analyzer.h, some previous frame info.
 * @current_aggregate: static variable from paket_analyzer.h, if this frame is in the current aggregate.
 * @is_first_frame: static variable from packet_analyzer.h, check if this frame is the first captured frame.
 *
 * Return: 1 if it is in an A-MPDU
 */

static u_int8_t in_ampdu(const struct ieee_802_11_phdr *phdr){
	fprintf(stderr, ".....in_ampdu functino.............\n");

    /* A-MPDU / aggregate detection
     * Different generators need different detection algorithms
     * One common pattern is to report all subframes in the aggregate with the same
     * tsf, referenced to the start of the AMPDU (Broadcom). Another pattern is to
     * report the tsf on the first subframe, then tsf=0 for the rest of the subframes
     * (Intel).
     * Another pattern is to report TSF = -1 for all frames but the last, and the
     * last has the tsf referenced to the end of the PPDU. (QCA)
     */
	if ((phdr->phy == PHDR_802_11_PHY_11N || phdr->phy == PHDR_802_11_PHY_11AC) &&
        phdr->phy == prev_frame.phy &&
        phdr->has_tsf_timestamp && prev_frame.has_tsf_timestamp &&
		(phdr->tsf_timestamp == prev_frame.tsf_timestamp || /* find matching TSFs */
         (!current_aggregate && prev_frame.tsf_timestamp && phdr->tsf_timestamp == 0) || /* Intel detect second frame */
         (prev_frame.tsf_timestamp == MAXUINT64) /* QCA, detect last frame */
        )){
		
		fprintf(stderr, "This is a part of the AMPDU\n");
		if (!current_aggregate){
			/* This is the second subframe in a aggregate */
			is_second_subframe = 1;
			fprintf(stderr, "This is the second A-MPDU subframe\n");
		}	
		else
			is_second_subframe = 0;

		current_aggregate = 1;
		return 1;		
	}
	fprintf(stderr, "This is not the part of any AMPDU\n");
	current_aggregate = 0;

	fprintf(stderr, "....................................\n");

	return 0;
}
