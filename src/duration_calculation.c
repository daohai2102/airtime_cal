#include <math.h>
#include "ieee80211.h"

#define MAX_MCS_INDEX 76
#define PHDR_802_11_BANDWIDTH_20_MHZ   0 /* 20 MHz */
#define PHDR_802_11_BANDWIDTH_40_MHZ   1 /* 40 MHz */

static const u_int8_t ieee80211_ht_streams[MAX_MCS_INDEX+1] = {
       1,1,1,1,1,1,1,1,2,2,2,2,2,2,2,2,3,3,3,3,3,3,3,3,4,4,4,4,4,4,4,4,
       1,2,2,2,2,2,2,3,3,3,3,3,3,3,3,3,3,3,3,3,3,4,4,4,4,4,4,4,4,4,4,4,
       4,4,4,4,4,4,4,4,4,4,4,4,4
};

static const u_int8_t ieee80211_ht_Nes[MAX_MCS_INDEX+1] = {
       1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,
       1,1,1,1,1,2,2,2, 1,1,1,1,2,2,2,2,
       1,
       1,1,1,1,1,1,
       1,1,1,1,1,1,1,1,1,1,1,1,1,1,
       1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,2,2,2,2,2,2,2
};

static const u_int16_t ieee80211_ht_Dbps[MAX_MCS_INDEX+1] = {
    /* MCS  0 - 1 stream */
    26, 52, 78, 104, 156, 208, 234, 260,

    /* MCS  8 - 2 stream */
    52, 104, 156, 208, 312, 416, 468, 520,

    /* MCS 16 - 3 stream */
    78, 156, 234, 312, 468, 624, 702, 780,

    /* MCS 24 - 4 stream */
    104, 208, 312, 416, 624, 832, 936, 1040,

    /* MCS 32 - 1 stream */
    12, /* only valid for 40Mhz - 11a/g DUP mode */

    /* MCS 33 - 2 stream */
    156, 208, 260, 234, 312, 390,

    /* MCS 39 - 3 stream */
    208, 260, 260, 312, 364, 364, 416, 312, 390, 390, 468, 546, 546, 624,

    /* MCS 53 - 4 stream */
    260, 312, 364, 312, 364, 416, 468, 416, 468, 520, 520, 572,
    390, 468, 546, 468, 546, 624, 702, 624, 702, 780, 780, 858
};

#define MAX_MCS_VHT_INDEX 9


struct mcs_vht_info {
  const char *modulation;
  const char *coding_rate;
  float data_bits_per_symbol; /* assuming 20MHz / 52 subcarriers */
};

static const struct mcs_vht_info ieee80211_vhtinfo[MAX_MCS_VHT_INDEX+1] = {
  /* MCS  0  */
  { "BPSK",  "1/2", 26 },
  /* MCS  1  */
  { "QPSK",  "1/2", 52 },
  /* MCS  2  */
  { "QPSK",  "3/4", 78 },
  /* MCS  3  */
  { "16-QAM", "1/2", 104 },
  /* MCS  4  */
  { "16-QAM", "3/4", 156 },
  /* MCS  5  */
  { "64-QAM", "2/3", 208 },
  /* MCS  6  */
  { "64-QAM", "3/4", 234 },
  /* MCS  7  */
  { "64-QAM", "5/6", 260 },
  /* MCS  8  */
  { "256-QAM", "3/4", 312 },
  /* MCS  9  */
  { "256-QAM", "5/6", (float)(1040/3.0) }
};


static const unsigned int subcarriers[4] = { 52, 108, 234, 468 };

/**
 * Calculates data rate corresponding to a given 802.11n MCS index,
 * bandwidth, and guard interval.
 * @mcs_index: 802.11n mcs index
 * @bandwidth: 1 for 40MHz, 0 for 20MHz
 * @short_gi: 1 for short guard interval, otherwise 0.
 *
 * Return: HT data rate.
 */
float ieee80211_htrate(u_int8_t mcs_index, u_int8_t bandwidth, u_int8_t short_gi)
{
    return (float)(ieee80211_ht_Dbps[mcs_index] * (bandwidth ? 108 : 52) / 52.0 / (short_gi ? 3.6 : 4.0));
}

/**
 * Calculates data rate corresponding to a given 802.11ac MCS index,
 * bandwidth, and guard interval.
 * @mcs_index: 802.11ac mcs index
 * @bandwidth_index: 0 for 20MHz, 1 for 40MHz, 2 for 80 MHz, 3 for 160Mhz
 * @short_gi: 1 for short guard interval, otherwise 0.
 *
 * Return: VHT data rate.
 */
static float ieee80211_vhtrate(u_int8_t mcs_index, u_int8_t bandwidth_index, u_int8_t short_gi)
{
    return (float)(ieee80211_vhtinfo[mcs_index].data_bits_per_symbol * subcarriers[bandwidth_index] / (short_gi ? 3.6 : 4.0) / 52.0);
}


/**
 * Calculate 802.11n frame duration.
 * @frame_length: frame_length, include fcs field (byte).
 * @info_n: 802.11n information.
 * @stbc_streams: the number of stbc streams.
 *
 * Return: frame duration (micro second).
 */
static unsigned int calculate_11n_duration(unsigned int frame_length,
		  struct ieee_802_11n* info_n,
		    u_int8_t stbc_streams,
			u_int8_t in_aggregate)
{
	fprintf(stderr, "....calculate_11n_duration function ............\n");
	unsigned int bits = 0;
	unsigned int bits_per_symbol = 0;
	unsigned int Mstbc = 0;
	unsigned int symbols = 0;

	/* data field calculation */
	if (1) {
		/* see ieee80211n-2009 20.3.11 (20-32) - for BCC FEC */
		bits = 8 * frame_length;
		if (!in_aggregate)	
			/* an A-MPDU subframe does not include 16 bit service field
			 * and tail bit */
			bits += 16 + ieee80211_ht_Nes[info_n->mcs_index] * 6;

		Mstbc = stbc_streams ? 2 : 1;
		fprintf(stderr, "Mstbs: %u\n", Mstbc);
		bits_per_symbol = ieee80211_ht_Dbps[info_n->mcs_index] *
		  (info_n->bandwidth == PHDR_802_11_BANDWIDTH_40_MHZ ? 2 : 1);
		fprintf(stderr, "bits per symbol: %u\n", bits_per_symbol);
		symbols = bits / (bits_per_symbol * Mstbc);
	} else {
		/* TODO: handle LDPC FEC, it changes the rounding */
	}
	/* round up to whole symbols */
	if ((bits % (bits_per_symbol * Mstbc)) > 0)
		symbols++;

	symbols *= Mstbc;
	fprintf(stderr, "number of symbols: %u\n", symbols);
	fprintf(stderr, "...............................................\n");
	return (symbols * (info_n->short_gi ? 36 : 40) + 5) / 10; /* It takes 0.5us 
																 for the radio
																 wave to propergate */
}


/**
 * Calculate 802.11ac frame duration.
 * @frame_length: frame lenth, include fcs (byte).
 * @data_rate: VHT data rate.
 *
 * Return: frame duration (micro second).
 */
static unsigned int calculate_11ac_duration(unsigned int frame_length, float data_rate)
{
	unsigned int bits = 8 * frame_length + 16;
	return (unsigned int) (bits / data_rate);
}

/**
 * calculate_duration - calculate frame duration (in microsecond).
 * @phdr: pointer to phy info
 * @frame_lenght:
 * @in_aggregate: equal 1 if this frame is an A-MPDU.
 *
 * Return: frame duration.
 */
unsigned int calculate_duration(struct ieee_802_11_phdr *phdr, 
								unsigned int frame_length,
								u_int8_t in_aggregate,
								u_int8_t first_frame){
	fprintf(stderr, ".....calculate_duration function..........\n");
	unsigned int duration = 0;
	float data_rate = 1.0f;
	fprintf(stderr, "phy type: %u\n", phdr->phy);
	
	switch (phdr->phy){
		case PHDR_802_11_PHY_11_FHSS:
			/* TODO: calculate */
			break;
		case PHDR_802_11_PHY_11B:
		{
			u_int8_t short_preamble = 0;
			if (phdr->phy_info.info_11b.has_short_preamble)
				short_preamble = phdr->phy_info.info_11b.short_preamble;
			u_int8_t preamble = short_preamble ? 96 : 192;
			
			fprintf(stderr, "preamble: %u\n", preamble);
			
			/* calculation of frame duration
			* Things we need to know to calculate accurate duration
			* 802.11 / 802.11b (DSSS or CCK modulation)
			* - length of preamble
			* - rate
			*/
			/* round up to whole microseconds */
			if (phdr->has_data_rate)
				data_rate = phdr->data_rate*0.5f;

			fprintf(stderr, "data rate: %f\n", data_rate);
			duration = (unsigned int) ceil(preamble + frame_length*8 / data_rate);

			break;
		}
		case PHDR_802_11_PHY_11G:
		case PHDR_802_11_PHY_11A:
		{	
			/* OFDM rate */
			/* calculation of frame duration
			* Things we need to know to calculate accurate duration
			* 802.11a / 802.11g (OFDM modulation)
			* - rate
			*/

			/* preamble + signal */
			u_int8_t preamble = 16 + 4;

			fprintf(stderr, "preamble: %u\n", preamble);

			/* 16 service bits, data and 6 tail bits */
			unsigned int bits = 16 + 8 * frame_length + 6;
			fprintf(stderr, "number of bits: %u\n", bits);
			/* bits_per_symble = data_rate * 4 */
			if (phdr->has_data_rate)
				data_rate = phdr->data_rate*0.5f;
			unsigned int symbols = (unsigned int) ceil(bits / (data_rate * 4));
			fprintf(stderr, "number of symbols: %u\n", symbols);

			duration = preamble + symbols * 4; /* 4us per symbol */
			break;
		}
		case PHDR_802_11_PHY_11N:
		{
			struct ieee_802_11n *info_n = &(phdr->phy_info.info_11n);
			
			/*see page 209, std 802.11n-2009 */
			static const u_int8_t Nhtdltf[4] = {1, 2, 4, 4}; /* HT data LTF */
			static const u_int8_t Nhteltf[4] = {0, 1, 2, 4}; /* HT extension LTF */

			/* calculation of frame duration
			* Things we need to know to calculate accurate duration
			* 802.11n / HT
			* - whether frame preamble is mixed or greenfield, (assume mixed)
			* - guard interval, 800ns or 400ns
			* - bandwidth, 20Mhz or 40Mhz
			* - MCS index - used with previous 2 to calculate rate
			* - how many additional STBC streams are used (assume 0)
			* - how many optional extension spatial streams are used (assume 0)
			* - whether BCC or LDCP coding is used (assume BCC)
			*/

			u_int8_t stbc_streams = 0;
			if (info_n->has_stbc_streams)
				stbc_streams = info_n->stbc_streams;
			fprintf(stderr, "stbc_streams: %u\n", stbc_streams);

			if (first_frame){
				u_int8_t preamble = 32; /* assume HT-mixed */


				/* number of extension spatial streams */
				u_int8_t ness = 0; 
				if (info_n->has_ness)
					ness = info_n->ness;
				fprintf(stderr, "ness: %u\n", ness);
				if (ness > 3)
					break;

				/* calculate number of HT-LTF training symbols.
				* see ieee80211n-2009 20.3.9.4.6 table 20-11 */
				u_int8_t Nsts = ieee80211_ht_streams[info_n->mcs_index] + stbc_streams;
				fprintf(stderr, "Nsts: %u\n", Nsts);
				if (Nsts == 0 || Nsts - 1 > 3)
					break;

				/* preamble duration
				* see ieee802.11n-2009 Figure 20-1 - PPDU format
				* for HT-mixed format
				* L-STF 8us, L-LTF 8us, L-SIG 4us, HT-SIG 8us, HT_STF 4us
				* for HT-greenfield
				* HT-GF-STF 8us, HT-LTF1 8us, HT_SIG 8us
				*/
				if (info_n->has_greenfield)
					preamble = info_n->greenfield ? 24 : 32; /* not include 
																any HT-LTF */
				preamble += 4 * (Nhtdltf[Nsts-1] + Nhteltf[ness]);
				fprintf(stderr, "preamble: %u\n", preamble);

				duration += preamble;
			}
			
			duration += calculate_11n_duration(frame_length, info_n, stbc_streams, in_aggregate);
			break;
		}
		case PHDR_802_11_PHY_11AC:
		{
			/* TODO: calculate */
			break;
		}
	}
	fprintf(stderr, "............................................\n");
	return duration;
}
