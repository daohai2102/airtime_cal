#ifndef _IEEE_802_11_H
#define _IEEE_802_11_H 

#include <pcap.h> 


/*
 * PHY types.
 */
#define PHDR_802_11_PHY_UNKNOWN        0 /* PHY not known */
#define PHDR_802_11_PHY_11_FHSS        1 /* 802.11 FHSS */
#define PHDR_802_11_PHY_11_IR          2 /* 802.11 IR */
#define PHDR_802_11_PHY_11_DSSS        3 /* 802.11 DSSS */
#define PHDR_802_11_PHY_11B            4 /* 802.11b */
#define PHDR_802_11_PHY_11A            5 /* 802.11a */
#define PHDR_802_11_PHY_11G            6 /* 802.11g */
#define PHDR_802_11_PHY_11N            7 /* 802.11n */
#define PHDR_802_11_PHY_11AC           8 /* 802.11ac */
#define PHDR_802_11_PHY_11AD           9 /* 802.11ad */


/*
 * 802.11 legacy FHSS.
 */
struct ieee_802_11_fhss {
    unsigned int    has_hop_set:1;
    unsigned int    has_hop_pattern:1;
    unsigned int    has_hop_index:1;

    u_int8_t   hop_set;        /* Hop set */
    u_int8_t   hop_pattern;    /* Hop pattern */
    u_int8_t   hop_index;      /* Hop index */
};

/*
 * 802.11b.
 */
struct ieee_802_11b {
    /* Which of this information is present? */
    u_int8_t    has_short_preamble:1;

    u_int8_t short_preamble:1; /* Short preamble */
};

/*
 * 802.11a.
 */
struct ieee_802_11a {
    /* Which of this information is present? */
    unsigned int    has_channel_type:1;
    unsigned int    has_turbo_type:1;

    unsigned int    channel_type:2;
    unsigned int    turbo_type:2;
};

/*
 * 802.11g.
 */
struct ieee_802_11g {
    /* Which of this information is present? */
    unsigned int    has_short_preamble:1;
    unsigned int    has_mode:1;

    u_int8_t short_preamble; /* Short preamble */
    u_int32_t  mode;           /* Various proprietary extensions */
};


/*
 * 802.11n.
 */
struct ieee_802_11n {
    /* Which of this information is present? */
    unsigned int    has_mcs_index:1;
    unsigned int    has_bandwidth:1;
    unsigned int    has_short_gi:1;
    unsigned int    has_greenfield:1;
    unsigned int    has_fec:1;
    unsigned int    has_stbc_streams:1;
    unsigned int    has_ness:1;

    u_int16_t  mcs_index;      /* MCS index */
    unsigned int    bandwidth;      /* Bandwidth = 20 MHz, 40 MHz, etc. */
    unsigned int    short_gi:1;     /* True for short guard interval */
    unsigned int    greenfield:1;   /* True for greenfield, short for mixed */
    unsigned int    fec:1;          /* FEC: 0 = BCC, 1 = LDPC */
    unsigned int    stbc_streams:2; /* Number of STBC streams */
    unsigned int    ness;           /* Number of extension spatial streams */
};

struct ieee_802_11ac {
    /* Which of this information is present? */
    unsigned int    has_stbc:1;
    unsigned int    has_txop_ps_not_allowed:1;
    unsigned int    has_short_gi:1;
    unsigned int    has_short_gi_nsym_disambig:1;
    unsigned int    has_ldpc_extra_ofdm_symbol:1;
    unsigned int    has_beamformed:1;
    unsigned int    has_bandwidth:1;
    unsigned int    has_fec:1;
    unsigned int    has_group_id:1;
    unsigned int    has_partial_aid:1;

    unsigned int    stbc:1;         /* 1 if all spatial streams have STBC */
    unsigned int    txop_ps_not_allowed:1;
    unsigned int    short_gi:1;     /* True for short guard interval */
    unsigned int    short_gi_nsym_disambig:1;
    unsigned int    ldpc_extra_ofdm_symbol:1;
    unsigned int    beamformed:1;
    u_int8_t   bandwidth;      /* Bandwidth = 20 MHz, 40 MHz, etc. */
    u_int8_t   mcs[4];         /* MCS index per user */
    u_int8_t   nss[4];         /* NSS per user */
    u_int8_t   fec;            /* Bit array of FEC per user: 0 = BCC, 1 = LDPC */
    u_int8_t   group_id;
    u_int16_t  partial_aid;
};

struct ieee_802_11ad {
    /* Which of this information is present? */
	unsigned int    has_mcs_index:1;

    u_int8_t   mcs;            /* MCS index */
};

union ieee_802_11_phy_info {
    struct ieee_802_11_fhss info_11_fhss;
    struct ieee_802_11b info_11b;
    struct ieee_802_11a info_11a;
    struct ieee_802_11g info_11g;
    struct ieee_802_11n info_11n;
    struct ieee_802_11ac info_11ac;
    struct ieee_802_11ad info_11ad;
};

struct ieee_802_11_phdr {
    int     fcs_len;          /* Number of bytes of FCS - -1 means "unknown" */
    //u_int8_t decrypted;        /* TRUE if frame is decrypted even if "protected" bit is set */
	//u_int8_t datapad;          /* TRUE if frame has padding between 802.11 header and payload */
    unsigned int    phy;              /* PHY type */
    union ieee_802_11_phy_info phy_info;

    /* Which of this information is present? */
    unsigned int    has_channel:1;
    unsigned int    has_frequency:1;
    unsigned int    has_data_rate:1;
    unsigned int    has_signal_percent:1;
    unsigned int    has_noise_percent:1;
    unsigned int    has_signal_dbm:1;
    unsigned int    has_noise_dbm:1;
    unsigned int    has_tsf_timestamp:1;
    unsigned int    has_aggregate_info:1;        /* aggregate flags and ID */
    unsigned int    has_zero_length_psdu_type:1; /* zero-length PSDU type */

    u_int16_t  channel;                     /* Channel number */
    u_int32_t  frequency;                   /* Channel center frequency */
    u_int8_t  data_rate;                   /* Data rate, in .5 Mb/s units */
    u_int8_t   signal_percent;              /* Signal level, as a percentage */
    u_int8_t   noise_percent;               /* Noise level, as a percentage */
    int8_t    signal_dbm;                  /* Signal level, in dBm */
    int8_t    noise_dbm;                   /* Noise level, in dBm */
    u_int64_t  tsf_timestamp;
    u_int16_t  aggregate_flags;             /* A-MPDU flags */
    u_int32_t  aggregate_id;                /* ID for A-MPDU reassembly */
    u_int8_t   zero_length_psdu_type;       /* type of zero-length PSDU */
};



struct aggregate {
  unsigned int phy;
  union ieee_802_11_phy_info phy_info;
  int8_t rssi; /* sometimes only available on the last frame */
  unsigned int duration; /* total duration of data 
							in microseconds (without preamble) */
};

struct wlan_radio {
  struct aggregate *aggregate; /* if this frame is part of an aggregate, 
								  point to it, otherwise NULL */
  unsigned int prior_aggregate_data; /* length of all prior data in this aggregate
										used for calculating duration of this subframe */
  u_int64_t start_tsf;
  u_int64_t end_tsf;

  int64_t ifs; /* inter frame space in microseconds */

  u_int16_t nav;
  int8_t rssi;
};


static float ieee80211_htrate(u_int8_t mcs_index, u_int8_t bandwidth, u_int8_t short_gi);

static float ieee80211_vhtrate(u_int8_t mcs_index, u_int8_t bandwidth_index, u_int8_t short_gi);

static unsigned int calculate_11n_duration(unsigned int frame_length, struct ieee_802_11n *info_n, u_int8_t stbc_streams, u_int8_t in_aggregate);

static unsigned int calculate_11ac_duration(unsigned int frame_length, float data_rate);
unsigned int calculate_duration(struct ieee_802_11_phdr *phdr, unsigned int frame_length, u_int8_t in_aggregate, u_int8_t first_frame);
#endif
