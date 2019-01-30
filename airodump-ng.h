#ifndef AIRODUMP_H
#define AIRODUMP_H

#include <stdint.h>

#define ENC_OPN		1
#define ENC_WEP		2
#define ENC_WPA		3
#define ENC_WPA2	4

#define CIPHER_NONE	0
#define CIPHER_WEP40	1
#define CIPHER_TKIP	2
#define CIPHER_WRAP	3
#define CIPHER_CCMP	4
#define CIPHER_WEP104	5

#define AUTH_OPN	0
#define AUTH_MGT	1
#define AUTH_PSK	2

#pragma pack(push, 1)

typedef struct _radiotap_header {
    uint8_t version;
    uint8_t pad;
    uint16_t length;
    uint32_t present_flag;
} radiotap_header;

enum radiotap_present_flag {
    RADIOTAP_TSFT = 0,
    RADIOTAP_FLAGS = 1,
    RADIOTAP_RATE = 2,
    RADIOTAP_CHANNEL = 3,
    RADIOTAP_FHSS = 4,
    RADIOTAP_DBM_ANTSIGNAL = 5,
    RADIOTAP_DBM_ANTNOISE = 6,
    RADIOTAP_LOCK_QUALITY = 7,
    RADIOTAP_TX_ATTENUATION = 8,
    RADIOTAP_DB_TX_ATTENUATION = 9,
    RADIOTAP_DBM_TX_POWER = 10,
    RADIOTAP_ANTENNA = 11,
    RADIOTAP_DB_ANTSIGNAL = 12,
    RADIOTAP_DB_ANTNOISE = 13,
    RADIOTAP_RX_FLAGS = 14,
    RADIOTAP_TX_FLAGS = 15,
    RADIOTAP_RTS_RETRIES = 16,
    RADIOTAP_DATA_RETRIES = 17,
    RADIOTAP_MCS = 19,
    RADIOTAP_AMPDU_STATUS = 20,
    RADIOTAP_VHT = 21,
    RADIOTAP_TIMESTAMP = 22,
    RADIOTAP_RADIOTAP_NAMESPACE = 29,
    RADIOTAP_VENDOR_NAMESPACE = 30,
    RADIOTAP_EXT = 31
};

typedef struct _ieee80211_header {
    uint8_t frame_control_version : 2;
    uint8_t frame_control_type : 2;
    uint8_t frame_control_subtype : 4;
    uint8_t flags; 
    uint16_t duration;
    uint8_t destination_addr[6];
    uint8_t source_addr[6];
    uint8_t bssid_addr[6];
    uint16_t fragment_number : 4;
    uint16_t sequence_number : 12;
} ieee80211_header;

enum ieee80211_flags {
    TO_DS = 0,
    FROM_DS = 1,
    MORE_FRAGEMENTS = 2,
    RETRY = 3,
    PWR_MAG = 4,
    MORE_DATA = 5,
    PROTECTED_FLAG = 7,
    ORDER_FLAG = 8
};

typedef struct _fixed_parameter {
    uint64_t timestamp;
    uint16_t beacon_interval;
    uint16_t capabilities_ess : 1;
    uint16_t capabilities_ibss : 1;
    uint16_t capabilities_cfp : 2;
    uint16_t capabilities_privacy : 1;
    uint16_t capabilities_short_preamble : 1;
    uint16_t capabilities_pbcc : 1;
    uint16_t capabilities_channel_agility : 1;
    uint16_t capabilities_spectrum_management : 1;
    uint16_t capabiltiies_short_slot_time : 1;
    uint16_t capabilities_cfp2 : 1;
    uint16_t capabilities_automatic_power_save_delivery : 1;
    uint16_t capabilities_radio_measurement : 1;
    uint16_t capabilities_dsss_ofdm : 1;
    uint16_t capabilities_delayed_block_ack : 1;
    uint16_t capabilities_immediate_block_ack : 1;
} fixed_parameter;

typedef struct _tagged_parameter {
    uint8_t tag_number;
    uint8_t tag_length;
} tagged_parameter;

typedef struct _beacon_information {
    uint8_t BSSID[6];
    int PWR;
    int BEACONS;
    int DATA;
    uint8_t CH;
    char MB[5];
    char ENC[5];
    char CIPHER[5];
    char AUTH[5];
    char ESSID[33];
} beacon_information;

typedef struct _probe_information {
    uint8_t BSSID[6];
    uint8_t STATION[6];
    int PWR;
    char RATE[16];
    int LOST;
    int FRAMES;
    char PROBE[33];
} probe_information;

#pragma pack(pop)

#endif
