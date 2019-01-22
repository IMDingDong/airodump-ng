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
    uint32_t present_flag[2];
    uint8_t flags;
    uint16_t channel_frequency;
    uint16_t channel_flags;
    uint8_t data_rate;
    uint8_t antenna_signal1;
    uint8_t reserved;
    uint16_t rx_flags;
    uint8_t antenna_signal2;
    uint8_t antenna;
} radiotap_header;

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
    int S;
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
