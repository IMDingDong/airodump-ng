#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <time.h>
#include <pcap.h>

#include "airodump-ng.h"

int channel_array[] = {1, 7, 13, 2, 8, 3, 14, 9, 4, 10, 5, 11, 6, 12};    // Channel Hopping 1 ~ 14
int channel_count = 0;    // 0 ~ 13

long long time_count = 0;
int elapsed =  0;

int beacon_count = 0;
int probe_count = 0;

beacon_information beacon_info[100];
probe_information probe_info[100];

void usage() {
    printf("usage: ./airodump-ng <interface>\n");
    printf("sample: ./airodump-ng -c 1 mon0\n\n");
}

void print_mac(uint8_t * MAC_address) {
    printf(" %02X:%02X:%02X:%02X:%02X:%02X ", MAC_address[0], MAC_address[1], MAC_address[2], MAC_address[3], MAC_address[4], MAC_address[5]);
}

void display(int beacon_count, int probe_count, beacon_information * pbeacon, probe_information * pprobe) {
    /* time */
    struct tm * date;
    const time_t t = time(NULL);
    date = localtime(&t);

    printf("\e[2J\e[H\e[?25l");    // \e[2J : clear entire screen, \e[H : move cursor to upper left corner, \e[?25l : hide cursor
    printf("\n CH %2d", channel_array[channel_count]);    // TODO incomplete
    printf(" ][ Elapsed: %d s", elapsed);    // TODO incomplete
    printf(" ][ %4d-%02d-%02d %02d:%02d", date->tm_year + 1900, date->tm_mon + 1, date->tm_mday, date->tm_hour, date->tm_min);
    // printf(" ][ WPA handshake: %18s");

    printf("\n\n BSSID              PWR  Beacons    #Data, #/s  CH  MB   ENC  CIPHER AUTH ESSID\n\n");

    for (int i = 0; i < beacon_count; i++) {
        print_mac(pbeacon[i].BSSID);
        printf(" %3d     %4d     %4d  %3d  %2d  %-4s %-4s %-4s   %-3s  %-33s\n", 
            pbeacon[i].PWR, pbeacon[i].BEACONS, pbeacon[i].DATA, pbeacon[i].S, pbeacon[i].CH, 
            pbeacon[i].MB, pbeacon[i].ENC, pbeacon[i].CIPHER, pbeacon[i].AUTH, pbeacon[i].ESSID);
    }

    printf("\n BSSID              STATION            PWR   Rate    Lost    Frames  Probe\n\n");

    for (int j = 0; j < probe_count; j++) {
        print_mac(pprobe[j].BSSID);
        print_mac(pprobe[j].STATION);
        printf(" %3d  %7s  %5d    %5d  %-33s\n", pprobe[j].PWR, pprobe[j].RATE, pprobe[j].LOST, pprobe[j].FRAMES, pprobe[j].PROBE);
    }
    printf("\n");
}

long long tickCount()
{
    struct timeval te; 
    gettimeofday(&te, NULL);
    long long milliseconds = te.tv_sec*1000LL + te.tv_usec/1000;
    return milliseconds;
}

void * timer(void * dev) {
    while(1) {
        char cmd[255];
        if (tickCount() - time_count > 1000) {    // Every Second
            time_count = tickCount();
            elapsed++;
            snprintf(cmd, sizeof(cmd), "iwconfig %s channel %d", (char *)dev, channel_array[channel_count]);
            system(cmd);

            display(beacon_count, probe_count, beacon_info, probe_info);

            if (channel_count <= 13) channel_count++;
            else channel_count = 0;
        }
    }
}

int main(int argc, char * argv[]) {
    char * dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t * handle;
    struct pcap_pkthdr * header;
    const u_char * packet;
    int res;

    pthread_t p_thread;
    int thr_id;
    int status;

    int data_count = 0;

    int s_num = 0;    // TODO 10 sec packet count
    int tagged_size = 0;
    u_char * tag_data;

    int check = 0;
    int cnt = 0;

    int pwr = 0;
    int MB = 0;
    int rsn = 0;

    radiotap_header * radiotap;
    ieee80211_header * ieee80211;

    fixed_parameter * fixed;
    tagged_parameter * tagged;

    if (argc < 2) {
        usage();
        return -1;
    }

    dev = argv[argc-1];

    if ((handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf)) == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    };

    // display(beacon_count, probe_count, beacon_info, probe_info);    // initial screen

    thr_id = pthread_create(&p_thread, NULL, timer, (void *)argv[argc-1]);

    while (1) {
        res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        else if (res == -1 || res == -2) break;

	radiotap = (radiotap_header *)packet;
        ieee80211 = (ieee80211_header *)(packet + radiotap->length);
/*
        for (uint32_t pflag = 0; pflag < 32; pflag++) {
            if (radiotap->present_flag & (1 << pflag)) {
                switch(pflag) {
                    case RADIOTAP_TSFT:
                    case RADIOTAP_FLAGS:
                    case RADIOTAP_RATE:
                    case RADIOTAP_CHANNEL:
                    case RADIOTAP_FHSS:
                    case RADIOTAP_DBM_ANTSIGNAL:
                    case RADIOTAP_DBM_ANTNOISE:
                    case RADIOTAP_LOCK_QUALITY:
                    case RADIOTAP_TX_ATTENUATION:
                    case RADIOTAP_DB_TX_ATTENUATION:
                    case RADIOTAP_DBM_TX_POWER:
                    case RADIOTAP_ANTENNA:
                    case RADIOTAP_DB_ANTSIGNAL:
                    case RADIOTAP_DB_ANTNOISE:
                    case RADIOTAP_RX_FLAGS:
                    case RADIOTAP_TX_FLAGS:
                    case RADIOTAP_RTS_RETRIES:
                    case RADIOTAP_DATA_RETRIES:
                    case RADIOTAP_MCS:
                    case RADIOTAP_AMPDU_STATUS:
                    case RADIOTAP_VHT:
                    case RADIOTAP_TIMESTAMP:
                    case RADIOTAP_RADIOTAP_NAMESPACE:
                    case RADIOTAP_VENDOR_NAMESPACE:
                    case RADIOTAP_EXT:
                        break;
                } 
            }
        }
*/
        /* [BEACON FRAME] */
        if (ieee80211->frame_control_type == 0x00 && ieee80211->frame_control_subtype == 0x08) {
            for (check = 0, cnt = 0; cnt < beacon_count; cnt++) {
                if (!memcmp(beacon_info[cnt].BSSID, ieee80211->bssid_addr, sizeof(beacon_info[cnt].BSSID))) {
                    check = 1;
                    beacon_info[cnt].PWR = pwr;
                    beacon_info[cnt].BEACONS++;
                    break;
                }
            }
            if (!check) {
                memcpy(beacon_info[beacon_count].BSSID, ieee80211->bssid_addr, sizeof(beacon_info[beacon_count].BSSID));
 
                beacon_info[beacon_count].PWR = pwr;
                beacon_info[beacon_count].BEACONS = 1;
                beacon_info[beacon_count].DATA = data_count;
                beacon_info[beacon_count].S = s_num;

                fixed = (fixed_parameter *)((u_char *)ieee80211 + sizeof(ieee80211_header));
                tagged = (tagged_parameter *)((u_char *)fixed + sizeof(fixed_parameter));

                tagged_size = header->caplen - radiotap->length - sizeof(ieee80211_header) - sizeof(fixed_parameter);

                if (fixed->capabilities_privacy == 0) {
                    strncpy(beacon_info[beacon_count].ENC, "OPN", sizeof(beacon_info[beacon_count].ENC));
                    strncpy(beacon_info[beacon_count].CIPHER, " ", sizeof(beacon_info[beacon_count].CIPHER));
                    strncpy(beacon_info[beacon_count].AUTH, " ", sizeof(beacon_info[beacon_count].AUTH));
                }

                while (tagged_size > 0) {
                    tag_data = (u_char *)tagged + sizeof(tagged_parameter);
                    switch(tagged->tag_number) {
                        case 0x00:    // SSID
                            strncpy(beacon_info[beacon_count].ESSID, tag_data, tagged->tag_length);
                            break;

                        case 0x01:    // SUPORTED DATA RATES
                        case 0x32:    // EXTENDED SUPPORTED RATES
                            switch (*(uint8_t *)(tag_data + tagged->tag_length -1)) {
                                case 0x81:
                                    MB = 1;
                                    break;

                                case 0x84:
                                    MB = 2;
                                    break;

                                case 0x8B:
                                    MB = 5;
                                    break;

                                case 0x96:
                                    MB = 11;
                                    break;

                                case 0x24:
                                    MB = 18;
                                    break;

                                case 0x30:
                                    MB = 24;
                                    break;

                                case 0x48:
                                    MB = 36;
                                    break;

                                case 0x6C:
                                    MB = 54;
                                    break;

                                default:
                                    break;
                            }
                            snprintf(beacon_info[beacon_count].MB, sizeof(beacon_info[beacon_count].MB), "%2d%1s%1s", MB, "e", ".");    //TODO qos -> e , preamble -> .
                            break;

                        case 0x03:    // DIRECT SEQUNCE CHANNEL SET
                            beacon_info[beacon_count].CH = *(uint8_t *)(tag_data);
                            break;

                        case 0x30:    // RSN INFORMATION ELEMENT
                            rsn = 5;
                            switch (*(uint8_t *)(tag_data + rsn)) {    // Group Cipher Suite Type
                                case 0x01:    // WEP 40
                                    strncpy(beacon_info[beacon_count].CIPHER, "WEP", 4);
                                    strncpy(beacon_info[beacon_count].ENC, "WEP", 4);
                                    break;

                                case 0x02:
                                    strncpy(beacon_info[beacon_count].CIPHER, "TKIP", 5);
                                    strncpy(beacon_info[beacon_count].ENC, "WPA", 4);
                                    break;

                                case 0x03:
                                    strncpy(beacon_info[beacon_count].CIPHER, "WARP", 5);
                                    break;

                                case 0x04:
                                    strncpy(beacon_info[beacon_count].CIPHER, "CCMP", 5);
                                    break;

                                case 0x05:    // WEP104
                                    strncpy(beacon_info[beacon_count].CIPHER, "WEP", 7);
                                    strncpy(beacon_info[beacon_count].ENC, "WEP", 4);
                                    break;

                                default:
                                    strncpy(beacon_info[beacon_count].CIPHER, " ", 2);
                                    break;
                            }

                            rsn += 2 + *(uint16_t *)(tag_data + rsn + 1) * 4;
                            switch(*(uint8_t *)(tag_data + rsn)) {    // Pairwise Cipher Suite Type
                                case 0x04:
                                    strncpy(beacon_info[beacon_count].ENC, "WPA2", 5);
                                    break;
                            }

                            rsn += 2 + *(uint16_t *)(tag_data + rsn + 1) * 4;
                            switch(*(uint8_t *)(tag_data + rsn)) {    // Auth Key Management Type
                                case 0x01:
                                    strncpy(beacon_info[beacon_count].AUTH, "MGT", 4); 
                                    break;

                                case 0x02:
                                    strncpy(beacon_info[beacon_count].AUTH, "PSK", 4);
                                    break;

                                default:
                                    strncpy(beacon_info[beacon_count].AUTH, " ", 2); 
                                    break;
                            }
                            break;

                        case 0xDD:
                            if (!memcmp(tag_data, "\x00\x50\xF2\x02\x01\x01", 6)) {
                                // qos = 1;
                            }
                            break;

/*
                        case 0xDD:    // VENDOR SPECIFIC: MICROSOFT CORP
                           switch (*(uint8_t *)((u_char *)tagged + sizeof(tagged_parameter) + 4)) {    // Type
                               case 0x01:
                               case 0x02:
                                   strncpy(beacon_info[beacon_count].ENC, "WPA", 4);
                                   break;

                               case 0x04:
                                   strncpy(beacon_info[beacon_count].ENC, "WPA2", 5);
                                   break;

                               default:
                                   strncpy(beacon_info[beacon_count].ENC, "ZZZ", 4);
                                   break;
                           } 
*/
                        deault:
                            break;
                    }
		    tagged_size -= sizeof(tagged_parameter) + tagged->tag_length;
		    tagged = (tagged_parameter *)(tag_data + tagged->tag_length);
                }

                beacon_count++;
                display(beacon_count, probe_count, beacon_info, probe_info);
            }
        }

        /* [PROBE RESPONSE FRAME] */
        if (ieee80211->frame_control_type == 0x00 && ieee80211->frame_control_subtype == 0x05) {
            for (check = 0, cnt = 0; cnt < probe_count; cnt++) {
                if (!memcmp(probe_info[cnt].BSSID, ieee80211->bssid_addr, sizeof(probe_info[cnt].BSSID))) {
                    check = 1;
                    probe_info[cnt].PWR = pwr;
                    probe_info[cnt].FRAMES++;

                    // display(beacon_count, probe_count, beacon_info, probe_info);
                    break;
                }
            }
            if (!check) {
                memcpy(probe_info[probe_count].BSSID, ieee80211->bssid_addr, sizeof(probe_info[probe_count].BSSID));
                memcpy(probe_info[probe_count].STATION, ieee80211->destination_addr, sizeof(probe_info[probe_count].STATION));

                probe_info[probe_count].PWR = pwr;
                probe_info[probe_count].FRAMES = 1;

                probe_info[probe_count].LOST = 0;    // TODO incomplete
                strcpy(probe_info[probe_count].RATE, "0e-6e");    // TODO incomplete

                fixed = (fixed_parameter *)((u_char *)ieee80211 + sizeof(ieee80211_header));
                tagged = (tagged_parameter *)((u_char *)fixed + sizeof(fixed_parameter));

                tagged_size = header->caplen - radiotap->length - sizeof(ieee80211_header) - sizeof(fixed_parameter);

                while (tagged_size > 0) {
                    switch(tagged->tag_number) {
                        case 0x00:    // SSID
                            strncpy(probe_info[probe_count].PROBE, (u_char *)tagged + sizeof(tagged_parameter), tagged->tag_length);    // TODO incomplete
                            break;

                        default:
                            break;
                    }
                    tagged_size -= sizeof(tagged_parameter) + tagged->tag_length;
                    tagged = (tagged_parameter *)((u_char *)tagged + sizeof(tagged_parameter) + tagged->tag_length);
                }

                fixed = (fixed_parameter *)((u_char *)ieee80211 + sizeof(ieee80211_header));
                tagged = (tagged_parameter *)((u_char *)fixed + sizeof(fixed_parameter));

                probe_count++;
                display(beacon_count, probe_count, beacon_info, probe_info);
            }
        }

        /* [PROBE REQUEST FRAME] */
        if (ieee80211->frame_control_type == 0x00 && ieee80211->frame_control_subtype == 0x04) {
            //for (check = 0, cnt = 0; cnt < probe_count; cnt++) {
                //if (!memcmp(probe_info[cnt].BSSID, ieee80211->bssid_addr, sizeof(probbe_info[cnt].STATION))) {
                    //check = 1;
                    //probe_info[cnt].PWR = (char)radiotpa->antenna_signal1;
                    //probe_info[cnt].FRAMES++;

                    //break;
                //}
            //}
        }


        /* [DATA FRAMES] */
        if (ieee80211->frame_control_type == 0x02) {
            for (cnt = 0; cnt < beacon_count; cnt++) {
                if (!memcmp(beacon_info[cnt].BSSID, ieee80211->bssid_addr, sizeof(beacon_info[cnt].BSSID))) {
                    beacon_info[cnt].DATA++;
                }
            }
        }
    }
    pcap_close(handle);
    return 0;
}
