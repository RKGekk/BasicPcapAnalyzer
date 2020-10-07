#pragma once

#include "LinkLayerType.h"

typedef struct pcap_hdr_s {
    unsigned magic_number; /* magic number */
    unsigned short version_major; /* major version number */
    unsigned short version_minor; /* minor version number */
    int thiszone; /* GMT to local correction */
    unsigned sigfigs; /* accuracy of timestamps */
    unsigned snaplen; /* max length of captured packets, in octets */
    LinkLayerType network; /* data link type */
} pcap_hdr_t;