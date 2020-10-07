#pragma once

typedef struct pcaprec_hdr_s {
    unsigned ts_sec; /* timestamp seconds */
    unsigned ts_usec; /* timestamp microseconds */
    unsigned incl_len; /* number of octets of packet saved in file */
    unsigned orig_len; /* actual length of packet */
} pcaprec_hdr_t;