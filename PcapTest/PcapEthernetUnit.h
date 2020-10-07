#pragma once
#include "pcaprec_hdr_t.h"
#include "Mac.h"
#include "EtherType.h"
#include "FCS.cpp"

struct PcapEthernetUnit {
	char* etherData;
	pcaprec_hdr_t phdr;
	Mac destination;
	Mac source;
	EtherType protocol;
	unsigned size;
	char* payloadData;
	FCS frameCheckSequence;
};