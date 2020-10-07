#include "IPv4Unit.h"

IPv4Unit::IPv4Unit() {
	m_initialized = false;
}

bool IPv4Unit::initialize(char* EtherData, size_t length) {
    if (length < 20) {
        return false;
    }

    m_version = ((*EtherData) >> 4) & 0x0F;
    m_headerLength = ((unsigned char)EtherData[0]) & 0x0F;
    m_trafficType = (unsigned char)EtherData[1];
    m_diffServices = m_trafficType >> 2;
    m_expCongestionNotify = m_trafficType & 0x03;
    m_totalLength = (((unsigned short)EtherData[2]) << 8) | ((((unsigned short)EtherData[3]) << 0) & 0xFF);
    m_identification = (((unsigned short)EtherData[4]) << 8) | ((((unsigned short)EtherData[5]) << 0) & 0xFF);
    m_fragmentationFlag = ((EtherData[6]) >> 5) & 0x07;
    m_fragmentatOffset = ((((unsigned short)EtherData[6]) << 8) & 0xE000) | ((((unsigned short)EtherData[7]) << 0) & 0xFF);
    m_ttl = (unsigned char)EtherData[8];
    m_nextHeader = (NextHeader)EtherData[9];
    m_checkSum = (((unsigned short)EtherData[10]) << 8) | ((((unsigned short)EtherData[11]) << 0) & 0xFF);
    std::copy(EtherData + 12, EtherData + 16, m_sourceAddress.bytes);
    std::copy(EtherData + 16, EtherData + 20, m_destinationAddress.bytes);
    
    m_payloadData = EtherData + 20;

    m_initialized = true;
    return true;
}

bool IPv4Unit::initialize(const PcapEthernetUnit& ethernetUnit) {
	return initialize(ethernetUnit.payloadData, ethernetUnit.size);
}
