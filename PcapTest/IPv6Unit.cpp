#include "IPv6Unit.h"

IPv6Unit::IPv6Unit() {
    m_initialized = false;
}

bool IPv6Unit::initialize(char* EtherData, size_t length) {

    if(length < 40) {
        return false;
    }

    m_version = ((*EtherData) >> 4) & 0x0F;
    m_trafficType = (((unsigned char)EtherData[0]) & 0x0F) | (((unsigned char)EtherData[1]) & 0xF0);
    m_diffServices = m_trafficType >> 2;
    m_expCongestionNotify = m_trafficType & 0x03;
    m_flowLabel = ((((unsigned char)EtherData[1]) & 0x0F) << 16) | ((((unsigned short)EtherData[2]) << 8) | ((((unsigned short)EtherData[3]) << 0) & 0xFF));
    m_payloadLength = (((unsigned short)EtherData[4]) << 8) | ((((unsigned short)EtherData[5]) << 0) & 0xFF);
    m_nextHeader = (NextHeader)EtherData[6];
    m_hopLimit = (unsigned char)EtherData[7];
    std::copy(EtherData + 8, EtherData + 24, m_sourceAddress.bytes);
    std::copy(EtherData + 24, EtherData + 40, m_destinationAddress.bytes);
    m_payloadData = EtherData + 40;

    m_initialized = true;
    return true;
}

bool IPv6Unit::initialize(const PcapEthernetUnit& ethernetUnit) {
    return initialize(ethernetUnit.payloadData, ethernetUnit.size);
}
