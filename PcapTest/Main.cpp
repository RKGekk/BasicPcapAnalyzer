// Разработать консольное приложение для подсчета статистики UDP / IP - пакетов в файле формата PCAP.
// 
// Редактировать
// Функциональные требования :
// Приложение должно отбрасывать любые не UDP / IP пакеты(например, TCP / IP)
// Приложение должно иметь возможность фильтровать UDP - пакеты по IP - адресу и / или порту назначения
// Приложение должно выводить на экран результаты анализа PCAP файла в отформатированным виде со следующей информацией :
// <Номер строки статистики по порядку> <Адрес источника : Порт источника> <Адрес назначения : Порт назначения> <Количество пакетов> <Общий объем данных в пакетах>
// Достаточно поддержки IPv4
// Редактировать
// Нефункциональные требования :
// Архитектура приложения должна следовать принципам ООП
// Код должен собираться с помощью компилятора g++
// Требования к стандарту с++ не предъявляются
// Проект должен быть организован с использование cmake
// Ограничений на использование сторонних библиотек нет
// Код должен быть написан аккуратно, словно будет запускаться в продакшене
// Редактировать
// Входные параметры :
// Обязательные параметры :
// Путь к PCAP - файлу
// Опциональные параметры :
// Фильтр по IP - адресу назначения
// Фильтр по порту назначения

#include <iostream>
#include <fstream>
#include <iomanip>
#include <chrono>
#include <ctime>

#include "pcap_hdr_t.h"
#include "pcaprec_hdr_t.h"
#include "LinkLayerType.h"
#include "PcapEthernet.h"
#include "EtherType.h"
#include "IPv6Unit.h"
#include "IPv4Unit.h"
#include "NextHeader.h"

int main() {

	
	const char* fileName = "ttt.pcap";
	//const char* fileName = "dhcp1.pcap";
	PcapEthernet capture(fileName);
	if(!capture.initialize()) {
		std::cout << "Initialization failed" << std::endl;
		return 0;
	}
	std::cout << capture << std::endl;

	int counter = 0;
	int UDPCounter = 0;
	capture.iterate([&](const PcapEthernetUnit& eu) {
		if(eu.protocol == EtherType::ET_IPv6) {
			IPv6Unit ipUnit;
			ipUnit.initialize(eu);
			std::cout << counter++ << " : IPv" << (int)ipUnit.m_version << std::endl;
			if(ipUnit.m_nextHeader == NextHeader::NH_UDP) {
				++UDPCounter;
			}
		}
		if (eu.protocol == EtherType::ET_IPv4) {
			IPv4Unit ipUnit;
			ipUnit.initialize(eu);
			std::cout << counter++ << " : IPv" << (int)ipUnit.m_version << std::endl;
			if (ipUnit.m_nextHeader == NextHeader::NH_UDP) {
				++UDPCounter;
			}
		}
	});

	std::cout << "Total UDP packets: " << UDPCounter << std::endl;

	return 0;
}