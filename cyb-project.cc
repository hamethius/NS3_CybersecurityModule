/*
 * NS-3 Network Attacks & Defense Module
 * Features: UDP Flood, ICMP Flood, Malware Injection
 * Defenses: Rate Limiting, Port Filtering, Deep Packet Inspection (DPI)
 */

#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/packet-sink.h"
#include "ns3/point-to-point-module.h"
#include "ns3/udp-socket-factory.h"
#include "ns3/ipv4-header.h"
#include "ns3/udp-header.h"
#include <iostream>
#include <iomanip>
#include <string>
#include <map>

using namespace ns3;

// ===========================================================================
//                                GLOBAL CONFIGURATION
// ===========================================================================

bool g_simEnableFirewall    = true;  
bool g_simEnableRateLimit   = true;  
bool g_simEnablePortFilter  = true;  
bool g_simEnableDpi         = true;  

bool g_simRunUdpFlood       = true;  
bool g_simRunIcmpFlood      = true;  
bool g_simRunMalware        = true;
bool g_simSummaryMode       = false; 

// ===========================================================================
//                                SMART LOGGER
// ===========================================================================

#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[1;31m" 
#define COLOR_GREEN   "\033[1;32m" 
#define COLOR_YELLOW  "\033[1;33m" 
#define COLOR_PURPLE  "\033[1;35m" 

// Tracking variables for summary mode
std::map<std::string, int> g_logCounts;
int g_currentSecond = -1;

std::string GetNodeIdFromContext(std::string context) {
    size_t first = context.find("/NodeList/");
    if (first != std::string::npos) {
        size_t second = context.find("/", first + 10);
        return "Node " + context.substr(first + 10, second - (first + 10));
    }
    return "Unknown";
}

void LogPacketDecision(std::string context, Ipv4Address src, std::string proto, 
                       std::string action, std::string reason, std::string color) {
    
    // 1. Time Management
    int timeSec = (int)Simulator::Now().GetSeconds();
    if (timeSec > g_currentSecond) {
        g_currentSecond = timeSec;
        g_logCounts.clear(); // Reset counters every second
    }

    // 2. Construct a unique key for this type of event (e.g., "10.1.1.1-DROP-Flood")
    std::ostringstream keyStream;
    keyStream << src << "-" << action << "-" << reason;
    std::string key = keyStream.str();

    // 3. Check Summary Mode Limit
    // If summary is ON, we only show the first 3 packets of each type per second
    if (g_simSummaryMode) {
        if (g_logCounts[key] >= 3) {
            return; // SKIP LOGGING (Silence)
        }
        g_logCounts[key]++;
    }

    // 4. Print Log
    std::cout << std::left 
              << "[" << std::setw(7) << std::fixed << std::setprecision(4) << Simulator::Now().GetSeconds() << "s] "
              << "| " << std::setw(8) << GetNodeIdFromContext(context)
              << "| " << std::setw(13) << src
              << "| " << std::setw(5) << proto
              << "| " << color << std::setw(8) << action << COLOR_RESET
              << "| " << reason 
              << std::endl;
    
    // 5. Print a visual indicator if we hit the limit in summary mode
    if (g_simSummaryMode && g_logCounts[key] == 3) {
         std::cout << "           | ... (Suppressing similar logs for this second) ..." << std::endl;
    }
}

// ===========================================================================
//                                DEFENSE MODULE
// ===========================================================================

class DefenseModule : public Object {
public:
    static TypeId GetTypeId(void);
    
    DefenseModule() {
        m_packetCount = 0;
        m_lastCheckTime = Seconds(0);
        m_threshold = 50; 
    }

    bool InspectPacket(std::string context, Ptr<const Packet> packet, Ptr<Ipv4> ipv4, uint32_t interface) {
        
        if (!g_simEnableFirewall) {
            // Even in summary mode, we log passed packets to show flow
            Ipv4Header ipHeader; packet->PeekHeader(ipHeader);
            LogPacketDecision(context, ipHeader.GetSource(), "ALL", "PASS", "Firewall Disabled", COLOR_GREEN);
            return true;
        }

        Ipv4Header ipHeader;
        packet->PeekHeader(ipHeader);
        Ipv4Address srcIp = ipHeader.GetSource();
        uint32_t packetSize = packet->GetSize();
        
        std::string protoStr = "OTHER";
        if (ipHeader.GetProtocol() == 6) protoStr = "TCP";
        else if (ipHeader.GetProtocol() == 17) protoStr = "UDP";
        else if (ipHeader.GetProtocol() == 1) protoStr = "ICMP";

        UdpHeader udpHeader;
        bool isUdp = (ipHeader.GetProtocol() == 17);

        // --- DEFENSE 1: MALWARE ---
        if (g_simEnableDpi) {
            uint8_t *buffer = new uint8_t[packetSize];
            packet->CopyData(buffer, packetSize);
            std::string payload((char*)buffer, packetSize);
            delete[] buffer;

            if (payload.find("MALWARE_HASH") != std::string::npos) {
                LogPacketDecision(context, srcIp, protoStr, "DROP", "Malware Signature Detected", COLOR_PURPLE);
                return false; 
            }
        }

        // --- DEFENSE 2: PORT FILTER ---
        if (g_simEnablePortFilter && isUdp) {
            Ptr<Packet> copy = packet->Copy();
            copy->RemoveHeader(ipHeader);
            if (copy->PeekHeader(udpHeader)) {
                if (udpHeader.GetDestinationPort() == 0) {
                    LogPacketDecision(context, srcIp, protoStr, "DROP", "Invalid Port 0 (Fake ICMP)", COLOR_YELLOW);
                    return false; 
                }
            }
        }

        // --- DEFENSE 3: RATE LIMITING ---
        if (g_simEnableRateLimit && isUdp) { 
            Time now = Simulator::Now();
            if (now - m_lastCheckTime >= Seconds(1.0)) {
                m_packetCount = 0;
                m_lastCheckTime = now;
            }
            m_packetCount++;

            if (m_packetCount > m_threshold) {
                LogPacketDecision(context, srcIp, protoStr, "DROP", "Flood Rate Limit Exceeded", COLOR_RED);
                return false; 
            }
        }

        LogPacketDecision(context, srcIp, protoStr, "PASS", "Traffic Authorized", COLOR_GREEN);
        return true;
    }

private:
    uint32_t m_packetCount;
    Time m_lastCheckTime;
    uint32_t m_threshold;
};

NS_OBJECT_ENSURE_REGISTERED(DefenseModule);

TypeId DefenseModule::GetTypeId(void) {
    static TypeId tid = TypeId("DefenseModule")
        .SetParent<Object>()
        .SetGroupName("Network")
        .AddConstructor<DefenseModule>();
    return tid;
}

Ptr<DefenseModule> g_firewall;

void RxTrace(std::string context, Ptr<const Packet> packet, Ptr<Ipv4> ipv4, uint32_t interface) {
    if (g_firewall) g_firewall->InspectPacket(context, packet, ipv4, interface);
}

// ===========================================================================
//                                ATTACKS
// ===========================================================================

void SendFloodPacket(Ptr<Socket> socket, InetSocketAddress remote, uint32_t size, double interval) {
    if (!g_simRunUdpFlood) return; 
    Ptr<Packet> packet = Create<Packet>(size);
    socket->SendTo(packet, 0, remote);
    Simulator::Schedule(Seconds(interval), &SendFloodPacket, socket, remote, size, interval);
}

void UdpFloodAttack(Ptr<Node> attacker, Ipv4Address victim, uint16_t port, uint32_t size, double interval) {
    if (!g_simRunUdpFlood) return;
    std::cout << "\n" << COLOR_RED << ">>> SYSTEM ALERT: UDP FLOOD ATTACK INITIATED" << COLOR_RESET << "\n" << std::endl;
    Ptr<Socket> socket = Socket::CreateSocket(attacker, UdpSocketFactory::GetTypeId());
    InetSocketAddress remote(victim, port);
    Simulator::Schedule(Seconds(0.0), &SendFloodPacket, socket, remote, size, interval);
}

void IcmpFloodAttack(Ptr<Node> attacker, Ipv4Address victim, uint32_t size, double interval) {
    if (!g_simRunIcmpFlood) return;
    std::cout << "\n" << COLOR_YELLOW << ">>> SYSTEM ALERT: ICMP FLOOD ATTACK INITIATED" << COLOR_RESET << "\n" << std::endl;
    Ptr<Socket> socket = Socket::CreateSocket(attacker, UdpSocketFactory::GetTypeId());
    InetSocketAddress remote(victim, 0); 
    Simulator::Schedule(Seconds(0.01), [socket, remote, size, interval]() mutable {
        Ptr<Packet> packet = Create<Packet>(size);
        socket->SendTo(packet, 0, remote);
        Simulator::Schedule(Seconds(interval), [socket, remote, size, interval]() mutable {
            Ptr<Packet> packet = Create<Packet>(size);
            socket->SendTo(packet, 0, remote);
        });
    });
}

void MalwarePacketAttack(Ptr<Node> attacker, Ipv4Address victim, std::string hash) {
    if (!g_simRunMalware) return;
    std::cout << "\n" << COLOR_PURPLE << ">>> SYSTEM ALERT: MALWARE INJECTION INITIATED" << COLOR_RESET << "\n" << std::endl;
    Ptr<Socket> socket = Socket::CreateSocket(attacker, UdpSocketFactory::GetTypeId());
    InetSocketAddress remote(victim, 5555);
    std::string payload = "MALWARE_HASH:" + hash;
    Ptr<Packet> packet = Create<Packet>((uint8_t*)payload.c_str(), payload.size());
    Simulator::Schedule(Seconds(1.0), [socket, remote, packet]() mutable {
        socket->SendTo(packet, 0, remote);
    });
}

// ===========================================================================
//                                MAIN
// ===========================================================================

int main(int argc, char* argv[]) {
    
    CommandLine cmd;
    cmd.AddValue("firewall", "Enable/Disable Entire Firewall", g_simEnableFirewall);
    cmd.AddValue("defenseFlood", "Enable/Disable Rate Limiting Defense", g_simEnableRateLimit);
    cmd.AddValue("defenseIcmp", "Enable/Disable ICMP/Port0 Filtering", g_simEnablePortFilter);
    cmd.AddValue("defenseMalware", "Enable/Disable Malware DPI", g_simEnableDpi);
    cmd.AddValue("attackFlood", "Run UDP Flood Attack", g_simRunUdpFlood);
    cmd.AddValue("attackIcmp", "Run ICMP Flood Attack", g_simRunIcmpFlood);
    cmd.AddValue("attackMalware", "Run Malware Attack", g_simRunMalware);
    cmd.AddValue("summary", "Enable summary mode (reduce log spam)", g_simSummaryMode);

    cmd.Parse(argc, argv);

    std::cout << "\n";
    std::cout << "==================================================================================" << std::endl;
    std::cout << "                       CYBERSECURITY SIMULATION: CONFIGURATION                    " << std::endl;
    std::cout << "==================================================================================" << std::endl;
    std::cout << std::left << std::setw(30) << "MODULE" << std::setw(20) << "STATUS" << std::endl; 
    std::cout << "--------------------------------------------------" << std::endl;
    std::cout << std::left << std::setw(30) << "Firewall Master" << (g_simEnableFirewall ? "ON" : "OFF") << std::endl;
    std::cout << std::left << std::setw(30) << "Rate Limiting" << (g_simEnableRateLimit ? "ON" : "OFF") << std::endl;
    std::cout << std::left << std::setw(30) << "Port Filtering" << (g_simEnablePortFilter ? "ON" : "OFF") << std::endl;
    std::cout << std::left << std::setw(30) << "DPI (Malware)" << (g_simEnableDpi ? "ON" : "OFF") << std::endl;
    std::cout << "--------------------------------------------------" << std::endl;
    std::cout << std::left << std::setw(30) << "Attack: UDP Flood" << (g_simRunUdpFlood ? "ON" : "OFF") << std::endl;
    std::cout << std::left << std::setw(30) << "Attack: ICMP Flood" << (g_simRunIcmpFlood ? "ON" : "OFF") << std::endl;
    std::cout << std::left << std::setw(30) << "Attack: Malware" << (g_simRunMalware ? "ON" : "OFF") << std::endl;
    std::cout << std::left << std::setw(30) << "Log Mode" << (g_simSummaryMode ? "SUMMARY (Short)" : "FULL (Detailed)") << std::endl;
    std::cout << "==================================================================================" << std::endl;
    std::cout << "\n";

    std::cout << std::left 
              << std::setw(10) << "[TIME]"
              << "| " << std::setw(8) << "[NODE]"
              << "| " << std::setw(13) << "[SRC IP]"
              << "| " << std::setw(5) << "[PROTO]"
              << "| " << std::setw(8) << "[ACTION]"
              << "| " << "[REASON / INFO]" << std::endl;
    std::cout << "----------------------------------------------------------------------------------" << std::endl;

    NodeContainer nodes; nodes.Create(2);

    PointToPointHelper ptp;
    ptp.SetDeviceAttribute("DataRate", StringValue("5Mbps"));
    ptp.SetChannelAttribute("Delay", StringValue("2ms"));
    NetDeviceContainer devices = ptp.Install(nodes);

    InternetStackHelper internet; internet.Install(nodes);
    Ipv4AddressHelper ipv4; ipv4.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer iface = ipv4.Assign(devices);
    
    Ptr<Node> attackerNode = nodes.Get(0);
    Ptr<Node> victimNode = nodes.Get(1);
    Ipv4Address victimIp = iface.GetAddress(1);

    g_firewall = CreateObject<DefenseModule>();
    Config::Connect("/NodeList/1/$ns3::Ipv4L3Protocol/Rx", MakeCallback(&RxTrace));

    uint16_t port = 9;
    BulkSendHelper source("ns3::TcpSocketFactory", InetSocketAddress(victimIp, port));
    source.SetAttribute("MaxBytes", UintegerValue(0));
    ApplicationContainer sourceApps = source.Install(attackerNode);
    sourceApps.Start(Seconds(0.0));
    sourceApps.Stop(Seconds(10.0));

    PacketSinkHelper sink("ns3::TcpSocketFactory", InetSocketAddress(Ipv4Address::GetAny(), port));
    ApplicationContainer sinkApps = sink.Install(victimNode);
    sinkApps.Start(Seconds(0.0));
    sinkApps.Stop(Seconds(10.0));

    Simulator::Schedule(Seconds(2.0), &UdpFloodAttack, attackerNode, victimIp, port, 1024, 0.005);
    Simulator::Schedule(Seconds(4.0), &IcmpFloodAttack, attackerNode, victimIp, 64, 0.01);
    Simulator::Schedule(Seconds(6.0), &MalwarePacketAttack, attackerNode, victimIp, std::string("HASH123XYZ"));

    Simulator::Stop(Seconds(10.0));
    Simulator::Run();
    Simulator::Destroy();

    Ptr<PacketSink> sinkPtr = DynamicCast<PacketSink>(sinkApps.Get(0));
    std::cout << "\n==================================================================================" << std::endl;
    std::cout << "[RESULT] Total Valid Application Bytes Received: " << sinkPtr->GetTotalRx() << std::endl;
    std::cout << "==================================================================================" << std::endl;

    return 0;
}
