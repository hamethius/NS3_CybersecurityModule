#ifndef NS3_CYBERMOD_H
#define NS3_CYBERMOD_H

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"

#include <vector>
#include <string>
#include <map>

namespace ns3 {

/* ================= GLOBAL STATISTICS ================= */
extern uint64_t totalPacketsReceived[100];
extern std::vector<Ptr<Packet>> capturedPackets;

struct AttackStats
{
    uint32_t packetsSent = 0;
    uint32_t packetsReceived = 0;
    Ipv4Address targetIp;
    std::string attackType;
};
extern std::map<uint32_t, AttackStats> attackerStats;

/* ================= VICTIM CLASS ================= */
class Victim
{
public:
    uint32_t victimId;          // Numeric ID
    std::string pcName;         // Human-readable name (PC1, PC2...)
    uint32_t cpuPower;
    uint32_t memoryMB;
    uint32_t maxPacketRate;
    bool hasFirewall;
    bool hasIntrusionDetection;

    Victim(uint32_t id);
};

/* ================= SIMULATION PARAMETERS ================= */
struct SimParams
{
    uint32_t numAttackers;
    uint32_t numVictims;
    uint16_t attackPort;
    std::string attackRate;     // Flood rate
    std::string attackType;     // udp-flood, tcp-flood, icmp-flood, ip-spoofing, replay
    std::string attackMode;     // dos or ddos

    std::vector<Ipv4InterfaceContainer> iface;
    NodeContainer attackers;
    NodeContainer victims;
};

/* ================= CALLBACKS ================= */
void PacketReceivedCallback(uint32_t victimId,
                            Ptr<const Packet> packet,
                            const Address &from);

void TxCounter(uint32_t attackerId, Ptr<const Packet> packet);

/* ================= ATTACK SETUP FUNCTIONS ================= */
void SetupOnOffFlood(const SimParams& params,
                     const std::string& socketFactory);

void SetupIpSpoofingAttack(const SimParams& params);

void SetupReplayAttack(const SimParams& params);

void SetupAttack(const SimParams& params);

/* ================= LOGGING FUNCTIONS ================= */
void SaveLogs(const SimParams& params);

/* ================= GLOBAL VICTIM REGISTRY ================= */
extern std::vector<Victim> victimRegistry;

} // namespace ns3

#endif // NS3_CYBERMOD_H
