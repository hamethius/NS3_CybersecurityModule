#include "ns3/ns3cybermod.h"
#include "ns3/on-off-helper.h"
#include "ns3/packet-sink.h"
#include "ns3/ipv4-raw-socket-factory.h"
#include "ns3/ipv4-header.h"
#include "ns3/udp-header.h"
#include "ns3/tcp-header.h"
#include "ns3/socket.h"
#include "ns3/simulator.h"
#include <fstream>
#include <cstdlib>

namespace ns3 {

/* ================= GLOBAL VARIABLES ================= */
uint64_t totalPacketsReceived[100] = {0};
std::vector<Ptr<Packet>> capturedPackets;
std::vector<Victim> victimRegistry;
std::map<uint32_t, AttackStats> attackerStats;

/* ================= VICTIM CONSTRUCTOR ================= */
Victim::Victim(uint32_t id)
    : victimId(id),
      pcName("PC" + std::to_string(id + 1)),
      cpuPower(2),
      memoryMB(1024),
      maxPacketRate(5000),
      hasFirewall(false),
      hasIntrusionDetection(false)
{
}

/* ================= CALLBACKS ================= */
void PacketReceivedCallback(uint32_t victimId,
                            Ptr<const Packet> packet,
                            const Address &from)
{
    totalPacketsReceived[victimId]++;
}

void TxCounter(uint32_t attackerId, Ptr<const Packet> packet)
{
    attackerStats[attackerId].packetsSent++;
}

/* ================= FLOOD ATTACK ================= */
void SetupOnOffFlood(const SimParams& params,
                     const std::string& socketFactory)
{
    uint32_t A = params.numAttackers;
    uint32_t V = params.numVictims;
    uint32_t attackerLimit = (params.attackMode == "dos") ? 1 : A;

    // Install PacketSink on victims
    for (uint32_t v = 0; v < V; v++)
    {
        // FIX: Use params.numAttackers to skip ALL attackers to find victim IPs
        PacketSinkHelper sink(
            socketFactory,
            InetSocketAddress(params.iface[0].GetAddress(params.numAttackers + v),
                              params.attackPort));

        ApplicationContainer sinkApp = sink.Install(params.victims.Get(v));
        sinkApp.Start(Seconds(0.0));
        sinkApp.Stop(Seconds(12.0));

        Ptr<PacketSink> sinkPtr = DynamicCast<PacketSink>(sinkApp.Get(0));
        sinkPtr->TraceConnectWithoutContext(
            "Rx", MakeBoundCallback(&PacketReceivedCallback, v));
    }

    // Install OnOffApplication on attackers
    for (uint32_t a = 0; a < attackerLimit; a++)
    {
        for (uint32_t v = 0; v < V; v++)
        {
            // FIX: Use params.numAttackers here too
            OnOffHelper onoff(
                socketFactory,
                InetSocketAddress(params.iface[0].GetAddress(params.numAttackers + v),
                                  params.attackPort));

            onoff.SetConstantRate(DataRate(params.attackRate));
            onoff.SetAttribute("PacketSize", UintegerValue(512));

            ApplicationContainer app = onoff.Install(params.attackers.Get(a));
            app.Start(Seconds(1.0));
            app.Stop(Seconds(11.0));

            Ptr<OnOffApplication> onoffApp = DynamicCast<OnOffApplication>(app.Get(0));
            onoffApp->TraceConnectWithoutContext("Tx", MakeBoundCallback(&TxCounter, a));

            // Store metadata for logging
            attackerStats[a].attackType = params.attackType;
            attackerStats[a].targetIp = params.iface[0].GetAddress(params.numAttackers + v);
        }
    }
}

/* ================= IP SPOOFING ATTACK ================= */
void SetupIpSpoofingAttack(const SimParams& params)
{
    uint32_t A = params.numAttackers;
    uint32_t V = params.numVictims;
    uint32_t attackerLimit = (params.attackMode == "dos") ? 1 : A;

    for (uint32_t a = 0; a < attackerLimit; a++)
    {
        Ptr<Socket> rawSocket =
            Socket::CreateSocket(params.attackers.Get(a),
                                 Ipv4RawSocketFactory::GetTypeId());

        rawSocket->SetAttribute("Protocol", UintegerValue(17)); // UDP

        // Randomly select victim to spoof
        uint32_t spoofedVictimId = rand() % V;
        
        // FIX: Correct offset for victim IP
        Ipv4Address spoofedIp = params.iface[0].GetAddress(params.numAttackers + spoofedVictimId);

        NS_LOG_UNCOND("[IP SPOOFING] Attacker " << a
            << " impersonating " << victimRegistry[spoofedVictimId].pcName
            << " (IP: " << spoofedIp << ")");

        attackerStats[a].attackType = params.attackType;
        attackerStats[a].targetIp = spoofedIp;

        for (uint32_t v = 0; v < V; v++)
        {
            Simulator::Schedule(
                Seconds(1.0 + a),
                [=]() {
                    Ptr<Packet> packet = Create<Packet>(512);

                    Ipv4Header ip;
                    ip.SetSource(spoofedIp);
                    // FIX: Correct offset
                    ip.SetDestination(params.iface[0].GetAddress(params.numAttackers + v));
                    ip.SetProtocol(17);
                    ip.SetPayloadSize(packet->GetSize());

                    UdpHeader udp;
                    udp.SetSourcePort(9999);
                    udp.SetDestinationPort(params.attackPort);

                    packet->AddHeader(udp);
                    packet->AddHeader(ip);

                    rawSocket->SendTo(packet, 0,
                                      InetSocketAddress(params.iface[0].GetAddress(params.numAttackers + v),
                                                        params.attackPort));

                    // Count packets sent
                    attackerStats[a].packetsSent++;
                });
        }
    }
}

/* ================= REPLAY ATTACK ================= */
void CapturePacket(Ptr<const Packet> packet, const Address &addr)
{
    capturedPackets.push_back(packet->Copy());
}

void SetupReplayAttack(const SimParams& params)
{
    uint32_t A = params.numAttackers;
    uint32_t V = params.numVictims;
    uint32_t attackerLimit = (params.attackMode == "dos") ? 1 : A;

    for (uint32_t v = 0; v < V; v++)
    {
        // FIX: Correct offset
        PacketSinkHelper sink("ns3::UdpSocketFactory",
                              InetSocketAddress(params.iface[0].GetAddress(params.numAttackers + v),
                                                params.attackPort));

        ApplicationContainer sinkApp = sink.Install(params.victims.Get(v));
        sinkApp.Start(Seconds(0.0));
        sinkApp.Stop(Seconds(12.0));

        Ptr<PacketSink> sinkPtr = DynamicCast<PacketSink>(sinkApp.Get(0));
        sinkPtr->TraceConnectWithoutContext("Rx", MakeCallback(&CapturePacket));
    }

    Simulator::Schedule(Seconds(6.0),
        [=]() {
            for (uint32_t a = 0; a < attackerLimit; a++)
            {
                Ptr<Socket> sock = Socket::CreateSocket(params.attackers.Get(a),
                                                        UdpSocketFactory::GetTypeId());

                for (auto pkt : capturedPackets)
                {
                    // FIX: Replay to first victim (offset fixed)
                    sock->SendTo(pkt->Copy(), 0,
                                 InetSocketAddress(params.iface[0].GetAddress(params.numAttackers),
                                                   params.attackPort));

                    attackerStats[a].packetsSent++;
                    
                    NS_LOG_UNCOND("[REPLAY] Attacker " << a << " replaying packet of size " << pkt->GetSize());
                }
            }
        });
}

/* ================= ATTACK SELECTOR ================= */
void SetupAttack(const SimParams& params)
{
    if (victimRegistry.empty())
    {
        for (uint32_t i = 0; i < params.numVictims; i++)
            victimRegistry.emplace_back(i);
    }

    if (params.attackType == "udp-flood")
        SetupOnOffFlood(params, "ns3::UdpSocketFactory");
    else if (params.attackType == "tcp-flood")
        SetupOnOffFlood(params, "ns3::TcpSocketFactory");
    else if (params.attackType == "icmp-flood")
        SetupOnOffFlood(params, "ns3::UdpSocketFactory");
    else if (params.attackType == "ip-spoofing")
        SetupIpSpoofingAttack(params);
    else if (params.attackType == "replay")
        SetupReplayAttack(params);
    else
        NS_ABORT_MSG("Unsupported attack type");
}

/* ================= LOGS ================= */
void SaveLogs(const SimParams& params)
{
    NS_LOG_UNCOND("\n================ ATTACK SUMMARY ================\n");

    NS_LOG_UNCOND("Attack Type  : " << params.attackType);
    NS_LOG_UNCOND("Attack Mode  : " << params.attackMode);
    NS_LOG_UNCOND("Attackers    : " << params.numAttackers);
    NS_LOG_UNCOND("Victims      : " << params.numVictims);
    NS_LOG_UNCOND("");

    for (uint32_t a = 0; a < params.numAttackers; ++a)
    {
        // Only log active attackers or those that attempted something
        if (params.attackMode == "dos" && a >= 1) continue;

        NS_LOG_UNCOND("Attacker " << a
            << " -> Target IP " << attackerStats[a].targetIp
            << " | Attack Type: " << attackerStats[a].attackType);

        NS_LOG_UNCOND("Packets Sent       : " << attackerStats[a].packetsSent);
        NS_LOG_UNCOND("Packets Received : " 
            << totalPacketsReceived[a % params.numVictims]);
        NS_LOG_UNCOND("-------------------------------------------");
    }

    NS_LOG_UNCOND("===============================================\n");
}

} // namespace ns3
