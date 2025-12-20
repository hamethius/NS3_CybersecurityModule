#include "ns3/ns3cybermod.h"
#include "ns3/csma-module.h"
#include "ns3/internet-module.h"
#include "ns3/core-module.h"
#include "ns3/on-off-helper.h" // Needed for background traffic

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("ScenarioReplay");

int main(int argc, char *argv[])
{
    SimParams params;
    params.numAttackers = 1;
    params.numVictims   = 2;
    params.attackPort   = 443;         
    params.attackType   = "replay";
    params.attackMode   = "dos";

    NS_LOG_UNCOND("--- SCENARIO: TRAFFIC REPLAY ---");
    NS_LOG_UNCOND("Phase 1 (1s-4s): Legitimate traffic is sent (and silently captured).");
    NS_LOG_UNCOND("Phase 2 (6s-10s): Attacker replays the captured traffic.");

    /* ================= SETUP NODES ================= */
    params.attackers.Create(params.numAttackers);
    params.victims.Create(params.numVictims);

    NodeContainer allNodes;
    allNodes.Add(params.attackers);
    allNodes.Add(params.victims);

    InternetStackHelper internet;
    internet.Install(allNodes);

    CsmaHelper csma;
    csma.SetChannelAttribute("DataRate", StringValue("100Mbps"));
    csma.SetChannelAttribute("Delay", StringValue("6560ns"));
    NetDeviceContainer devices = csma.Install(allNodes);

    Ipv4AddressHelper ip;
    ip.SetBase("192.168.50.0", "255.255.255.0");
    params.iface.push_back(ip.Assign(devices));

    /* ================= ADD BACKGROUND TRAFFIC ================= */
    // We need 'normal' traffic to capture. 
    // Let's say Attacker 0 acts as a 'normal client' initially.
    OnOffHelper backgroundTraffic("ns3::UdpSocketFactory", 
                                  InetSocketAddress(params.iface[0].GetAddress(params.numAttackers), // Target Victim 0
                                  params.attackPort));
    
    backgroundTraffic.SetConstantRate(DataRate("200kbps")); // Normal low rate traffic
    backgroundTraffic.SetAttribute("PacketSize", UintegerValue(1024));
    
    // Install on Attacker 0, run from 1s to 4s
    ApplicationContainer bgApp = backgroundTraffic.Install(params.attackers.Get(0));
    bgApp.Start(Seconds(1.0));
    bgApp.Stop(Seconds(4.0));

    /* ================= ACTIVATE REPLAY MODULE ================= */
    // This installs sinks on victims (to capture the background traffic)
    // AND schedules the replay attack for T=6.0s
    SetupAttack(params);

    Simulator::Stop(Seconds(10.0));
    Simulator::Run();
    
    SaveLogs(params);
    Simulator::Destroy();
    return 0;
}
