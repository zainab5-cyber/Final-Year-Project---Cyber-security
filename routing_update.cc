#include "ns3/aodv-module.h"
#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/dsdv-module.h"
#include "ns3/dsr-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/network-module.h"
#include "ns3/olsr-module.h"
#include "ns3/yans-wifi-helper.h"

#include <fstream>
#include <iostream>
#include <map>
#include <cmath>
#include <algorithm>


using namespace ns3;
using namespace dsr;

NS_LOG_COMPONENT_DEFINE("MANET_DDoS_IDPS");

class RoutingExperiment
{
public:
  void Run();

private:
  Ptr<Socket> SetupPacketReceive(Ipv4Address addr, Ptr<Node> node);
  void ReceivePacket(Ptr<Socket> socket);
  void CheckThroughput();

  /* ===== Detection ===== */
  bool CountDetection(Ipv4Address sender);
  bool RateDetection(Ipv4Address sender);
  bool EntropyDetection(Ipv4Address sender);

  /* ===== Mitigation ===== */
  bool ApplyMitigation(Ipv4Address sender);
  void UpdateTrust(Ipv4Address sender, double delta);

  uint32_t port{9};
  uint32_t bytesTotal{0};
  uint32_t packetsReceived{0};

  /* ===== Detection State ===== */
  std::map<Ipv4Address, uint32_t> m_count;
  std::map<Ipv4Address, uint32_t> m_rate;
  std::map<Ipv4Address, Time> m_lastTime;

  std::map<Ipv4Address, uint32_t> m_entropyCount;
  Time m_entropyWindowStart{Seconds(0)};

  /* ===== Mitigation State ===== */
  std::map<Ipv4Address, double> m_trust;
  std::map<Ipv4Address, double> m_dropProb;
  std::map<Ipv4Address, Time> m_blacklist;

  Ptr<UniformRandomVariable> m_rng = CreateObject<UniformRandomVariable>();
};

/* ================= MITIGATION CORE ================= */

bool
RoutingExperiment::ApplyMitigation(Ipv4Address sender)
{
  Time now = Simulator::Now();

  /* Blacklist check */
  if (m_blacklist.count(sender) && now < m_blacklist[sender])
  {
    NS_LOG_UNCOND(now.GetSeconds()
                  << " [MITIGATION] Blacklisted packet dropped from "
                  << sender);
    return true;
  }

  /* Probabilistic drop */
  double prob = m_dropProb[sender];
  if (m_rng->GetValue() < prob)
  {
    NS_LOG_UNCOND(now.GetSeconds()
                  << " [MITIGATION] Rate-limited packet dropped from "
                  << sender);
    return true;
  }

  return false;
}

void
RoutingExperiment::UpdateTrust(Ipv4Address sender, double delta)
{
  if (!m_trust.count(sender))
    m_trust[sender] = 1.0;

  m_trust[sender] = std::clamp(m_trust[sender] + delta, 0.0, 1.0);

  if (m_trust[sender] >= 0.7)
    m_dropProb[sender] = 0.0;
  else if (m_trust[sender] >= 0.4)
    m_dropProb[sender] = 0.5;
  else
  {
    m_blacklist[sender] = Simulator::Now() + Seconds(20);
    m_dropProb[sender] = 1.0;
  }
}

/* ================= DETECTION ================= */

bool
RoutingExperiment::CountDetection(Ipv4Address sender)
{
  m_count[sender]++;
  if (m_count[sender] > 50)
  {
    UpdateTrust(sender, -0.2);
    m_count[sender] = 0;
    NS_LOG_UNCOND(Simulator::Now().GetSeconds()
                  << " [COUNT] Flood detected from " << sender);
    return true;
  }
  return false;
}

bool
RoutingExperiment::RateDetection(Ipv4Address sender)
{
  Time now = Simulator::Now();
  if (!m_lastTime.count(sender))
  {
    m_lastTime[sender] = now;
    m_rate[sender] = 1;
    return false;
  }

  if ((now - m_lastTime[sender]) <= Seconds(1))
    m_rate[sender]++;
  else
  {
    m_rate[sender] = 1;
    m_lastTime[sender] = now;
  }

  if (m_rate[sender] > 20)
  {
    UpdateTrust(sender, -0.3);
    m_rate[sender] = 0;
    NS_LOG_UNCOND(now.GetSeconds()
                  << " [RATE] Flood detected from " << sender);
    return true;
  }
  return false;
}

bool
RoutingExperiment::EntropyDetection(Ipv4Address sender)
{
  Time now = Simulator::Now();
  if (m_entropyWindowStart == Seconds(0))
    m_entropyWindowStart = now;

  m_entropyCount[sender]++;

  if ((now - m_entropyWindowStart) >= Seconds(2))
  {
    uint32_t total = 0;
    for (auto &p : m_entropyCount)
      total += p.second;

    double H = 0;
    for (auto &p : m_entropyCount)
    {
      double pr = (double)p.second / total;
      H -= pr * std::log2(pr);
    }

    m_entropyCount.clear();
    m_entropyWindowStart = now;

    if (H > 3.5)
    {
      UpdateTrust(sender, -0.4);
      NS_LOG_UNCOND(now.GetSeconds()
                    << " [ENTROPY] Distributed DDoS detected (H="
                    << H << ")");
      return true;
    }
  }
  return false;
}

/* ================= PACKET RECEIVE ================= */

void
RoutingExperiment::ReceivePacket(Ptr<Socket> socket)
{
  Ptr<Packet> packet;
  Address senderAddr;

  while ((packet = socket->RecvFrom(senderAddr)))
  {
    InetSocketAddress addr = InetSocketAddress::ConvertFrom(senderAddr);
    Ipv4Address sender = addr.GetIpv4();

    /* Apply mitigation BEFORE processing */
    if (ApplyMitigation(sender))
      continue;

    /* Detection */
    CountDetection(sender);
    RateDetection(sender);
    EntropyDetection(sender);

    /* Normal traffic recovery */
    UpdateTrust(sender, +0.01);

    bytesTotal += packet->GetSize();
    packetsReceived++;
  }
}

/* ================= REST (unchanged essentials) ================= */

Ptr<Socket>
RoutingExperiment::SetupPacketReceive(Ipv4Address addr, Ptr<Node> node)
{
  Ptr<Socket> sink =
      Socket::CreateSocket(node, UdpSocketFactory::GetTypeId());
  sink->Bind(InetSocketAddress(addr, port));
  sink->SetRecvCallback(MakeCallback(&RoutingExperiment::ReceivePacket, this));
  return sink;
}

void
RoutingExperiment::CheckThroughput()
{
  bytesTotal = 0;
  packetsReceived = 0;
  Simulator::Schedule(Seconds(1.0),
                      &RoutingExperiment::CheckThroughput, this);
}

void
RoutingExperiment::Run()
{
  NodeContainer nodes;
  nodes.Create(50);

WifiHelper wifi;
wifi.SetStandard(WIFI_STANDARD_80211b);

wifi.SetRemoteStationManager(
  "ns3::ConstantRateWifiManager",
  "DataMode", StringValue("DsssRate11Mbps"),
  "ControlMode", StringValue("DsssRate11Mbps")
);

/* Channel helper DOES use Default() */
YansWifiChannelHelper channel = YansWifiChannelHelper::Default();

/* PHY helper is constructed normally */
YansWifiPhyHelper phy;
phy.SetChannel(channel.Create());

WifiMacHelper mac;
mac.SetType("ns3::AdhocWifiMac");

NetDeviceContainer devs = wifi.Install(phy, mac, nodes);
 
MobilityHelper mobility;

/* Initial position for all nodes */
mobility.SetPositionAllocator(
  "ns3::GridPositionAllocator",
  "MinX", DoubleValue(0.0),
  "MinY", DoubleValue(0.0),
  "DeltaX", DoubleValue(10.0),
  "DeltaY", DoubleValue(10.0),
  "GridWidth", UintegerValue(10),
  "LayoutType", StringValue("RowFirst")
);

/* IMPORTANT: PositionAllocator attribute passed INSIDE the model */
mobility.SetMobilityModel(
  "ns3::RandomWaypointMobilityModel",
  "Speed", StringValue("ns3::UniformRandomVariable[Min=1.0|Max=20.0]"),
  "Pause", StringValue("ns3::ConstantRandomVariable[Constant=0.0]"),
  "PositionAllocator",
  PointerValue(
    CreateObjectWithAttributes<RandomRectanglePositionAllocator>(
      "X", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=500.0]"),
      "Y", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=500.0]")
    )
  )
);

mobility.Install(nodes);



  InternetStackHelper internet;
  AodvHelper aodv;
  internet.SetRoutingHelper(aodv);
  internet.Install(nodes);

  Ipv4AddressHelper addr;
  addr.SetBase("10.1.1.0", "255.255.255.0");
  auto interfaces = addr.Assign(devs);

  SetupPacketReceive(interfaces.GetAddress(0), nodes.Get(0));

  OnOffHelper onoff("ns3::UdpSocketFactory",
                    InetSocketAddress(interfaces.GetAddress(0), port));
  onoff.SetAttribute("DataRate", StringValue("2048bps"));
  onoff.SetAttribute("PacketSize", UintegerValue(64));

  for (uint32_t i = 1; i < nodes.GetN(); i++)
    onoff.Install(nodes.Get(i)).Start(Seconds(1));

  Simulator::Stop(Seconds(200));
  Simulator::Run();
  Simulator::Destroy();
}

int
main(int argc, char *argv[])
{
  CommandLine cmd;
  cmd.Parse(argc, argv);

  RoutingExperiment experiment;
  experiment.Run();

  return 0;
}
