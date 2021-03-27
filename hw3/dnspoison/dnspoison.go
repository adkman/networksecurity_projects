package main

import (
    "fmt"
    "flag"
    "io/ioutil"
    "strings"
    "net"
    "github.com/google/gopacket/pcap"
    //"github.com/google/gopacket/layers"
    "github.com/google/gopacket"
    "log"
    //"encoding/hex"
    //"strconv"
    //"time"
)

func handlePacket(packet gopacket.Packet) {
    /*
    var sb strings.Builder

    timestamp := packet.Metadata().Timestamp
    var srcMac string = ""
    var dstMac string = ""
    var etherType layers.EthernetType = layers.EthernetTypeIPv4
    var packetLength int = packet.Metadata().Length
    ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
    if ethernetLayer != nil {
        ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
        srcMac = ethernetPacket.SrcMAC.String()
        dstMac = ethernetPacket.DstMAC.String()
        etherType = ethernetPacket.EthernetType
    }
    sb.WriteString(strings.Join(strings.Split(timestamp.Format(time.RFC3339Nano), "T"), " "))
    sb.WriteString(" ")
    sb.WriteString(srcMac)
    sb.WriteString(" -> ")
    sb.WriteString(dstMac)
    sb.WriteString(" type ")
    tt := fmt.Sprintf("0x%x", uint16(etherType))
    sb.WriteString(tt)
    sb.WriteString(" len ")
    sb.WriteString(strconv.Itoa(packetLength))
    sb.WriteString("\n")

    var srcIp string = ""
    var dstIp string = ""
    var protocol layers.IPProtocol = layers.IPProtocolIPv4
    var protocolStr string = ""
    tcpFlags := make([]string, 9)
    if etherType == layers.EthernetTypeIPv4 {
        ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
        if ipv4Layer != nil {
            ip, _ := ipv4Layer.(*layers.IPv4)
            srcIp = ip.SrcIP.String()
            dstIp = ip.DstIP.String()
            protocol = ip.Protocol
            protocolStr = ip.Protocol.String()

            if protocol == layers.IPProtocolTCP {
                tcpLayer := packet.Layer(layers.LayerTypeTCP)
                if tcpLayer != nil {
                    tcp, _ := tcpLayer.(*layers.TCP)

                    srcIp = srcIp + ":" + tcp.SrcPort.String()
                    dstIp = dstIp + ":" + tcp.DstPort.String()
                    idx := 0
                    if tcp.FIN {
                        tcpFlags[idx] = "FIN"
                        idx = idx + 1
                    }
                    if tcp.SYN {
                        tcpFlags[idx] = "SYN"
                        idx = idx + 1
                    }
                    if tcp.RST {
                        tcpFlags[idx] = "RST"
                        idx = idx + 1
                    }
                    if tcp.PSH {
                        tcpFlags[idx] = "PSH"
                        idx = idx + 1
                    }
                    if tcp.ACK {
                        tcpFlags[idx] = "ACK"
                        idx = idx + 1
                    }
                    if tcp.URG {
                        tcpFlags[idx] = "URG"
                        idx = idx + 1
                    }
                    if tcp.ECE {
                        tcpFlags[idx] = "ECE"
                        idx = idx + 1
                    }
                    if tcp.CWR {
                        tcpFlags[idx] = "CWR"
                        idx = idx + 1
                    }
                    if tcp.NS {
                        tcpFlags[idx] = "NS"
                        idx = idx + 1
                    }
                    tcpFlags = tcpFlags[0: idx]
                }
            } else if protocol == layers.IPProtocolUDP {
                udpLayer := packet.Layer(layers.LayerTypeUDP)
                if udpLayer != nil {
                    udp, _ := udpLayer.(*layers.UDP)

                    srcIp = srcIp + ":" + udp.SrcPort.String()
                    dstIp = dstIp + ":" + udp.DstPort.String()
                }
            } else if protocol == layers.IPProtocolICMPv4 {
                // Do nothing
            } else {
                protocolStr = "OTHER"
            }

            sb.WriteString(srcIp)
            sb.WriteString(" -> ")
            sb.WriteString(dstIp)
            sb.WriteString(" ")
            sb.WriteString(protocolStr)
            sb.WriteString(" ")
            sb.WriteString(strings.Join(tcpFlags, "|"))
            sb.WriteString("\n")
        }
    }

    var payload []byte
    payloadLayer := packet.ApplicationLayer()
    if payloadLayer != nil {
        payload = payloadLayer.Payload()
        if search != "" && !strings.Contains(string(payload), search) {
            return
        }
    } else if search != "" {
        return
    }

    if payload != nil {
        sb.WriteString(hex.Dump(payload))
        sb.WriteString("\n")
    }

    fmt.Printf("%s", sb.String())

    // Check for errors
    if err := packet.ErrorLayer(); err != nil {
        fmt.Println("Error decoding some part of the packet:", err)
    }
    */
}

func handlePacketSource(handle *pcap.Handle, bpfFilter string) {
    var err = handle.SetBPFFilter(bpfFilter)
    check(err)
    /*
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packetSource.Packets() {
        handlePacket(packet)
    }
    */
}

func listenForDnsReq(intf string, hostnameMap map[string]net.IP, bpfFilter string) {
    fmt.Println("Listening on interface ", intf)

    if handle, err := pcap.OpenLive(intf, 1600, true, pcap.BlockForever); err != nil {
        log.Fatal(err)
    } else {
        handlePacketSource(handle, bpfFilter)
    }
}

func check(e error) {
    if e != nil {
        log.Fatal(e)
    }
}

func main() {

    intfPtr := flag.String("i", "", "network device interface")
    hostnameFile := flag.String("f", "", "hostnames file")

    flag.Parse()

    var bpfFilterStr string = "(udp and port 53)"
    if bpfArgs := flag.Args(); len(bpfArgs) != 0 {
        bpfFilterStr = bpfFilterStr + " and " + strings.Join(bpfArgs, " ")
    }

    networkIntfName := ""
    var networkIntfIP net.IP
    if *intfPtr != "" {
        networkIntfName = *intfPtr
        intf, err := net.InterfaceByName(*intfPtr)
        check(err)
        addrs, err := intf.Addrs()
        check(err)
        for _, addr := range addrs {
            if networkIntfIP = addr.(*net.IPNet).IP.To4(); networkIntfIP != nil {
                break
            }
        }
    } else {
        fmt.Println("No inteface or file specified, will use the default network interface")
        devices, err := pcap.FindAllDevs()
        check(err)

        networkIntfName = devices[0].Name
        networkIntfIP = devices[0].Addresses[0].IP
    }

    hostnameMap := make(map[string]net.IP)
    if *hostnameFile != "" {
        dat, err := ioutil.ReadFile(*hostnameFile)
        check(err)

        entries := strings.Split(string(dat), "\n")
        for i := 0; i < len(entries); i++ {
            entry := strings.Split(entries[i], " ")
            hostnameMap[entry[len(entry) - 1]] = net.ParseIP(entry[0])
        }
    } else {
        fmt.Println(networkIntfIP)
        hostnameMap["*"] = networkIntfIP
    }

    listenForDnsReq(networkIntfName, hostnameMap, bpfFilterStr)
}
