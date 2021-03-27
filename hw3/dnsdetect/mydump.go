package main

import (
    "fmt"
    "flag"
    "strings"
    "github.com/google/gopacket/pcap"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket"
    "log"
    "encoding/hex"
    "strconv"
    "time"
)

func handlePacket(packet gopacket.Packet, search string) {

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
}

func handlePacketSource(handle *pcap.Handle, search string, bpfFilter string) {
    var err = handle.SetBPFFilter(bpfFilter)
    if err != nil {
        log.Fatal(err)
    }
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packetSource.Packets() {
        handlePacket(packet, search)
    }
}

func readFromFile(file string, search string, bpfFilter string) {
    fmt.Println("Reading from pcap file ", file);
    if handle, err := pcap.OpenOffline(file); err != nil {
        log.Fatal(err)
    } else {
        handlePacketSource(handle, search, bpfFilter)
    }
}

func listenFromInterface(intf string, search string, bpfFilter string) {
    fmt.Println("Listening on interface ", intf)
    if handle, err := pcap.OpenLive(intf, 1600, true, pcap.BlockForever); err != nil {
        log.Fatal(err)
    } else {
        handlePacketSource(handle, search, bpfFilter)
    }
}

func main() {

    intfPtr := flag.String("i", "", "network device interface")
    readFilePtr := flag.String("r", "", "path to pcap file")
    searchStringPtr := flag.String("s", "", "filter packets having this string in payload")

    flag.Parse()

    var bpfFilterStr = strings.Join(flag.Args(), " ")

    if *readFilePtr != "" {
        readFromFile(*readFilePtr, *searchStringPtr, bpfFilterStr)
    } else if *intfPtr != "" {
        listenFromInterface(*intfPtr, *searchStringPtr, bpfFilterStr)
    } else {
        fmt.Println("No inteface or file specified, will use the default network interface")
        devices, err := pcap.FindAllDevs()
        if err!= nil {
            log.Fatal(err)
        }

        listenFromInterface(devices[0].Name, *searchStringPtr, bpfFilterStr)
    }
}
