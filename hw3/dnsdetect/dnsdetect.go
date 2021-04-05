package main

import (
    "fmt"
    "flag"
    "strings"
    "github.com/google/gopacket/pcap"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket"
    "log"
    "time"
    "strconv"
)

type dnsPacketInfo struct {
    txId        uint16
    timestamp   time.Time
    qr          bool
    question    layers.DNSQuestion
    answerCount uint16
    answers     []layers.DNSResourceRecord
}

type dnsAttackTrackingInfo struct {
    queryCount      int
    dnsPacketInfos  []dnsPacketInfo
}

var (
    err error
    packetTracker   =  make(map[string]dnsAttackTrackingInfo)
    timeDelta int   = 5
)

func checkTrackingDelta(packetInfos []dnsPacketInfo, timestamp time.Time) (int, int) {
    var queryCount = 0
    var queryIdx = len(packetInfos)
    for i := len(packetInfos) - 1; i >= 0; i-- {
        if int(timestamp.Sub(packetInfos[i].timestamp).Seconds()) > timeDelta {
            return queryIdx, queryCount
        }
        if !packetInfos[i].qr {
            queryIdx = i
            queryCount = queryCount + 1
        }
    }
    return 0, queryCount
}

func printAttackAttempt(packetInfos []dnsPacketInfo) {
    fmt.Println(packetInfos[0].timestamp.Format(time.StampMicro), "DNS poisoning attempt")
    fmt.Println("TXID", packetInfos[0].txId, "Request", string(packetInfos[0].question.Name))
    var ansNum = 0
    for _, packetInfo := range packetInfos[1:] {
        if packetInfo.qr {
            ansNum = ansNum + 1
            fmt.Print("Answer ", ansNum)
            for j, answer := range packetInfo.answers {
                if answer.Type != layers.DNSTypeCNAME {
                    fmt.Print(" ", answer.Type.String())
                }
                fmt.Print(" ", answer.String())
                if j < len(packetInfo.answers) - 1 {
                    fmt.Print(",")
                }
            }
            fmt.Println()
        }
    }
    fmt.Println()
}

func handlePacket(packet gopacket.Packet) {

    ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
    if ipv4Layer == nil {
        log.Println("Error parsing IPv4 layer from packet")
        return
    }
    ip, _ := ipv4Layer.(*layers.IPv4)

    dnsLayer := packet.Layer(layers.LayerTypeDNS)
    if dnsLayer == nil {
        log.Println("Error parsing DNS layer from packet")
        return
    }
    dns, _ := dnsLayer.(*layers.DNS)

    pktInfo := dnsPacketInfo{
        txId: dns.ID,
        timestamp: packet.Metadata().Timestamp,
        qr: dns.QR,
        question: dns.Questions[0],
        answerCount: dns.ANCount,
        answers: dns.Answers,
    }

    // key should be <queried hostname>_<txid>_<client ip>_<dns server ip>
    var key = string(dns.Questions[0].Name) + "_" + strconv.FormatUint(uint64(dns.ID), 10)
    if dns.QR {     // This is a dns response
        key = key + "_" + ip.DstIP.String() + "_" + ip.SrcIP.String()

        trackingInfo, prs := packetTracker[key]
        if prs {    // Here, check for any attempt at attack
            idx, qc := checkTrackingDelta(trackingInfo.dnsPacketInfos, pktInfo.timestamp)
            trackingInfo.dnsPacketInfos = trackingInfo.dnsPacketInfos[idx:]
            trackingInfo.queryCount = qc

            // Check whether number of resp packets in the tracker map is less than number of query packets
            if len(trackingInfo.dnsPacketInfos) - trackingInfo.queryCount < trackingInfo.queryCount {
                // This is the no attack scenario
                trackingInfo.dnsPacketInfos = append(trackingInfo.dnsPacketInfos, pktInfo)
                packetTracker[key] = trackingInfo
            } else { // Now there is an extra packet for which we need to make sure whether its an attack attempt
                // Check if this is NOT a legit duplicate packet sent by a buggy dns server
                length := len(trackingInfo.dnsPacketInfos)
                if trackingInfo.dnsPacketInfos[length - 1].answerCount != pktInfo.answerCount ||
                    trackingInfo.dnsPacketInfos[length - 1].answers[0].String() != pktInfo.answers[0].String() {

                    printAttackAttempt(append(trackingInfo.dnsPacketInfos[length - 2:], pktInfo))
                }
                // Not adding the extra packet to the tracker map to maintain the equality of query and response packets
            }
        } // else: Ignore this packet as there was no entry for its query packet in the tracker map
    } else {        // This is a dns query
        key = key + "_" + ip.SrcIP.String() + "_" + ip.DstIP.String()

        trackingInfo, prs := packetTracker[key]
        if prs {
            // Stop tracking packets which exceed the timeDelta
            idx, qc := checkTrackingDelta(trackingInfo.dnsPacketInfos, pktInfo.timestamp)
            trackingInfo.dnsPacketInfos = append(trackingInfo.dnsPacketInfos[idx:], pktInfo)
            trackingInfo.queryCount = qc + 1
            // Add the new query packet in the tracker map
            packetTracker[key] = trackingInfo
        } else {    // Add new query packet entry in the tracker map
            var tempinfos []dnsPacketInfo
            tempinfos = append(tempinfos, pktInfo)
            var tempTrackingInfo = dnsAttackTrackingInfo{
                queryCount: 1,
                dnsPacketInfos: tempinfos,
            }
            packetTracker[key] = tempTrackingInfo
        }
    }

    // Check for errors
    if err := packet.ErrorLayer(); err != nil {
        log.Println("Error decoding some part of the packet:", err)
    }
}

func handlePacketSource(handle *pcap.Handle, bpfFilter string) {
    fmt.Println(" [", bpfFilter, "]")
    fmt.Println()

    err = handle.SetBPFFilter(bpfFilter)
    check(err)

    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packetSource.Packets() {
        handlePacket(packet)
    }
}

func listenFromInterface(intf string, bpfFilter string) {
    fmt.Print("dnsdetect: Listening on ", intf)

    if handle, err := pcap.OpenLive(intf, 65536, true, pcap.BlockForever); err != nil {
        log.Fatal(err)
    } else {
        defer handle.Close()
        handlePacketSource(handle, bpfFilter)
    }
}

func readFromFile(file string, bpfFilter string) {
    fmt.Print("dnsdetect: Reading from pcap file ", file)

    if handle, err := pcap.OpenOffline(file); err != nil {
        log.Fatal(err)
    } else {
        defer handle.Close()
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
    readFilePtr := flag.String("r", "", "path to the pcap file")

    flag.Parse()

    var bpfFilterStr string = "udp port 53"
    if bpfArgs := flag.Args(); len(bpfArgs) != 0 {
        bpfFilterStr = bpfFilterStr + " and " + strings.Join(bpfArgs, " ")
    }

    if *readFilePtr != "" {
        readFromFile(*readFilePtr, bpfFilterStr)
    } else if *intfPtr != "" {
        listenFromInterface(*intfPtr, bpfFilterStr)
    } else {
        fmt.Println("No inteface or file specified, will use the default network interface")
        devices, err := pcap.FindAllDevs()
        check(err)

        listenFromInterface(devices[0].Name, bpfFilterStr)
    }
}
