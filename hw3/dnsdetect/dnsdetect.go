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
)

type dnsPacketInfo struct {
    txId uint16
    timestamp time.Time
    qr bool
    packetLength int
    question layers.DNSQuestion
    answers []layers.DNSResourceRecord
}

var (
    err             error
    packetTracker  =  make(map[uint16][]dnsPacketInfo)
)

func printAttackAttempt(packetInfos []dnsPacketInfo) {
    fmt.Println(packetInfos[0].timestamp.Format("20210309 15:08:49.000000"), "DNS poisoning attempt")
    fmt.Println("TXID", packetInfos[0].txId, "Request", string(packetInfos[0].question.Name))
    for i, packetInfo := range packetInfos[1:] {
        fmt.Print("Answer ", i + 1)
        for _, answer := range packetInfo.answers {
            fmt.Print(" ", answer.String(), ",")
        }
        fmt.Println("")
    }
    fmt.Println()
}

func handlePacket(packet gopacket.Packet) {

    timestamp := packet.Metadata().Timestamp

    dnsLayer := packet.Layer(layers.LayerTypeDNS)
    if dnsLayer == nil {
        log.Println("Error parsing DNS layer from packet")
        return
    }
    dns, _ := dnsLayer.(*layers.DNS)

    pktInfo := dnsPacketInfo{
        txId: dns.ID,
        timestamp: timestamp,
        qr: dns.QR,
        packetLength: packet.Metadata().Length,
        question: dns.Questions[0],
        answers: dns.Answers,
    }
    if dns.QR {     // This is a dns response
        infos, prs := packetTracker[dns.ID]
        if prs {    // Here, check for any attempt at attack
            if len(infos) == 1 { // There was no prior dns response for this txid
                infos = append(infos, pktInfo)
                packetTracker[dns.ID] = infos
            } else {    // There was a response earlier for this txid. Need to check for attack attempt
                infos = append(infos, pktInfo)
                packetTracker[dns.ID] = infos

                if infos[1].packetLength != pktInfo.packetLength { // Currently just checking whether the second response has the same length or not
                    printAttackAttempt(infos)
                }
            }
        } else {    // Should not encounter this case as it means there initially no query for this txID
        }
    } else {        // This is a dns query
        _, prs := packetTracker[dns.ID]
        if prs {    // Need to check whether it received a response or not. If not then this might be a duplicated query. if not, need to remove the entry

        } else {    // Add entry in the tracker map
            var tempinfos []dnsPacketInfo
            tempinfos = append(tempinfos, pktInfo)
            packetTracker[dns.ID] = tempinfos
        }
    }

    // Check for errors
    if err := packet.ErrorLayer(); err != nil {
        log.Println("Error decoding some part of the packet:", err)
    }
}

func handlePacketSource(handle *pcap.Handle, bpfFilter string) {
    fmt.Println(" [", bpfFilter, "]")

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
    fmt.Print("Reading from pcap file", file)

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
