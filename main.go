package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"strconv"
	"sync"
	"time"
)

var handle *pcap.Handle
var err error

type Packet struct {
	Destination string
	Source string
	SourcePort int
	DestPort int
	Size int
}

type Server struct {
	IP string
	PacketsIn []*Packet
	PacketsOut []*Packet
}

var serverMap = make(map[string]*Server)

func main() {
	pcapFile := flag.String("pcap", "test.pcap", "pcap file to profile")
	machine := flag.String("machine", "10.191.1.11", "machine to profile")
	flag.Parse()

	handle, err = pcap.OpenOffline(*pcapFile)
	if err != nil {
		log.Fatal(err)
	}

	var wg sync.WaitGroup
	packetChannel := make(chan *Packet, 10000)
	wg.Add(1)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	go SortPacketsToServers(packetChannel, &wg)
	for packet := range packetSource.Packets() {
		if packet.Layer(layers.LayerTypeTCP) != nil || packet.Layer(layers.LayerTypeUDP) != nil{
			packObj := new(Packet)
			packObj.Destination = packet.NetworkLayer().NetworkFlow().Dst().String()
			packObj.Source = packet.NetworkLayer().NetworkFlow().Src().String()
			if packet.Layer(layers.LayerTypeTCP) != nil {
				packObj.SourcePort, _ = strconv.Atoi(packet.Layer(layers.LayerTypeTCP).(*layers.TCP).SrcPort.String())
				packObj.DestPort, _ = strconv.Atoi(packet.Layer(layers.LayerTypeTCP).(*layers.TCP).DstPort.String())
				packObj.Size = len(packet.Layer(layers.LayerTypeTCP).(*layers.TCP).Contents)
			}
			packetChannel <- packObj
		}
	}
	wg.Wait()
	packetsIn := 0
	packetsInCount := 1
	for _, packet := range serverMap[*machine].PacketsIn {
		packetsIn += packet.Size
		packetsInCount += 1
	}
	fmt.Println("Packets In: ", packetsInCount)
	fmt.Println("Traffic In: ", packetsIn)
}

func SortPacketsToServers(inChannel chan *Packet, wg *sync.WaitGroup) {
	defer wg.Done()
	outerloop:
	for {
		select {
		case packet := <-inChannel:
			if _, ok := serverMap[packet.Source]; !ok {
				serverMap[packet.Source] = &Server{IP: packet.Source}
			}
			if _, ok := serverMap[packet.Destination]; !ok {
				serverMap[packet.Destination] = &Server{IP: packet.Destination}
			}
			serverMap[packet.Source].PacketsOut = append(serverMap[packet.Source].PacketsOut, packet)
			serverMap[packet.Destination].PacketsIn = append(serverMap[packet.Destination].PacketsIn, packet)
		case <- time.After(500 * time.Millisecond):
			fmt.Println("died")
			break outerloop
		}
	}
}