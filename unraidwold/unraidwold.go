// Copyright (c) 2021, Scott Ellis
// All rights reserved.
// Copyright (c) 2023 Limetech, Simon Fairweather.
//
// Unraid Wake-on-LAN(V1.0.0)
//
// Listens for a WOL magic packet (UDP) and ether frame type 0x0842
// If a matching VM/Docker or LXC is found, it is started (if not already running) and resumed if paused
//
// Filters on ether proto 0x0842 or udp port 9

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"log/syslog"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var logger *log.Logger

func main() {
	var logOutput io.Writer
	var (
		appVersion    bool
		interfaceName string
		logFile       string
		promiscuous   bool
	)

	flag.BoolVar(&appVersion, "version", false, "Print the version and copyright information")
	flag.StringVar(&interfaceName, "interface", "", "Network interface name(s) (required; comma or whitespace separated)")
	flag.StringVar(&logFile, "log", "", "Log file path")
	flag.BoolVar(&promiscuous, "promiscuous", false, "Enable promiscuous mode")

	flag.Parse()

	versionInfo := "Unraid Wake-on-LAN (V1.0.0)\nCopyright (c) 2021, Scott Ellis\nAll rights reserved.\nCopyright (c) 2023 Limetech, Simon Fairweather.\n"

	if appVersion {
		fmt.Println(versionInfo)
		return
	}

	interfaces, err := parseInterfaces(interfaceName)
	if err != nil {
		fmt.Println("Error:", err)
		flag.PrintDefaults()
		os.Exit(1)
	}

	if !deviceExists(interfaces) {
		fmt.Println("Error: one or more interfaces are not valid")
		flag.PrintDefaults()
		os.Exit(1)
	}

	logger = log.New(os.Stderr, "", log.LstdFlags)
	if logFile != "" {
		file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			logger.Fatal(err)
		}
		defer file.Close()
		logOutput = io.MultiWriter(file, os.Stdout)
	} else {
		syslogWriter, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "Unraidwold")
		if err != nil {
			logger.Fatal(err)
		}
		logOutput = syslogWriter
	}

	logger = log.New(logOutput, "", log.LstdFlags)

	pidFile := "/var/run/unraidwold.pid"
	if err := writePIDFile(pidFile); err != nil {
		logger.Fatal(err)
	}

	logger.Printf("Processing WOL Requests on interfaces: %s", strings.Join(interfaces, ", "))
	if promiscuous {
		logger.Println("Promiscuous mode is enabled")
	}

	handles, err := openInterfaces(interfaces, promiscuous)
	if err != nil {
		logger.Fatal(err)
	}
	defer func() {
		for _, handle := range handles {
			handle.Close()
		}
	}()

	signalChan := make(chan os.Signal, 1)
	doneChan := make(chan bool, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	packetChan := make(chan gopacket.Packet, 100)
	for _, handle := range handles {
		go streamPackets(handle, packetChan)
	}

	go processPackets(packetChan, signalChan, doneChan)

	<-doneChan
	removePIDFile(pidFile)
	logger.Println("Stopping WOL Daemon.")
}

func writePIDFile(pidFile string) error {
	pid := os.Getpid()
	pidStr := fmt.Sprintf("%d\n", pid)
	return ioutil.WriteFile(pidFile, []byte(pidStr), 0644)
}

func removePIDFile(pidFile string) {
	err := os.Remove(pidFile)
	if err != nil {
		logger.Printf("Error removing PID file: %v\n", err)
	}
}

func openInterfaces(interfacenames []string, promiscuous bool) ([]*pcap.Handle, error) {
	var handles []*pcap.Handle
	for _, name := range interfacenames {
		handle, err := pcap.OpenLive(name, 1600, promiscuous, pcap.BlockForever)
		if err != nil {
			for _, openHandle := range handles {
				openHandle.Close()
			}
			return nil, fmt.Errorf("opening interface %s: %w", name, err)
		}
		if err := handle.SetBPFFilter("ether proto 0x0842 or udp port 9"); err != nil {
			for _, openHandle := range handles {
				openHandle.Close()
			}
			return nil, fmt.Errorf("setting BPF filter for %s: %w", name, err)
		}
		handles = append(handles, handle)
	}
	return handles, nil
}

func streamPackets(handle *pcap.Handle, packetChan chan<- gopacket.Packet) {
	source := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range source.Packets() {
		packetChan <- packet
	}
}

func processPackets(packetChan <-chan gopacket.Packet, signalChan chan os.Signal, doneChan chan bool) {
	var mac string
	for {
		select {
		case packet, ok := <-packetChan:
			if !ok {
				doneChan <- true
				return
			}
			ethLayer := packet.Layer(layers.LayerTypeEthernet)
			udpLayer := packet.Layer(layers.LayerTypeUDP)

			if ethLayer != nil {
				ethernetPacket, _ := ethLayer.(*layers.Ethernet)
				if ethernetPacket.EthernetType == 0x0842 {
					payload := ethernetPacket.Payload
					mac = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", payload[6], payload[7], payload[8], payload[9], payload[10], payload[11])
				}
			}

			if udpLayer != nil {
				udpPacket, _ := udpLayer.(*layers.UDP)
				if udpPacket.DstPort == layers.UDPPort(9) {
					appPacket := packet.ApplicationLayer()
					if appPacket != nil {
						payload := appPacket.Payload()
						mac = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", payload[12], payload[13], payload[14], payload[15], payload[16], payload[17])
					}
				}
			}

			go runcmd(mac)

		case sig := <-signalChan:
			fmt.Printf("Received signal: %v\n", sig)
			doneChan <- true
			return
		}
	}
}

func runcmd(mac string) bool {
	app := "/usr/local/emhttp/plugins/WOL4Services/include/WOLrun.php"
	arg := mac
	cmd := exec.Command(app, arg)
	stdout, err := cmd.Output()
	if err != nil {
		fmt.Println(err.Error())
		return false
	}
	logger.Println(string(stdout))
	return true
}

// Return the first MAC address seen in the UDP WOL packet
func GrabMACAddrUDP(packet gopacket.Packet) (string, error) {
	app := packet.ApplicationLayer()
	if app != nil {
		payload := app.Payload()
		mac := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", payload[12], payload[13], payload[14], payload[15], payload[16], payload[17])
		return mac, nil
	}
	return "", errors.New("no MAC found in packet")
}

func parseInterfaces(input string) ([]string, error) {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return nil, errors.New("no interface names provided")
	}

	parts := strings.FieldsFunc(trimmed, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})

	interfaces := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			interfaces = append(interfaces, part)
		}
	}
	if len(interfaces) == 0 {
		return nil, errors.New("no interface names provided")
	}
	return interfaces, nil
}

// Check if the network devices exist
func deviceExists(interfacenames []string) bool {
	if len(interfacenames) == 0 {
		fmt.Printf("No valid interface to listen on specified\n\n")
		return false
	}

	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Panic(err)
	}

	availableInterfaces := make(map[string]struct{}, len(devices))
	for _, device := range devices {
		availableInterfaces[device.Name] = struct{}{}
	}

	for _, name := range interfacenames {
		if _, ok := availableInterfaces[name]; !ok {
			fmt.Printf("Interface not found: %s\n", name)
			return false
		}
	}
	return true
}
