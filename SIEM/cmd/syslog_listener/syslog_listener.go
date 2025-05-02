package main

import (
	"fmt"
	"net"

	"siem/pkg/parser"
	"siem/pkg/storage"
)

func main() {

	addr := net.UDPAddr{
		Port: 514,
		IP:   net.ParseIP("0.0.0.0"),
	}

	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		fmt.Printf("Eroare la ascultare %v: %s \n", addr, err)
	}
	defer conn.Close()

	buffer := make([]byte, 4096)
	n, _, err := conn.ReadFromUDP(buffer)
	if err != nil {
		fmt.Printf("Ai o problema la citirea datelor din jurnal: %s", err)
	}

	mesaj := string(buffer[:n])
	syslog := parser.SyslogParsing(mesaj)
	storage.SalveazaSyslog(syslog)
	fmt.Printf("Acesta este jurnalul: %v", syslog)
}
