package parser

import (
	"fmt"
	"strings"
)

type SyslogMessage struct {
	Prival    string
	Timestamp string
	Hostname  string
	Program   string
	Message   string
}

func SyslogParsing(linie string) SyslogMessage {
	prival := ""

	// Dacă linia începe cu < și are un > în primele 6 caractere, extragem <PRI>
	if strings.HasPrefix(linie, "<") {
		index := strings.Index(linie, ">")
		if index != -1 && index < 6 {
			prival = linie[1:index]                    // extragem valoarea fără < >
			linie = strings.TrimSpace(linie[index+1:]) // eliminăm <PRI> din linie
		}
	}
	fmt.Println(linie)
	// Split în maxim 5 părți
	parts := strings.SplitN(linie, " ", 6)

	if len(parts) < 5 {
		fmt.Printf("Linie prea scurtă pentru a fi parsată: %s\n", linie)
		return SyslogMessage{}
	}

	mesaj := SyslogMessage{
		Prival:    prival,
		Timestamp: parts[0] + " " + parts[1] + " " + parts[2],
		Hostname:  parts[3],
		Program:   strings.TrimSuffix(parts[4], ":"), // curățăm `:`
		Message:   parts[5],
	}

	return mesaj
}
