package parser

import (
	"fmt"
	"strings"
)

type SyslogMessage struct {
	Timestamp string
	Hostname  string
	Program   string
	Message   string
}

func SyslogParsing(linie string) SyslogMessage {
	parts := strings.SplitN(linie, " ", 5)

	if len(parts) < 5 {
		fmt.Printf("Linie prea scruta pentru a fi parsata: %s", linie)
		return SyslogMessage{}
	}

	mesaj := SyslogMessage{
		Timestamp: parts[0] + " " + parts[1],
		Hostname:  parts[2],
		Program:   parts[3],
		Message:   parts[4],
	}

	return mesaj
}
