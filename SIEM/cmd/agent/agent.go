package main

import (
	"log"
	"runtime"

	"siem/pkg/monitor"
)

func main() {
	switch runtime.GOOS {
	case "linux":
		monitor.MonitorizeazaLinux()
	case "windows":
		monitor.MonitorizeazaWindows()
	default:
		log.Fatal("Sistemul de operare nu este suportat.")
	}
}
