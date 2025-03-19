package main

import (
	"log"
	"runtime"
)

func main() {
	// Go detecteaza pe ce sistem de operare lucreaza si salveaza tipul in variabila GOOS din runtime, tip de date:char
	switch runtime.GOOS {
	case "linux":
		monitorizeazaLinux()
	case "windows":
		monitorizeazaWindows()
	default:
		log.Fatal("Sistemul de operare nu este suportat.")
	}
}

//    #####		Implementare SCRIPT pentru Linux 		######

func monitorizeazaLinux() {

}

//    #####		Implementare SCRIPT pentru Windows 		######

func monitorizeazaWindows() {

}
