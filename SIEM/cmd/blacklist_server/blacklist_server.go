
package main

import (
    "fmt"
    "net/http"
    "os"
)

func main() {
    http.HandleFunc("/blacklist.txt", func(w http.ResponseWriter, r *http.Request) {
        data, err := os.ReadFile("blacklist.txt")
        if err != nil {
            http.Error(w, "Eroare la citirea fișierului", http.StatusInternalServerError)
            return
        }
        w.Header().Set("Content-Type", "text/plain")
        w.Write(data)
    })

    fmt.Println("Serverul de blacklist rulează pe http://localhost:8080/blacklist.txt")
    http.ListenAndServe(":8080", nil)
}
