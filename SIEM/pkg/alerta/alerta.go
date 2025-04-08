package alerta

type Alerta struct {
	Sistem    string `json:"sistem"`
	Tip       string `json:"tip"`
	Descriere string `json:"descriere"`
	Timestamp string `json:"timestamp"`
}
