package main

import (
	"fmt"
	"time"

	"claudetoapi/internal/tlsfp"
	"net/http"
)

func main() {
	tr := tlsfp.Transport("")
	client := &http.Client{Transport: tr, Timeout: 15 * time.Second}
	req, _ := http.NewRequest("GET", "https://api.anthropic.com/", nil)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("HANDSHAKE/TLS TEST FAILED:", err)
		return
	}
	defer resp.Body.Close()
	fmt.Println("TLS OK, status:", resp.Status)
}
