package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type Meta struct {
	Monitored       int64  `json:"monitored"`
	WireguardConfig string `json:"wireguard_config"`
}

type State struct {
	State int  `json:"state"`
	Meta  Meta `json:"meta"`
}

type RequestData struct {
	State State `json:"state"`
}

func getConfig(path string) (string, error) {
	wgConfig, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read wireguard config: %w", err)
	}

	body := make(map[string]any)
	if err := json.Unmarshal(wgConfig, &body); err != nil {
		return "", err
	}

	clients, ok := body["clients"].(map[string]any)
	if !ok || len(clients) == 0 {
		return "", fmt.Errorf("no clients")
	}
	server, ok := body["server"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("no server")
	}

	var client map[string]any
	for key := range clients {
		client = clients[key].(map[string]any)
		break
	}

	wgPortNum, err := strconv.Atoi(wgPort)
	if err != nil {
		return "", fmt.Errorf("invalid port")
	}
	clientConfig := WireGuardConfig{
		ClientPrivateKey: client["privateKey"].(string),
		ClientAddress:    client["address"].(string),
		ClientListenPort: wgPortNum,
		ClientDNS:        "1.1.1.1",

		ServerPublicKey:    server["publicKey"].(string),
		ServerPresharedKey: client["preSharedKey"].(string),
		ServerAllowedIPs:   []string{"0.0.0.0/0"},
		ServerEndpoint:     wgHost + ":" + wgPort,
	}

	return clientConfig.CreateConfig(), nil
}

func sendConfig(path string) error {
	now := time.Now().UTC().Unix()

	configString, err := getConfig(path)
	if err != nil {
		return err
	}

	data := RequestData{
		State: State{
			State: 3,
			Meta: Meta{
				Monitored:       now,
				WireguardConfig: configString,
			},
		},
	}

	return sendMonitoringRequest(data)
}

func sendMonitoring(path string) {
	for {
		created, err := ensureClient(path)
		if err != nil {
			log.Println("Error ensuring client from monitoring. Error: " + err.Error())
			continue
		}
		if created {
			restartChan <- struct{}{}
		}
		if err := sendConfig(path); err != nil {
			log.Println("Error sending monitoring data:", err)
		}
		time.Sleep(157 * time.Second)
	}
}

func sendMonitoringRequest(data RequestData) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	req, err := http.NewRequest("POST", "https://"+stateUrl, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+instanceToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("send config back error. Server returned: %s", string(body))
	}

	return nil
}

type WireGuardConfig struct {
	ClientPrivateKey string
	ClientAddress    string
	ClientListenPort int
	ClientDNS        string

	ServerPublicKey    string
	ServerPresharedKey string
	ServerAllowedIPs   []string
	ServerEndpoint     string
}

func (wgConfig WireGuardConfig) CreateConfig() string {
	allowedIPs := strings.Join(wgConfig.ServerAllowedIPs, ",")

	return fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s
ListenPort = %d
DNS = %s

[Peer]
PublicKey = %s
PresharedKey = %s
AllowedIPs = %s
Endpoint = %s
`,
		wgConfig.ClientPrivateKey,
		wgConfig.ClientAddress,
		wgConfig.ClientListenPort,
		wgConfig.ClientDNS,
		wgConfig.ServerPublicKey,
		wgConfig.ServerPresharedKey,
		allowedIPs,
		wgConfig.ServerEndpoint,
	)
}
