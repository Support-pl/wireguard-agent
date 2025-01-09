package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

type wgEasyClient struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	Address      string     `json:"address"`
	PrivateKey   string     `json:"privateKey"`
	PublicKey    string     `json:"publicKey"`
	PreSharedKey string     `json:"preSharedKey"`
	CreatedAt    *time.Time `json:"createdAt"`
	UpdatedAt    *time.Time `json:"updatedAt"`
	ExpiredAt    *time.Time `json:"expiredAt"`
	Enabled      bool       `json:"enabled"`
}

var (
	instanceToken string
	stateUrl      string
	configUrl     string
	wgHost        string
)

func init() {
	instanceToken = os.Getenv("ACCESS_TOKEN")
	stateUrl = os.Getenv("POST_STATE_URL")
	configUrl = os.Getenv("POST_CONFIG_DATA_URL")
	wgHost = os.Getenv("WG_HOST")
}

func main() {
	if instanceToken == "" || stateUrl == "" || configUrl == "" {
		log.Fatal("Cannot run without required envs. Got envs: ", instanceToken, stateUrl, configUrl)
	}

	restartChan := make(chan struct{})

	go func() {
	restart:
		cmd := exec.Command("/usr/bin/dumb-init", "node", "server.js")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		go func() {
			if err := cmd.Run(); err != nil {
				if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
					log.Fatal("Failed to run. Error: " + err.Error())
				}
			}
		}()
		<-restartChan
		if err := cmd.Process.Kill(); err != nil {
			log.Println("Failed to kill process. Error: " + err.Error())
		}
		time.Sleep(time.Duration(1) * time.Second)
		goto restart
	}()

	const configPath = "/etc/wireguard/wg0.json"
	retries := 0
retry:
	f, err := os.Open(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			retries++
			if retries > 10 {
				log.Fatal("Couldn't wait for wg0.json config to be created. Timed out")
			}
			time.Sleep(time.Duration(1) * time.Second)
			goto retry
		}

		log.Fatal("Failed to open config file. Error: " + err.Error())
	}
	_ = f.Close()
	contents, err := os.ReadFile(configPath)
	if err != nil {
		log.Fatal("Failed to read config file. Error: " + err.Error())
	}
	body := make(map[string]any)
	if err = json.Unmarshal(contents, &body); err != nil {
		log.Fatal("Failed to marshal config contents. Error: " + err.Error())
	}
	clients := make(map[string]any)
	if content, ok := body["clients"]; ok {
		clients = content.(map[string]any)
	}
	if len(clients) == 0 {
		log.Println("No client in config. Creating default client automatically")
		id := uuid.New().String()
		now := time.Now()
		private, err := exec.Command("wg", "genkey").Output()
		if err != nil {
			log.Fatal("Failed generate new key. Error: " + err.Error())
		}
		public, err := genPubKey(string(private))
		if err != nil {
			log.Fatal("Failed generate public key. Error: " + err.Error())
		}
		preshared, err := exec.Command("wg", "genpsk").Output()
		if err != nil {
			log.Fatal("Failed generate preshared key. Error: " + err.Error())
		}
		client := wgEasyClient{
			ID:           id,
			Name:         "default",
			Address:      "10.8.0.2",
			Enabled:      true,
			CreatedAt:    &now,
			UpdatedAt:    &now,
			PrivateKey:   strings.TrimRight(string(private), "\n"),
			PublicKey:    strings.TrimRight(public, "\n"),
			PreSharedKey: strings.TrimRight(string(preshared), "\n"),
		}
		clients[id] = client
		body["clients"] = clients
		newBody, err := json.Marshal(body)
		if err != nil {
			log.Fatal("Failed marshal new config. Error: " + err.Error())
		}
		if err = os.WriteFile(configPath, newBody, fs.ModeExclusive); err != nil {
			log.Fatal("Failed to write new config to file. Error: " + err.Error())
		}
		restartChan <- struct{}{}
		goto retry
	}
	log.Println("At least one client found. Proceeding...")

	if err = sendConfig(configPath); err != nil {
		log.Fatal("Failed to send monitoring back for the first time. Error: " + err.Error())
	}
	go sendMonitoring(configPath)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	log.Println("Got termination signal:", <-sig)
	conf, err := getConfig(configPath)
	if err != nil {
		log.Println("Failed to get config to cleanup. Error: " + err.Error())
	}
	data := RequestData{
		State: State{
			State: 3,
			Meta: Meta{
				Monitored:       0,
				WireguardConfig: conf,
			},
		},
	}
	if err = sendMonitoringRequest(data); err != nil {
		log.Println("Failed to send empty monitoring to cleanup. Error: " + err.Error())
	}
}

func genPubKey(private string) (string, error) {
	echoCmd := exec.Command("echo", private)
	wgPubkeyCmd := exec.Command("wg", "pubkey")

	wgPubkeyCmd.Stdin, _ = echoCmd.StdoutPipe()

	var output bytes.Buffer
	wgPubkeyCmd.Stdout = &output

	if err := echoCmd.Start(); err != nil {
		return "", fmt.Errorf("failed to start echo: %w", err)
	}

	if err := wgPubkeyCmd.Start(); err != nil {
		return "", fmt.Errorf("failed to start pubgen: %w", err)
	}

	if err := echoCmd.Wait(); err != nil {
		return "", fmt.Errorf("error waiting for echo: %w", err)
	}

	if err := wgPubkeyCmd.Wait(); err != nil {
		return "", fmt.Errorf("error waiting for pubgen: %w", err)
	}

	return output.String(), nil
}
