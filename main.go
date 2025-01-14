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
	wgPort        string

	restartChan       chan struct{}
	waitProcessChan   chan struct{}
	termChan          chan struct{}
	processFinishChan chan struct{}
)

func init() {
	instanceToken = os.Getenv("ACCESS_TOKEN")
	stateUrl = os.Getenv("POST_STATE_URL")
	configUrl = os.Getenv("POST_CONFIG_DATA_URL")
	wgHost = os.Getenv("WG_HOST")
	wgPort = "51820"
}

func fatal(v ...any) {
	termChan <- struct{}{}
	<-processFinishChan
	log.Fatal(v...)
}

func main() {
	if instanceToken == "" || stateUrl == "" || configUrl == "" {
		log.Fatal("Cannot run without required envs. Got envs: ", instanceToken, stateUrl, configUrl)
	}

	restartChan = make(chan struct{})
	waitProcessChan = make(chan struct{})
	termChan = make(chan struct{})
	processFinishChan = make(chan struct{})

	go func() {
	restart:
		cmd := exec.Command("/usr/bin/dumb-init", "node", "server.js")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Start(); err != nil {
			log.Fatal("Failed to start run. Error: " + err.Error())
		}

		go func() {
			if err := cmd.Wait(); err != nil {
				if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
					log.Fatal("Run completed by itself but shouldn't had. Error: " + err.Error())
				}
			}
			log.Println("Run finished due to signal restart or termination")
			waitProcessChan <- struct{}{}
		}()
		select {
		case <-termChan:
			log.Println("Termination called")
			if err := cmd.Process.Kill(); err != nil {
				log.Println("Failed to kill process. Error: " + err.Error())
			}
			<-waitProcessChan
			processFinishChan <- struct{}{}
			return
		case <-restartChan:
			log.Println("Restart called")
		}
		if err := cmd.Process.Kill(); err != nil {
			log.Println("Failed to kill process. Error: " + err.Error())
		}
		<-waitProcessChan
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
			if retries > 15 {
				fatal("Couldn't wait for wg0.json config to be created. Timed out")
			}
			time.Sleep(time.Duration(1) * time.Second)
			goto retry
		}
		fatal("Failed to open config file. Error: " + err.Error())
	}
	_ = f.Close()

	created, err := ensureClient(configPath)
	if err != nil {
		fatal(err)
	}
	if created {
		restartChan <- struct{}{}
		goto retry
	}

	if err = sendConfig(configPath); err != nil {
		fatal("Failed to send monitoring back for the first time. Error: " + err.Error())
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
	termChan <- struct{}{}
	<-processFinishChan
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

func ensureClient(configPath string) (bool, error) {
	changed := false

	contents, err := os.ReadFile(configPath)
	if err != nil {
		return false, fmt.Errorf("failed to read config file: %w", err)
	}
	body := make(map[string]any)
	if err = json.Unmarshal(contents, &body); err != nil {
		return false, fmt.Errorf("failed to marshal config contents: %w", err)
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
			return false, fmt.Errorf("failed generate new key: %w", err)
		}
		public, err := genPubKey(string(private))
		if err != nil {
			return false, fmt.Errorf("failed to generate public key: %w", err)
		}
		preshared, err := exec.Command("wg", "genpsk").Output()
		if err != nil {
			return false, fmt.Errorf("failed to generate preshared key: %w", err)
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
			return false, fmt.Errorf("failed to marshal new config: %w", err)
		}
		if err = os.WriteFile(configPath, newBody, fs.ModeExclusive); err != nil {
			return false, fmt.Errorf("failed to write new config to file: %w", err)
		}
		changed = true
	}
	log.Println("At least one client found. Proceeding...")
	return changed, nil
}
