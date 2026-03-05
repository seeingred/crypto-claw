package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/seeingred/crypto-claw/internal/config"
	"github.com/seeingred/crypto-claw/internal/tss"
)

const (
	remoteConfigDir = "/etc/crypto-claw"
	containerNameA  = "crypto-claw-party-a"
	containerNameB  = "crypto-claw-party-b"
	dockerImage     = "ghcr.io/seeingred/crypto-claw"
)

// DeployParty deploys a single party to a remote server via SSH.
// The party parameter should be "a" or "b".
func DeployParty(client *ssh.Client, party string, cfg *config.Config, cert, key, caCert []byte, logFn func(string)) error {
	containerName := containerNameA
	if party == "b" {
		containerName = containerNameB
	}

	// Step 1: Install Docker if not present.
	logFn(fmt.Sprintf("[%s] Checking for Docker installation...", party))
	if err := ensureDocker(client, logFn, party); err != nil {
		return fmt.Errorf("ensure docker: %w", err)
	}

	// Step 2: Create config directory.
	logFn(fmt.Sprintf("[%s] Creating config directory %s...", party, remoteConfigDir))
	if _, _, err := SSHRunCommand(client, fmt.Sprintf("sudo mkdir -p %s && sudo chmod 700 %s", remoteConfigDir, remoteConfigDir)); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	// Step 3: Upload TLS certificates.
	logFn(fmt.Sprintf("[%s] Uploading TLS certificates...", party))
	certFiles := map[string][]byte{
		filepath.Join(remoteConfigDir, "cert.pem"): cert,
		filepath.Join(remoteConfigDir, "key.pem"):  key,
		filepath.Join(remoteConfigDir, "ca.pem"):   caCert,
	}
	for path, data := range certFiles {
		if err := SSHUploadFile(client, data, path); err != nil {
			return fmt.Errorf("upload %s: %w", path, err)
		}
	}

	// Step 4: Write config.json.
	logFn(fmt.Sprintf("[%s] Writing configuration...", party))
	cfgJSON, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	configPath := filepath.Join(remoteConfigDir, "config.json")
	if err := SSHUploadFile(client, cfgJSON, configPath); err != nil {
		return fmt.Errorf("upload config: %w", err)
	}

	// Step 5: Pull Docker image.
	logFn(fmt.Sprintf("[%s] Pulling Docker image...", party))
	imageTag := fmt.Sprintf("%s:party-%s-latest", dockerImage, party)
	stdout, stderr, err := SSHRunCommand(client, fmt.Sprintf("sudo docker pull %s 2>&1 || true", imageTag))
	if err != nil {
		slog.Warn("docker pull failed, will attempt build", "party", party, "stdout", stdout, "stderr", stderr)
		logFn(fmt.Sprintf("[%s] Docker pull failed, attempting build from source...", party))
		if buildErr := buildFromSource(client, party, logFn); buildErr != nil {
			return fmt.Errorf("build from source: %w", buildErr)
		}
		imageTag = fmt.Sprintf("crypto-claw-party-%s:latest", party)
	}

	// Step 6: Stop and remove existing container if present.
	logFn(fmt.Sprintf("[%s] Stopping any existing container...", party))
	SSHRunCommand(client, fmt.Sprintf("sudo docker stop %s 2>/dev/null; sudo docker rm %s 2>/dev/null", containerName, containerName))

	// Step 7: Create and start Docker container.
	logFn(fmt.Sprintf("[%s] Starting Docker container...", party))
	listenPort := "9000"
	if party == "a" {
		listenPort = "8080"
	}

	runCmd := fmt.Sprintf(
		"sudo docker run -d --name %s --restart unless-stopped "+
			"-v %s:%s:ro "+
			"-p %s:%s "+
			"%s "+
			"-config %s/config.json",
		containerName,
		remoteConfigDir, remoteConfigDir,
		listenPort, listenPort,
		imageTag,
		remoteConfigDir,
	)
	stdout, stderr, err = SSHRunCommand(client, runCmd)
	if err != nil {
		return fmt.Errorf("start container: %s %s: %w", stdout, stderr, err)
	}
	containerID := strings.TrimSpace(stdout)
	if len(containerID) > 12 {
		containerID = containerID[:12]
	}
	logFn(fmt.Sprintf("[%s] Container started: %s", party, containerID))

	// Step 8: Verify container is running.
	logFn(fmt.Sprintf("[%s] Verifying container health...", party))
	time.Sleep(2 * time.Second)
	stdout, _, err = SSHRunCommand(client, fmt.Sprintf("sudo docker inspect -f '{{.State.Running}}' %s", containerName))
	if err != nil || strings.TrimSpace(stdout) != "true" {
		// Get container logs for diagnostics.
		logs, _, _ := SSHRunCommand(client, fmt.Sprintf("sudo docker logs --tail 20 %s 2>&1", containerName))
		logFn(fmt.Sprintf("[%s] WARNING: Container may not be running. Logs: %s", party, logs))
		return fmt.Errorf("container not running after start")
	}

	logFn(fmt.Sprintf("[%s] Deployment complete.", party))
	return nil
}

// ensureDocker checks if Docker is installed and installs it if not.
func ensureDocker(client *ssh.Client, logFn func(string), party string) error {
	_, _, err := SSHRunCommand(client, "docker --version")
	if err == nil {
		logFn(fmt.Sprintf("[%s] Docker is already installed.", party))
		return nil
	}

	logFn(fmt.Sprintf("[%s] Docker not found, installing...", party))

	// Detect the OS and install Docker accordingly.
	osRelease, _, _ := SSHRunCommand(client, "cat /etc/os-release 2>/dev/null || cat /etc/redhat-release 2>/dev/null || echo unknown")

	var installCmd string
	switch {
	case strings.Contains(osRelease, "Ubuntu") || strings.Contains(osRelease, "Debian"):
		installCmd = `export DEBIAN_FRONTEND=noninteractive && ` +
			`sudo apt-get update -qq && ` +
			`sudo apt-get install -y -qq apt-transport-https ca-certificates curl software-properties-common && ` +
			`curl -fsSL https://get.docker.com | sudo sh`
	case strings.Contains(osRelease, "CentOS") || strings.Contains(osRelease, "Red Hat") || strings.Contains(osRelease, "Fedora"):
		installCmd = `sudo yum install -y yum-utils && ` +
			`sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo && ` +
			`sudo yum install -y docker-ce docker-ce-cli containerd.io && ` +
			`sudo systemctl start docker && sudo systemctl enable docker`
	default:
		// Fallback to the convenience script.
		installCmd = `curl -fsSL https://get.docker.com | sudo sh`
	}

	logFn(fmt.Sprintf("[%s] Running Docker installation (this may take a minute)...", party))
	stdout, stderr, err := SSHRunCommand(client, installCmd)
	if err != nil {
		return fmt.Errorf("install docker: stdout=%s stderr=%s: %w", stdout, stderr, err)
	}

	// Verify Docker is now available.
	_, _, err = SSHRunCommand(client, "sudo docker --version")
	if err != nil {
		return fmt.Errorf("docker not available after install: %w", err)
	}

	logFn(fmt.Sprintf("[%s] Docker installed successfully.", party))
	return nil
}

// buildFromSource clones the repo and builds the Docker image on the remote server.
func buildFromSource(client *ssh.Client, party string, logFn func(string)) error {
	logFn(fmt.Sprintf("[%s] Cloning source repository...", party))

	commands := []string{
		"sudo apt-get install -y -qq git 2>/dev/null || sudo yum install -y git 2>/dev/null || true",
		"rm -rf /tmp/crypto-claw-build",
		"git clone --depth 1 https://github.com/seeingred/crypto-claw.git /tmp/crypto-claw-build",
		fmt.Sprintf("cd /tmp/crypto-claw-build && sudo docker build -t crypto-claw-party-%s:latest -f docker/Dockerfile.party-%s .", party, party),
		"rm -rf /tmp/crypto-claw-build",
	}

	for _, cmd := range commands {
		logFn(fmt.Sprintf("[%s] %s", party, cmd))
		stdout, stderr, err := SSHRunCommand(client, cmd)
		if err != nil {
			return fmt.Errorf("command %q: stdout=%s stderr=%s: %w", cmd, stdout, stderr, err)
		}
	}

	return nil
}

// DeployLocal deploys both parties locally without SSH (for testing/development).
// It writes configs and certs to a temporary directory and starts processes.
func DeployLocal(state *WizardState, logFn func(string)) error {
	baseDir := filepath.Join(os.TempDir(), "crypto-claw-local")
	if err := os.MkdirAll(baseDir, 0700); err != nil {
		return fmt.Errorf("create base dir: %w", err)
	}

	for _, party := range []string{"a", "b"} {
		partyDir := filepath.Join(baseDir, "party-"+party)
		if err := os.MkdirAll(partyDir, 0700); err != nil {
			return fmt.Errorf("create party dir: %w", err)
		}

		logFn(fmt.Sprintf("[%s] Writing certificates to %s", party, partyDir))

		var cert, key []byte
		if party == "a" {
			cert = state.CertA
			key = state.KeyA
		} else {
			cert = state.CertB
			key = state.KeyB
		}

		files := map[string][]byte{
			"ca.pem":   state.CACert,
			"cert.pem": cert,
			"key.pem":  key,
		}
		for name, data := range files {
			if err := os.WriteFile(filepath.Join(partyDir, name), data, 0600); err != nil {
				return fmt.Errorf("write %s: %w", name, err)
			}
		}

		cfg := buildPartyConfig(state, party, partyDir)
		cfgJSON, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal config: %w", err)
		}
		cfgPath := filepath.Join(partyDir, "config.json")
		if err := os.WriteFile(cfgPath, cfgJSON, 0600); err != nil {
			return fmt.Errorf("write config: %w", err)
		}

		// Write key shares.
		logFn(fmt.Sprintf("[%s] Writing key shares...", party))
		if err := writeKeyShares(state, party, partyDir); err != nil {
			return fmt.Errorf("write key shares for party %s: %w", party, err)
		}

		logFn(fmt.Sprintf("[%s] Configuration written to %s", party, partyDir))
	}

	// In local mode, start processes directly.
	logFn("[local] Starting Party B...")
	partyBDir := filepath.Join(baseDir, "party-b")
	cmdB := exec.Command("go", "run", "./cmd/party-b", "-config", filepath.Join(partyBDir, "config.json"))
	cmdB.Dir = findProjectRoot()
	cmdB.Stdout = os.Stdout
	cmdB.Stderr = os.Stderr
	if err := cmdB.Start(); err != nil {
		logFn(fmt.Sprintf("[local] WARNING: Could not start Party B process: %v", err))
		logFn("[local] You can start it manually with: go run ./cmd/party-b -config " + filepath.Join(partyBDir, "config.json"))
	} else {
		logFn(fmt.Sprintf("[local] Party B started (PID %d)", cmdB.Process.Pid))
	}

	logFn("[local] Starting Party A...")
	partyADir := filepath.Join(baseDir, "party-a")
	cmdA := exec.Command("go", "run", "./cmd/party-a", "-config", filepath.Join(partyADir, "config.json"))
	cmdA.Dir = findProjectRoot()
	cmdA.Stdout = os.Stdout
	cmdA.Stderr = os.Stderr
	if err := cmdA.Start(); err != nil {
		logFn(fmt.Sprintf("[local] WARNING: Could not start Party A process: %v", err))
		logFn("[local] You can start it manually with: go run ./cmd/party-a -config " + filepath.Join(partyADir, "config.json"))
	} else {
		logFn(fmt.Sprintf("[local] Party A started (PID %d)", cmdA.Process.Pid))
	}

	logFn("[local] Local deployment complete.")
	logFn(fmt.Sprintf("[local] Config directory: %s", baseDir))
	return nil
}

// buildPartyConfig creates a config.Config for the given party.
func buildPartyConfig(state *WizardState, party string, certDir string) *config.Config {
	cfg := &config.Config{
		Party:   party,
		DataDir: certDir,
		Database: config.DatabaseConfig{
			Host:     "127.0.0.1",
			Port:     5432,
			User:     "crypto_claw",
			Password: "crypto_claw",
			DBName:   "crypto_claw_" + party,
			SSLMode:  "disable",
		},
		Transport: config.TransportConfig{
			CertFile:   filepath.Join(certDir, "cert.pem"),
			KeyFile:    filepath.Join(certDir, "key.pem"),
			CACertFile: filepath.Join(certDir, "ca.pem"),
		},
	}

	if party == "a" {
		partyAAddr := state.PartyAAddr
		if partyAAddr == "" {
			partyAAddr = "127.0.0.1:8080"
		}
		cfg.API = config.APIConfig{
			ListenAddr: partyAAddr,
		}
		// Party A connects to Party B.
		if state.LocalMode {
			cfg.Transport.RemoteAddr = "127.0.0.1:9000"
		} else {
			cfg.Transport.RemoteAddr = fmt.Sprintf("%s:9000", state.ServerB.Host)
		}
		cfg.Chains = config.ChainsConfig{
			EVM: []config.EVMChainConfig{
				{Name: "ethereum", ChainID: 1, RPCURL: "https://eth.llamarpc.com"},
			},
		}
	} else {
		// Party B listens for connections.
		cfg.Transport.ListenAddr = "0.0.0.0:9000"
		cfg.Analyzer = config.AnalyzerConfig{
			LLM: config.LLMConfig{
				Provider: state.LLMProvider,
				APIKey:   state.LLMAPIKey,
				Model:    state.LLMModel,
				Endpoint: state.LLMEndpoint,
			},
		}
		cfg.Telegram = config.TelegramConfig{
			BotToken:          state.TelegramBotToken,
			AuthorizedUserID:  state.TelegramUserID,
			EscalationTimeout: 5 * time.Minute,
		}
	}

	return cfg
}

// writeKeyShares serializes and writes key shares for a party to disk.
func writeKeyShares(state *WizardState, party string, dir string) error {
	var ecdsaShare, eddsaShare *tss.KeyShare
	if party == "a" {
		ecdsaShare = state.ShareA
		eddsaShare = state.EdShareA
	} else {
		ecdsaShare = state.ShareB
		eddsaShare = state.EdShareB
	}

	if ecdsaShare != nil {
		data, err := json.Marshal(ecdsaShare)
		if err != nil {
			return fmt.Errorf("marshal ECDSA share: %w", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "ecdsa_share.json"), data, 0600); err != nil {
			return fmt.Errorf("write ECDSA share: %w", err)
		}
	}

	if eddsaShare != nil {
		data, err := json.Marshal(eddsaShare)
		if err != nil {
			return fmt.Errorf("marshal EdDSA share: %w", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "eddsa_share.json"), data, 0600); err != nil {
			return fmt.Errorf("write EdDSA share: %w", err)
		}
	}

	return nil
}

// findProjectRoot walks up from the current working directory looking for go.mod.
func findProjectRoot() string {
	dir, err := os.Getwd()
	if err != nil {
		return "."
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "."
		}
		dir = parent
	}
}
