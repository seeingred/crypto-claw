package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/seeingred/crypto-claw/internal/config"
	"github.com/seeingred/crypto-claw/internal/store"
	"github.com/seeingred/crypto-claw/internal/tss"
)

const (
	remoteConfigDir = "/etc/crypto-claw"
	containerNameA  = "crypto-claw-party-a"
	containerNameB  = "crypto-claw-party-b"
	containerNamePG = "crypto-claw-postgres"
	dockerImage     = "ghcr.io/seeingred/crypto-claw"
)

// remoteOS detects the operating system on a remote SSH host.
// Returns "darwin" for macOS, "linux" for Linux.
func remoteOS(client *ssh.Client) string {
	out, _, _ := SSHRunCommand(client, "uname -s")
	if strings.TrimSpace(strings.ToLower(out)) == "darwin" {
		return "darwin"
	}
	return "linux"
}

// remoteConfigPath returns the config directory for the given OS.
// macOS: ~/.crypto-claw (no sudo needed), Linux: /etc/crypto-claw.
func remoteConfigPath(osType string, client *ssh.Client) string {
	if osType == "darwin" {
		home, _, _ := SSHRunCommand(client, "echo $HOME")
		return filepath.Join(strings.TrimSpace(home), ".crypto-claw")
	}
	return remoteConfigDir
}

// sudoPrefix returns "sudo " on Linux and "" on macOS (Docker Desktop runs as user).
func sudoPrefix(osType string) string {
	if osType == "darwin" {
		return ""
	}
	return "sudo "
}

// sshRunWithPath runs a command via SSH with an extended PATH on macOS.
// On macOS, SSH sessions get a minimal PATH that doesn't include /usr/local/bin
// or /opt/homebrew/bin where Docker and Homebrew tools live.
func sshRunWithPath(client *ssh.Client, osType string, cmd string) (string, string, error) {
	if osType == "darwin" {
		cmd = `export PATH="/usr/local/bin:/opt/homebrew/bin:$PATH"; ` + cmd
	}
	return SSHRunCommand(client, cmd)
}

// DeployParty deploys a single party to a remote server via SSH.
// The party parameter should be "a" or "b".
func DeployParty(client *ssh.Client, party string, cfg *config.Config, cert, key, caCert []byte, logFn func(string)) error {
	containerName := containerNameA
	if party == "b" {
		containerName = containerNameB
	}

	// Detect remote OS.
	osType := remoteOS(client)
	sudo := sudoPrefix(osType)
	cfgDir := remoteConfigPath(osType, client)
	logFn(fmt.Sprintf("[%s] Detected remote OS: %s", party, osType))

	// Step 1: Install Docker if not present.
	logFn(fmt.Sprintf("[%s] Checking for Docker installation...", party))
	if err := ensureDocker(client, logFn, party, osType); err != nil {
		return fmt.Errorf("ensure docker: %w", err)
	}

	// Step 1.5: Ensure PostgreSQL is running on the remote server.
	logFn(fmt.Sprintf("[%s] Setting up PostgreSQL...", party))
	if err := ensureRemotePostgres(client, party, sudo, osType, logFn); err != nil {
		return fmt.Errorf("ensure postgres: %w", err)
	}

	// Step 2: Create config directory.
	logFn(fmt.Sprintf("[%s] Creating config directory %s...", party, cfgDir))
	mkdirCmd := fmt.Sprintf("%smkdir -p %s && %schmod 700 %s", sudo, cfgDir, sudo, cfgDir)
	if osType == "darwin" {
		mkdirCmd = fmt.Sprintf("mkdir -p %s && chmod 700 %s", cfgDir, cfgDir)
	}
	if _, _, err := SSHRunCommand(client, mkdirCmd); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	// Step 3: Upload TLS certificates.
	logFn(fmt.Sprintf("[%s] Uploading TLS certificates...", party))
	certFiles := map[string][]byte{
		filepath.Join(cfgDir, "cert.pem"): cert,
		filepath.Join(cfgDir, "key.pem"):  key,
		filepath.Join(cfgDir, "ca.pem"):   caCert,
	}
	for path, data := range certFiles {
		if err := SSHUploadFile(client, data, path); err != nil {
			return fmt.Errorf("upload %s: %w", path, err)
		}
	}

	// Step 4: Write config.json — update paths to match remote config dir.
	logFn(fmt.Sprintf("[%s] Writing configuration...", party))
	cfg.DataDir = cfgDir
	cfg.Transport.CertFile = filepath.Join(cfgDir, "cert.pem")
	cfg.Transport.KeyFile = filepath.Join(cfgDir, "key.pem")
	cfg.Transport.CACertFile = filepath.Join(cfgDir, "ca.pem")
	// macOS Docker: container can't reach host at 127.0.0.1, use host.docker.internal.
	// Linux: --network host means 127.0.0.1 works fine.
	if osType == "darwin" && cfg.Database.Host == "127.0.0.1" {
		cfg.Database.Host = "host.docker.internal"
	}
	cfgJSON, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	configPath := filepath.Join(cfgDir, "config.json")
	if err := SSHUploadFile(client, cfgJSON, configPath); err != nil {
		return fmt.Errorf("upload config: %w", err)
	}

	// Step 5: Pull Docker image, fall back to building from source.
	logFn(fmt.Sprintf("[%s] Pulling Docker image...", party))
	imageTag := fmt.Sprintf("%s:party-%s-latest", dockerImage, party)
	stdout, stderr, err := sshRunWithPath(client, osType, fmt.Sprintf("%sdocker pull %s 2>&1", sudo, imageTag))
	if err != nil || strings.Contains(stdout, "denied") || strings.Contains(stdout, "not found") {
		slog.Warn("docker pull failed, will attempt build", "party", party, "stdout", stdout, "stderr", stderr)
		logFn(fmt.Sprintf("[%s] Docker pull failed, building from source...", party))
		if buildErr := buildFromSource(client, party, logFn, osType); buildErr != nil {
			return fmt.Errorf("build from source: %w", buildErr)
		}
		imageTag = fmt.Sprintf("crypto-claw-party-%s:latest", party)
	}

	// Step 6: Stop and remove existing container if present.
	logFn(fmt.Sprintf("[%s] Stopping any existing container...", party))
	sshRunWithPath(client, osType, fmt.Sprintf("%sdocker stop %s 2>/dev/null; %sdocker rm %s 2>/dev/null", sudo, containerName, sudo, containerName))

	// Step 7: Create and start Docker container.
	logFn(fmt.Sprintf("[%s] Starting Docker container...", party))
	listenPort := "8080"
	if party == "b" {
		// Extract port from transport listen addr (e.g. "0.0.0.0:443" -> "443").
		if _, p, err := net.SplitHostPort(cfg.Transport.ListenAddr); err == nil {
			listenPort = p
		} else {
			listenPort = "443"
		}
	}

	var runCmd string
	if osType == "linux" {
		// Linux: use --network host so container can reach host Postgres at 127.0.0.1.
		runCmd = fmt.Sprintf(
			"%sdocker run -d --name %s --restart unless-stopped "+
				"--network host "+
				"-v %s:%s:ro "+
				"%s "+
				"-config %s/config.json",
			sudo,
			containerName,
			cfgDir, cfgDir,
			imageTag,
			cfgDir,
		)
	} else {
		// macOS: use host.docker.internal to reach host Postgres.
		runCmd = fmt.Sprintf(
			"docker run -d --name %s --restart unless-stopped "+
				"-v %s:%s:ro "+
				"-p %s:%s "+
				"--add-host=host.docker.internal:host-gateway "+
				"%s "+
				"-config %s/config.json",
			containerName,
			cfgDir, cfgDir,
			listenPort, listenPort,
			imageTag,
			cfgDir,
		)
	}
	stdout, stderr, err = sshRunWithPath(client, osType, runCmd)
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
	stdout, _, err = sshRunWithPath(client, osType, fmt.Sprintf("%sdocker inspect -f '{{.State.Running}}' %s", sudo, containerName))
	if err != nil || strings.TrimSpace(stdout) != "true" {
		// Get container logs for diagnostics.
		logs, _, _ := sshRunWithPath(client, osType, fmt.Sprintf("%sdocker logs --tail 20 %s 2>&1", sudo, containerName))
		logFn(fmt.Sprintf("[%s] WARNING: Container may not be running. Logs: %s", party, logs))
		return fmt.Errorf("container not running after start")
	}

	logFn(fmt.Sprintf("[%s] Deployment complete.", party))
	return nil
}

// ensureDocker checks if Docker is installed and installs it if not.
func ensureDocker(client *ssh.Client, logFn func(string), party string, osType string) error {
	_, _, err := sshRunWithPath(client, osType, "docker --version")
	if err == nil {
		// Verify daemon is actually running (Docker Desktop on macOS might be stopped).
		if osType == "darwin" {
			_, _, daemonErr := sshRunWithPath(client, osType, "docker info >/dev/null 2>&1")
			if daemonErr != nil {
				return fmt.Errorf("Docker is installed but not running. Please start Docker Desktop and try again")
			}
		}
		logFn(fmt.Sprintf("[%s] Docker is already installed.", party))
		return nil
	}

	if osType == "darwin" {
		return fmt.Errorf("Docker is not installed on this macOS server. Please install Docker Desktop (https://docker.com/products/docker-desktop) or run: brew install --cask docker — then start Docker Desktop and try again")
	}

	// Linux install path.
	logFn(fmt.Sprintf("[%s] Docker not found, installing...", party))

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
		installCmd = `curl -fsSL https://get.docker.com | sudo sh`
	}

	logFn(fmt.Sprintf("[%s] Running Docker installation (this may take a minute)...", party))
	stdout, stderr, err := SSHRunCommand(client, installCmd)
	if err != nil {
		return fmt.Errorf("install docker: stdout=%s stderr=%s: %w", stdout, stderr, err)
	}

	_, _, err = SSHRunCommand(client, "sudo docker --version")
	if err != nil {
		return fmt.Errorf("docker not available after install: %w", err)
	}

	logFn(fmt.Sprintf("[%s] Docker installed successfully.", party))
	return nil
}

// buildFromSource clones the repo and builds the Docker image on the remote server.
func buildFromSource(client *ssh.Client, party string, logFn func(string), osType string) error {
	logFn(fmt.Sprintf("[%s] Cloning source repository...", party))

	sudo := sudoPrefix(osType)
	gitInstall := "sudo apt-get install -y -qq git 2>/dev/null || sudo yum install -y git 2>/dev/null || true"
	if osType == "darwin" {
		// macOS: git comes with Xcode CLI tools, or install via brew.
		gitInstall = "which git || xcode-select --install 2>/dev/null || brew install git || true"
	}

	commands := []string{
		gitInstall,
		"rm -rf /tmp/crypto-claw-build",
		"git clone --depth 1 https://github.com/seeingred/crypto-claw.git /tmp/crypto-claw-build",
		fmt.Sprintf("cd /tmp/crypto-claw-build && %sdocker build -t crypto-claw-party-%s:latest -f docker/Dockerfile.party-%s .", sudo, party, party),
		"rm -rf /tmp/crypto-claw-build",
	}

	for _, cmd := range commands {
		logFn(fmt.Sprintf("[%s] %s", party, cmd))
		stdout, stderr, err := sshRunWithPath(client, osType, cmd)
		if err != nil {
			return fmt.Errorf("command %q: stdout=%s stderr=%s: %w", cmd, stdout, stderr, err)
		}
	}

	return nil
}

// localBaseDir returns ~/.crypto-claw as the persistent local config directory.
func localBaseDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "crypto-claw")
	}
	return filepath.Join(home, ".crypto-claw")
}

// localDSN returns the host-side DSN for a local party database.
func localDSN(party string) string {
	return fmt.Sprintf("postgres://crypto_claw:crypto_claw@127.0.0.1:5432/crypto_claw_%s?sslmode=disable", party)
}

// DeployLocal deploys both parties locally using Docker containers.
// Configs and certs are written to ~/.crypto-claw/ and mounted into containers.
func DeployLocal(state *WizardState, logFn func(string)) error {
	baseDir := localBaseDir()
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

		// Write key shares to disk (for DB import).
		logFn(fmt.Sprintf("[%s] Writing key shares...", party))
		if err := writeKeyShares(state, party, partyDir); err != nil {
			return fmt.Errorf("write key shares for party %s: %w", party, err)
		}

		// Config uses container-internal paths.
		cfg := buildLocalDockerConfig(state, party)
		cfgJSON, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal config: %w", err)
		}
		cfgPath := filepath.Join(partyDir, "config.json")
		if err := os.WriteFile(cfgPath, cfgJSON, 0600); err != nil {
			return fmt.Errorf("write config: %w", err)
		}

		logFn(fmt.Sprintf("[%s] Configuration written to %s", party, partyDir))
	}

	// Skip starting containers if CRYPTO_CLAW_NO_PROCESSES is set (e.g. in tests).
	if os.Getenv("CRYPTO_CLAW_NO_PROCESSES") != "" {
		logFn("[local] Skipping container start (CRYPTO_CLAW_NO_PROCESSES set).")
		logFn("[local] Local deployment complete (config only).")
		logFn(fmt.Sprintf("[local] Config directory: %s", baseDir))
		return nil
	}

	// Check Docker is available locally.
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("docker not found — please install Docker Desktop")
	}

	// Stop any existing containers.
	logFn("[local] Stopping any existing containers...")
	killExistingParties(logFn)

	// Ensure PostgreSQL databases exist.
	logFn("[local] Setting up PostgreSQL databases...")
	if err := ensureLocalPostgres(logFn); err != nil {
		return fmt.Errorf("postgres setup: %w", err)
	}

	// Import key shares into PostgreSQL (runs on host).
	logFn("[local] Importing key shares into databases...")
	for _, party := range []string{"a", "b"} {
		partyDir := filepath.Join(baseDir, "party-"+party)
		if err := importSharesToDB(localDSN(party), partyDir, logFn, party); err != nil {
			return fmt.Errorf("import shares for party %s: %w", party, err)
		}
	}

	// Build Docker images locally from source.
	projectRoot := findProjectRoot()
	for _, party := range []string{"a", "b"} {
		imageName := fmt.Sprintf("crypto-claw-party-%s:latest", party)
		dockerfile := fmt.Sprintf("docker/Dockerfile.party-%s", party)
		logFn(fmt.Sprintf("[local] Building Docker image %s...", imageName))

		if err := dockerBuildWithLogs(projectRoot, dockerfile, imageName, logFn); err != nil {
			return fmt.Errorf("build %s: %w", imageName, err)
		}
		logFn(fmt.Sprintf("[local] Image %s built successfully.", imageName))
	}

	// Start containers.
	for _, party := range []string{"b", "a"} { // B first (it listens)
		partyDir := filepath.Join(baseDir, "party-"+party)
		containerName := containerNameA
		port := "8080"
		if party == "b" {
			containerName = containerNameB
			port = "9000"
		}
		imageName := fmt.Sprintf("crypto-claw-party-%s:latest", party)

		logFn(fmt.Sprintf("[local] Starting %s...", containerName))
		cmd := exec.Command("docker", "run", "-d",
			"--name", containerName,
			"-v", partyDir+":"+remoteConfigDir+":ro",
			"-p", port+":"+port,
			"--add-host=host.docker.internal:host-gateway",
			"-e", "ALLOW_LOCAL_RPC=1",
			imageName,
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			logFn(fmt.Sprintf("[local] docker run output: %s", string(out)))
			return fmt.Errorf("start %s: %w", containerName, err)
		}
		containerID := strings.TrimSpace(string(out))
		if len(containerID) > 12 {
			containerID = containerID[:12]
		}
		logFn(fmt.Sprintf("[local] %s started (container %s)", containerName, containerID))
	}

	// Verify containers are running after a brief startup.
	time.Sleep(3 * time.Second)
	var containerErrors []string
	for _, name := range []string{containerNameB, containerNameA} {
		out, err := exec.Command("docker", "inspect", "-f", "{{.State.Running}}", name).Output()
		if err != nil || strings.TrimSpace(string(out)) != "true" {
			logs, _, _ := dockerLogs(name, 20)
			containerErrors = append(containerErrors, fmt.Sprintf("%s not running. Logs:\n%s", name, logs))
		}
	}
	if len(containerErrors) > 0 {
		for _, e := range containerErrors {
			logFn(fmt.Sprintf("[local] ERROR: %s", e))
		}
		return fmt.Errorf("containers failed to start: %s", strings.Join(containerErrors, "; "))
	}

	logFn("[local] Local deployment complete.")
	logFn(fmt.Sprintf("[local] Config directory: %s", baseDir))
	logFn("[local] Containers: docker logs crypto-claw-party-a | docker logs crypto-claw-party-b")
	return nil
}

// buildLocalDockerConfig creates a config for local Docker deployment.
// Uses container-internal paths and host.docker.internal for host services.
func buildLocalDockerConfig(state *WizardState, party string) *config.Config {
	cfg := &config.Config{
		Party:   party,
		DataDir: remoteConfigDir,
		Database: config.DatabaseConfig{
			Host:     "host.docker.internal",
			Port:     5432,
			User:     "crypto_claw",
			Password: "crypto_claw",
			DBName:   "crypto_claw_" + party,
			SSLMode:  "disable",
		},
		Transport: config.TransportConfig{
			CertFile:   filepath.Join(remoteConfigDir, "cert.pem"),
			KeyFile:    filepath.Join(remoteConfigDir, "key.pem"),
			CACertFile: filepath.Join(remoteConfigDir, "ca.pem"),
		},
	}

	if party == "a" {
		partyAAddr := state.PartyAAddr
		if partyAAddr == "" || strings.HasPrefix(partyAAddr, "127.0.0.1:") {
			// Inside a container, must bind to 0.0.0.0 to be reachable.
			port := "8080"
			if parts := strings.SplitN(partyAAddr, ":", 2); len(parts) == 2 {
				port = parts[1]
			}
			partyAAddr = "0.0.0.0:" + port
		}
		cfg.API = config.APIConfig{
			ListenAddr: partyAAddr,
		}
		// Party A connects to Party B via host network.
		cfg.Transport.RemoteAddr = fmt.Sprintf("host.docker.internal:%d", state.GetTransportPort())
	} else {
		cfg.Transport.ListenAddr = fmt.Sprintf("0.0.0.0:%d", state.GetTransportPort())

		// Rewrite localhost LLM endpoint to host.docker.internal so the
		// container can reach the host-side Ollama/vLLM.
		llmEndpoint := state.LLMEndpoint
		if llmEndpoint != "" {
			llmEndpoint = strings.Replace(llmEndpoint, "localhost", "host.docker.internal", 1)
			llmEndpoint = strings.Replace(llmEndpoint, "127.0.0.1", "host.docker.internal", 1)
		}

		cfg.Analyzer = config.AnalyzerConfig{
			DisableAI: state.DisableAI,
			LLM: config.LLMConfig{
				Provider: state.LLMProvider,
				APIKey:   state.LLMAPIKey,
				Model:    state.LLMModel,
				Endpoint: llmEndpoint,
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

// UpdateLocal rebuilds Docker images and restarts containers using existing config.
func UpdateLocal(logFn func(string)) error {
	baseDir := localBaseDir()

	// Verify config exists from a previous install.
	for _, party := range []string{"a", "b"} {
		cfgPath := filepath.Join(baseDir, "party-"+party, "config.json")
		if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
			return fmt.Errorf("no existing installation found at %s — run install or restore first", cfgPath)
		}
	}

	// Stop existing containers.
	logFn("[update] Stopping existing containers...")
	killExistingParties(logFn)

	// Rebuild Docker images from source (picks up code changes).
	projectRoot := findProjectRoot()
	for _, party := range []string{"a", "b"} {
		imageName := fmt.Sprintf("crypto-claw-party-%s:latest", party)
		dockerfile := fmt.Sprintf("docker/Dockerfile.party-%s", party)
		logFn(fmt.Sprintf("[update] Rebuilding Docker image %s...", imageName))

		if err := dockerBuildWithLogs(projectRoot, dockerfile, imageName, logFn); err != nil {
			return fmt.Errorf("build %s: %w", imageName, err)
		}
		logFn(fmt.Sprintf("[update] Image %s rebuilt.", imageName))
	}

	// Start containers.
	for _, party := range []string{"b", "a"} {
		partyDir := filepath.Join(baseDir, "party-"+party)
		containerName := containerNameA
		port := "8080"
		if party == "b" {
			containerName = containerNameB
			port = "9000"
		}
		imageName := fmt.Sprintf("crypto-claw-party-%s:latest", party)

		logFn(fmt.Sprintf("[update] Starting %s...", containerName))
		cmd := exec.Command("docker", "run", "-d",
			"--name", containerName,
			"-v", partyDir+":"+remoteConfigDir+":ro",
			"-p", port+":"+port,
			"--add-host=host.docker.internal:host-gateway",
			"-e", "ALLOW_LOCAL_RPC=1",
			imageName,
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			logFn(fmt.Sprintf("[update] docker run output: %s", string(out)))
			return fmt.Errorf("start %s: %w", containerName, err)
		}
		containerID := strings.TrimSpace(string(out))
		if len(containerID) > 12 {
			containerID = containerID[:12]
		}
		logFn(fmt.Sprintf("[update] %s started (container %s)", containerName, containerID))
	}

	// Verify containers are running.
	time.Sleep(3 * time.Second)
	var containerErrors []string
	for _, name := range []string{containerNameB, containerNameA} {
		out, err := exec.Command("docker", "inspect", "-f", "{{.State.Running}}", name).Output()
		if err != nil || strings.TrimSpace(string(out)) != "true" {
			logs, _, _ := dockerLogs(name, 20)
			containerErrors = append(containerErrors, fmt.Sprintf("%s not running. Logs:\n%s", name, logs))
		}
	}
	if len(containerErrors) > 0 {
		for _, e := range containerErrors {
			logFn(fmt.Sprintf("[update] ERROR: %s", e))
		}
		return fmt.Errorf("containers failed to start: %s", strings.Join(containerErrors, "; "))
	}

	logFn("[update] Local update complete.")
	logFn(fmt.Sprintf("[update] Config directory: %s", baseDir))
	return nil
}

// importSharesToDB reads key share JSON files from disk and imports them into the party's PostgreSQL database.
// If master keys change, all derived keys are cleared to prevent address mismatches.
func importSharesToDB(dsn string, partyDir string, logFn func(string), party string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	st, err := store.NewPostgresStore(ctx, dsn, "") // no passphrase for local dev
	if err != nil {
		return fmt.Errorf("connect to database: %w", err)
	}
	defer st.Close()

	importShare := func(path string, curve tss.Curve, label string) error {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil // file doesn't exist, skip
		}
		var share tss.KeyShare
		if err := json.Unmarshal(data, &share); err != nil {
			return fmt.Errorf("parse %s share: %w", label, err)
		}

		// Check if a master share already exists with a different public key.
		existing, err := st.GetMasterShare(ctx, curve)
		if err == nil && !bytesEqual(existing.PublicKey, share.PublicKey) {
			logFn(fmt.Sprintf("[%s] WARNING: %s master key changed — clearing old derived keys", party, label))
			st.ClearDerivedKeys(ctx)
		}

		if err := st.SaveMasterShare(ctx, &share); err != nil {
			return fmt.Errorf("save %s share: %w", label, err)
		}
		logFn(fmt.Sprintf("[%s] %s master share imported.", party, label))
		return nil
	}

	if err := importShare(filepath.Join(partyDir, "ecdsa_share.json"), tss.CurveSecp256k1, "ECDSA"); err != nil {
		return err
	}
	if err := importShare(filepath.Join(partyDir, "eddsa_share.json"), tss.CurveEd25519, "EdDSA"); err != nil {
		return err
	}

	return nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// killExistingParties stops and removes any existing Docker containers, and also
// cleans up any leftover bare processes from older installs.
func killExistingParties(logFn func(string)) {
	stopped := false

	// Stop and remove Docker containers.
	for _, name := range []string{containerNameA, containerNameB} {
		out, err := exec.Command("docker", "inspect", "-f", "{{.State.Running}}", name).Output()
		if err == nil {
			exec.Command("docker", "stop", name).Run()
			exec.Command("docker", "rm", name).Run()
			if strings.TrimSpace(string(out)) == "true" {
				logFn(fmt.Sprintf("[local] Stopped container %s.", name))
				stopped = true
			} else {
				// Container existed but wasn't running — just remove.
				logFn(fmt.Sprintf("[local] Removed stopped container %s.", name))
			}
		}
	}

	// Also kill any bare processes from older (pre-Docker) installs.
	for _, pattern := range []string{"party-a", "party-b"} {
		exec.Command("pkill", "-f", pattern).Run()
	}
	for _, port := range []string{"8080", "9000"} {
		out, _ := exec.Command("lsof", "-ti", ":"+port).Output()
		pids := strings.TrimSpace(string(out))
		if pids != "" {
			for _, pid := range strings.Split(pids, "\n") {
				exec.Command("kill", pid).Run()
				stopped = true
			}
		}
	}

	if stopped {
		time.Sleep(1 * time.Second) // let ports release
	}
}

// dockerLogs fetches the last N lines of logs from a Docker container.
func dockerLogs(containerName string, lines int) (string, string, error) {
	cmd := exec.Command("docker", "logs", "--tail", fmt.Sprintf("%d", lines), containerName)
	out, err := cmd.CombinedOutput()
	return string(out), "", err
}

// dockerBuildWithLogs runs docker build and streams output to logFn line by line.
func dockerBuildWithLogs(projectRoot, dockerfile, imageName string, logFn func(string)) error {
	cmd := exec.Command("docker", "build", "--progress=plain", "-t", imageName, "-f", dockerfile, ".")
	cmd.Dir = projectRoot

	// Use io.Pipe to merge stdout and stderr into a single stream.
	pr, pw := io.Pipe()
	cmd.Stdout = pw
	cmd.Stderr = pw

	if err := cmd.Start(); err != nil {
		pw.Close()
		return fmt.Errorf("start: %w", err)
	}

	// Read lines in a goroutine so we don't block.
	scanDone := make(chan struct{})
	go func() {
		defer close(scanDone)
		scanner := bufio.NewScanner(pr)
		scanner.Buffer(make([]byte, 0, 64*1024), 256*1024)
		for scanner.Scan() {
			line := scanner.Text()
			if trimmed := strings.TrimSpace(line); trimmed != "" {
				logFn(fmt.Sprintf("[build] %s", trimmed))
			}
		}
	}()

	err := cmd.Wait()
	pw.Close() // signals EOF to the scanner
	<-scanDone // wait for scanner to finish

	if err != nil {
		return fmt.Errorf("docker build failed: %w", err)
	}
	return nil
}

// ensureLocalPostgres ensures PostgreSQL is available for local mode.
// First checks for a host PostgreSQL; if not found, starts a Docker container.
func ensureLocalPostgres(logFn func(string)) error {
	// Try host PostgreSQL first.
	if hostPGAvailable() {
		logFn("[local] Using host PostgreSQL.")
		return ensureHostPostgresDatabases(logFn)
	}

	// No host Postgres — use Docker.
	logFn("[local] No host PostgreSQL found, starting Docker PostgreSQL...")
	return ensureDockerPostgres(logFn)
}

// hostPGAvailable checks if a host PostgreSQL is running and accessible.
func hostPGAvailable() bool {
	if _, err := exec.LookPath("pg_isready"); err != nil {
		return false
	}
	err := exec.Command("pg_isready", "-q").Run()
	return err == nil
}

// ensureHostPostgresDatabases creates role and databases on the host PostgreSQL.
func ensureHostPostgresDatabases(logFn func(string)) error {
	roleCheck, _ := exec.Command("psql", "-tAc",
		"SELECT 1 FROM pg_roles WHERE rolname='crypto_claw'", "postgres").Output()
	if strings.TrimSpace(string(roleCheck)) != "1" {
		logFn("[local] Creating PostgreSQL role 'crypto_claw'...")
		out, err := exec.Command("psql", "-c",
			"CREATE ROLE crypto_claw WITH LOGIN PASSWORD 'crypto_claw'", "postgres").CombinedOutput()
		if err != nil {
			return fmt.Errorf("create role: %s: %w", strings.TrimSpace(string(out)), err)
		}
	} else {
		logFn("[local] PostgreSQL role 'crypto_claw' already exists.")
	}

	for _, dbName := range []string{"crypto_claw_a", "crypto_claw_b"} {
		dbCheck, _ := exec.Command("psql", "-tAc",
			fmt.Sprintf("SELECT 1 FROM pg_database WHERE datname='%s'", dbName), "postgres").Output()
		if strings.TrimSpace(string(dbCheck)) != "1" {
			logFn(fmt.Sprintf("[local] Creating database '%s'...", dbName))
			out, err := exec.Command("createdb", "-O", "crypto_claw", dbName).CombinedOutput()
			if err != nil {
				return fmt.Errorf("create database %s: %s: %w", dbName, strings.TrimSpace(string(out)), err)
			}
		} else {
			logFn(fmt.Sprintf("[local] Database '%s' already exists.", dbName))
		}
	}

	logFn("[local] PostgreSQL setup complete.")
	return nil
}

// ensureDockerPostgres starts a PostgreSQL Docker container and creates the required
// role and databases. If the container already exists and is running, it's reused.
func ensureDockerPostgres(logFn func(string)) error {
	// Check if our PG container already exists and is running.
	out, err := exec.Command("docker", "inspect", "-f", "{{.State.Running}}", containerNamePG).Output()
	if err == nil && strings.TrimSpace(string(out)) == "true" {
		logFn("[local] PostgreSQL container already running.")
		return ensureDockerPostgresDatabases(logFn)
	}

	// Remove stopped container if it exists.
	exec.Command("docker", "rm", containerNamePG).Run()

	// Start PostgreSQL container.
	logFn("[local] Starting PostgreSQL container...")
	cmd := exec.Command("docker", "run", "-d",
		"--name", containerNamePG,
		"-p", "5432:5432",
		"-e", "POSTGRES_USER=crypto_claw",
		"-e", "POSTGRES_PASSWORD=crypto_claw",
		"-e", "POSTGRES_DB=crypto_claw_a",
		"--restart", "unless-stopped",
		"postgres:16-alpine",
	)
	runOut, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("start postgres container: %s: %w", strings.TrimSpace(string(runOut)), err)
	}
	logFn("[local] PostgreSQL container started.")

	// Wait for it to be ready (up to 30s).
	logFn("[local] Waiting for PostgreSQL to be ready...")
	for i := 0; i < 30; i++ {
		check := exec.Command("docker", "exec", containerNamePG,
			"pg_isready", "-U", "crypto_claw")
		if check.Run() == nil {
			logFn("[local] PostgreSQL is ready.")
			return ensureDockerPostgresDatabases(logFn)
		}
		time.Sleep(1 * time.Second)
	}
	return fmt.Errorf("PostgreSQL container failed to become ready within 30s")
}

// ensureDockerPostgresDatabases creates the second database (crypto_claw_b) inside
// the Docker PostgreSQL container. crypto_claw_a is created by POSTGRES_DB env var.
func ensureDockerPostgresDatabases(logFn func(string)) error {
	// crypto_claw_a already exists (created by POSTGRES_DB).
	// Create crypto_claw_b if it doesn't exist.
	check := exec.Command("docker", "exec", containerNamePG,
		"psql", "-U", "crypto_claw", "-tAc",
		"SELECT 1 FROM pg_database WHERE datname='crypto_claw_b'")
	out, _ := check.Output()
	if strings.TrimSpace(string(out)) != "1" {
		logFn("[local] Creating database 'crypto_claw_b'...")
		cmd := exec.Command("docker", "exec", containerNamePG,
			"createdb", "-U", "crypto_claw", "crypto_claw_b")
		if createOut, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("create crypto_claw_b: %s: %w", strings.TrimSpace(string(createOut)), err)
		}
	} else {
		logFn("[local] Database 'crypto_claw_b' already exists.")
	}
	logFn("[local] PostgreSQL setup complete.")
	return nil
}

// ensureRemotePostgres ensures a PostgreSQL Docker container is running on the remote server.
func ensureRemotePostgres(client *ssh.Client, party string, sudo string, osType string, logFn func(string)) error {
	pgContainer := fmt.Sprintf("crypto-claw-postgres-%s", party)
	dbName := fmt.Sprintf("crypto_claw_%s", party)

	// Check if our PG container is already running.
	out, _, _ := sshRunWithPath(client, osType, fmt.Sprintf("%sdocker inspect -f '{{.State.Running}}' %s 2>/dev/null", sudo, pgContainer))
	if strings.TrimSpace(out) == "true" {
		logFn(fmt.Sprintf("[%s] PostgreSQL container already running.", party))
		return nil
	}

	// Remove stopped container if it exists.
	sshRunWithPath(client, osType, fmt.Sprintf("%sdocker rm %s 2>/dev/null", sudo, pgContainer))

	// Start PostgreSQL container.
	logFn(fmt.Sprintf("[%s] Starting PostgreSQL container...", party))
	runCmd := fmt.Sprintf(
		"%sdocker run -d --name %s "+
			"-p 5432:5432 "+
			"-e POSTGRES_USER=crypto_claw "+
			"-e POSTGRES_PASSWORD=crypto_claw "+
			"-e POSTGRES_DB=%s "+
			"--restart unless-stopped "+
			"postgres:16-alpine",
		sudo, pgContainer, dbName,
	)
	out, stderr, err := sshRunWithPath(client, osType, runCmd)
	if err != nil {
		return fmt.Errorf("start postgres container: %s %s: %w", out, stderr, err)
	}

	// Wait for it to be ready.
	logFn(fmt.Sprintf("[%s] Waiting for PostgreSQL to be ready...", party))
	for i := 0; i < 30; i++ {
		_, _, err := sshRunWithPath(client, osType, fmt.Sprintf("%sdocker exec %s pg_isready -U crypto_claw", sudo, pgContainer))
		if err == nil {
			logFn(fmt.Sprintf("[%s] PostgreSQL is ready.", party))
			return nil
		}
		time.Sleep(1 * time.Second)
	}
	return fmt.Errorf("PostgreSQL container failed to become ready within 30s")
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
		if partyAAddr == "" || strings.HasPrefix(partyAAddr, "127.0.0.1:") {
			// Inside a container, must bind to 0.0.0.0 to be reachable via port mapping.
			port := "8080"
			if parts := strings.SplitN(partyAAddr, ":", 2); len(parts) == 2 {
				port = parts[1]
			}
			partyAAddr = "0.0.0.0:" + port
		}
		cfg.API = config.APIConfig{
			ListenAddr: partyAAddr,
		}
		// Party A connects to Party B.
		tport := state.GetTransportPort()
		if state.LocalMode {
			cfg.Transport.RemoteAddr = fmt.Sprintf("127.0.0.1:%d", tport)
		} else {
			cfg.Transport.RemoteAddr = fmt.Sprintf("%s:%d", state.ServerB.Host, tport)
		}
	} else {
		// Party B listens for connections.
		cfg.Transport.ListenAddr = fmt.Sprintf("0.0.0.0:%d", state.GetTransportPort())
		cfg.Analyzer = config.AnalyzerConfig{
			DisableAI: state.DisableAI,
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
