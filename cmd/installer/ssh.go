package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/crypto/ssh"
)

// SSHConfig holds the connection parameters for an SSH server.
type SSHConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	Password string `json:"password,omitempty"`
	KeyPath  string `json:"keyPath,omitempty"`
}

// Addr returns the host:port address string.
func (c SSHConfig) Addr() string {
	port := c.Port
	if port == 0 {
		port = 22
	}
	return net.JoinHostPort(c.Host, strconv.Itoa(port))
}

// SSHConnect establishes an SSH connection using the given configuration.
func SSHConnect(cfg SSHConfig) (*ssh.Client, error) {
	var authMethods []ssh.AuthMethod

	// Try key-based authentication first.
	if cfg.KeyPath != "" {
		keyData, err := os.ReadFile(cfg.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("read SSH key %s: %w", cfg.KeyPath, err)
		}
		signer, err := ssh.ParsePrivateKey(keyData)
		if err != nil {
			return nil, fmt.Errorf("parse SSH key: %w", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}

	// Also try default SSH keys from ~/.ssh/.
	if cfg.KeyPath == "" {
		homeDir, err := os.UserHomeDir()
		if err == nil {
			for _, name := range []string{"id_ed25519", "id_rsa", "id_ecdsa"} {
				keyPath := filepath.Join(homeDir, ".ssh", name)
				keyData, err := os.ReadFile(keyPath)
				if err != nil {
					continue
				}
				signer, err := ssh.ParsePrivateKey(keyData)
				if err != nil {
					continue
				}
				authMethods = append(authMethods, ssh.PublicKeys(signer))
				break
			}
		}
	}

	// Add password auth if provided.
	if cfg.Password != "" {
		authMethods = append(authMethods, ssh.Password(cfg.Password))
	}

	if len(authMethods) == 0 {
		return nil, fmt.Errorf("no SSH authentication methods available (provide password or key)")
	}

	sshCfg := &ssh.ClientConfig{
		User:            cfg.User,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // installer wizard use
	}

	client, err := ssh.Dial("tcp", cfg.Addr(), sshCfg)
	if err != nil {
		return nil, fmt.Errorf("SSH dial %s: %w", cfg.Addr(), err)
	}
	return client, nil
}

// SSHRunCommand executes a command on the remote server and returns stdout, stderr, and any error.
func SSHRunCommand(client *ssh.Client, cmd string) (string, string, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", "", fmt.Errorf("create SSH session: %w", err)
	}
	defer session.Close()

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	err = session.Run(cmd)
	return stdout.String(), stderr.String(), err
}

// SSHUploadFile uploads a byte slice to a remote path via SFTP-like mechanism
// using an SSH session with cat.
func SSHUploadFile(client *ssh.Client, content []byte, remotePath string) error {
	// Ensure the remote directory exists.
	dir := filepath.Dir(remotePath)
	if _, _, err := SSHRunCommand(client, fmt.Sprintf("mkdir -p %q", dir)); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("create SSH session: %w", err)
	}
	defer session.Close()

	// Use stdin piped to cat to write the file.
	stdinPipe, err := session.StdinPipe()
	if err != nil {
		return fmt.Errorf("open stdin pipe: %w", err)
	}

	var stderr bytes.Buffer
	session.Stderr = &stderr

	// Start the remote command that reads stdin and writes to the file.
	if err := session.Start(fmt.Sprintf("cat > %q", remotePath)); err != nil {
		return fmt.Errorf("start cat command: %w", err)
	}

	if _, err := io.Copy(stdinPipe, bytes.NewReader(content)); err != nil {
		return fmt.Errorf("write file data: %w", err)
	}
	stdinPipe.Close()

	if err := session.Wait(); err != nil {
		return fmt.Errorf("upload to %s: %s: %w", remotePath, stderr.String(), err)
	}

	// Set restrictive permissions on the file.
	if _, _, err := SSHRunCommand(client, fmt.Sprintf("chmod 0600 %q", remotePath)); err != nil {
		return fmt.Errorf("chmod %s: %w", remotePath, err)
	}

	return nil
}
