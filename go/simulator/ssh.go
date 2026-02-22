/*
 * © 2025 Sharon Aicler (saichler@gmail.com)
 *
 * Layer 8 Ecosystem is licensed under the Apache License, Version 2.0.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"strings"

	"golang.org/x/crypto/ssh"
)

// SSH Server implementation
func (s *SSHServer) Start() error {
	// Use pre-generated host key if available, otherwise generate one
	var signer ssh.Signer
	if s.signer != nil {
		signer = s.signer
	} else {
		// Fallback: generate host key (should rarely happen)
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return err
		}

		privateKeyPEM := &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		}
		privateKeyBytes := pem.EncodeToMemory(privateKeyPEM)

		signer, err = ssh.ParsePrivateKey(privateKeyBytes)
		if err != nil {
			return err
		}
	}

	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == USERNAME && string(pass) == PASSWORD {
				return nil, nil
			}
			return nil, fmt.Errorf("invalid credentials")
		},
	}
	config.AddHostKey(signer)

	addr := fmt.Sprintf("%s:%d", s.device.IP.String(), s.device.SSHPort)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	s.listener = listener
	s.config = config
	s.running = true

	go s.handleConnections()
	return nil
}

func (s *SSHServer) Stop() error {
	if s.listener != nil {
		s.running = false
		return s.listener.Close()
	}
	return nil
}

func (s *SSHServer) handleConnections() {
	for s.running {
		conn, err := s.listener.Accept()
		if err != nil {
			if s.running {
				log.Printf("SSH server error accepting connection: %v", err)
			}
			continue
		}

		go s.handleConnection(conn)

	}
}

func (s *SSHServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	sshConn, channels, requests, err := ssh.NewServerConn(conn, s.config)
	if err != nil {
		log.Printf("SSH handshake error: %v", err)
		return
	}
	defer sshConn.Close()

	go ssh.DiscardRequests(requests)

	for newChannel := range channels {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Printf("Error accepting channel: %v", err)
			continue
		}

		go s.handleSession(channel, requests)
	}
}

func (s *SSHServer) handleSession(channel ssh.Channel, requests <-chan *ssh.Request) {
	defer channel.Close()

	// Handle session requests
	go func() {
		for req := range requests {
			switch req.Type {
			case "shell", "exec", "pty-req", "window-change":
				req.Reply(true, nil)
			default:
				req.Reply(false, nil)
			}
		}
	}()

	// Send welcome message
	welcome := fmt.Sprintf("Welcome to %s\nDevice Simulator SSH Server\n\n", s.device.ID)
	channel.Write([]byte(welcome))

	scanner := bufio.NewScanner(channel)

	for {
		// Send prompt
		channel.Write([]byte(fmt.Sprintf("%s> ", s.device.ID)))

		// Read command
		if !scanner.Scan() {
			break
		}

		command := strings.TrimSpace(scanner.Text())
		if command == "" {
			continue
		}

		if command == "exit" || command == "quit" {
			channel.Write([]byte("Goodbye!\n"))
			break
		}

		// Find response
		response := s.findCommandResponse(command)
		channel.Write([]byte(response + "\n\n"))

		// log.Printf("SSH %s: %s -> %s", s.device.ID, command, strings.Split(response, "\n")[0])
	}
}

func (s *SSHServer) findCommandResponse(command string) string {
	// Safely access resources with read lock
	s.device.mu.RLock()
	defer s.device.mu.RUnlock()
	
	for _, resource := range s.device.resources.SSH {
		if strings.EqualFold(resource.Command, command) {
			return resource.Response
		}
	}
	return "Command not found"
}