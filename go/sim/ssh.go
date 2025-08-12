package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSH Server implementation
func (s *SSHServer) Start() error {
	// Use shared SSH key from manager's resource pool
	var sharedKey ssh.Signer
	if manager != nil && manager.resourcePool != nil {
		sharedKey = manager.resourcePool.sharedSSHKey
	} else {
		// Fallback: generate a key for this server (should not happen in normal operation)
		key, err := generateSharedSSHKey()
		if err != nil {
			return fmt.Errorf("failed to generate SSH key: %v", err)
		}
		sharedKey = key
	}

	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == USERNAME && string(pass) == PASSWORD {
				return nil, nil
			}
			return nil, fmt.Errorf("invalid credentials")
		},
	}
	config.AddHostKey(sharedKey)

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
		// Check if context is cancelled
		select {
		case <-s.ctx.Done():
			return
		default:
		}
		
		// Set accept deadline to allow context cancellation
		if tcpListener, ok := s.listener.(*net.TCPListener); ok {
			tcpListener.SetDeadline(time.Now().Add(1 * time.Second))
		}
		conn, err := s.listener.Accept()
		if err != nil {
			// Check if it's a timeout error (expected for context cancellation)
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if s.running {
				log.Printf("SSH server error accepting connection: %v", err)
			}
			continue
		}
		
		// Limit concurrent connections
		select {
		case s.connLimiter <- struct{}{}:
			go s.handleConnectionWithLimit(conn)
		default:
			// Too many connections, reject
			log.Printf("SSH server: rejecting connection, too many active connections")
			conn.Close()
		}

	}
}

func (s *SSHServer) handleConnectionWithLimit(conn net.Conn) {
	defer func() {
		// Release connection slot
		<-s.connLimiter
	}()
	s.handleConnection(conn)
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
			case "shell", "exec":
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

		log.Printf("SSH %s: %s -> %s", s.device.ID, command, strings.Split(response, "\n")[0])
	}
}

func (s *SSHServer) findCommandResponse(command string) string {
	for _, resource := range s.device.resources.SSH {
		if strings.EqualFold(resource.Command, command) {
			return resource.Response
		}
	}
	return "Command not found"
}