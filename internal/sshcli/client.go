package sshcli

import (
	"bytes"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Config holds SSH connection parameters.
type Config struct {
	Host         string
	Port         int
	User         string
	Password     string
	PromptRegex  string // regex to detect CLI prompt (e.g. "[>#]$")
	PagerDisable string // command to disable pager (e.g. "terminal length 0")
	ReadTimeout  time.Duration
}

// Client manages an SSH session for interactive CLI.
type Client struct {
	cfg     Config
	conn    *ssh.Client
	session *ssh.Session
	stdin   io.WriteCloser
	stdout  io.Reader
	buf     bytes.Buffer
	prompt  *regexp.Regexp
}

// Dial connects to the device and starts an interactive shell.
func Dial(cfg Config) (*Client, error) {
	if cfg.Port == 0 {
		cfg.Port = 22
	}
	if cfg.ReadTimeout == 0 {
		cfg.ReadTimeout = 10 * time.Second
	}

	sshCfg := &ssh.ClientConfig{
		User: cfg.User,
		Auth: []ssh.AuthMethod{
			ssh.Password(cfg.Password),
			ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range answers {
					answers[i] = cfg.Password
				}
				return answers, nil
			}),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	conn, err := ssh.Dial("tcp", addr, sshCfg)
	if err != nil {
		return nil, fmt.Errorf("ssh dial %s: %w", addr, err)
	}

	session, err := conn.NewSession()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("ssh session: %w", err)
	}

	// Request PTY for interactive CLI
	modes := ssh.TerminalModes{
		ssh.ECHO:          0,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := session.RequestPty("xterm", 80, 200, modes); err != nil {
		session.Close()
		conn.Close()
		return nil, fmt.Errorf("pty request: %w", err)
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		session.Close()
		conn.Close()
		return nil, err
	}

	stdout, err := session.StdoutPipe()
	if err != nil {
		session.Close()
		conn.Close()
		return nil, err
	}

	if err := session.Shell(); err != nil {
		session.Close()
		conn.Close()
		return nil, fmt.Errorf("shell: %w", err)
	}

	promptRegex := cfg.PromptRegex
	if promptRegex == "" {
		promptRegex = `[>#\]]\s*$`
	}

	c := &Client{
		cfg:     cfg,
		conn:    conn,
		session: session,
		stdin:   stdin,
		stdout:  stdout,
		prompt:  regexp.MustCompile(promptRegex),
	}

	// Wait for initial prompt
	if _, err := c.readUntilPrompt(); err != nil {
		c.Close()
		return nil, fmt.Errorf("initial prompt: %w", err)
	}

	// Disable pager if configured
	if cfg.PagerDisable != "" {
		if _, err := c.Execute(cfg.PagerDisable); err != nil {
			c.Close()
			return nil, fmt.Errorf("pager disable: %w", err)
		}
	}

	return c, nil
}

// Execute sends a command and returns the output (excluding the command echo and prompt).
func (c *Client) Execute(cmd string) (string, error) {
	if _, err := fmt.Fprintf(c.stdin, "%s\n", cmd); err != nil {
		return "", fmt.Errorf("write cmd: %w", err)
	}

	output, err := c.readUntilPrompt()
	if err != nil {
		return "", err
	}

	// Strip the echoed command from the beginning
	lines := strings.Split(output, "\n")
	var cleaned []string
	skipFirst := true
	for _, line := range lines {
		line = strings.TrimRight(line, "\r ")
		if skipFirst && strings.Contains(line, cmd) {
			skipFirst = false
			continue
		}
		skipFirst = false
		cleaned = append(cleaned, line)
	}

	// Remove the last line if it matches the prompt
	if len(cleaned) > 0 && c.prompt.MatchString(cleaned[len(cleaned)-1]) {
		cleaned = cleaned[:len(cleaned)-1]
	}

	result := strings.TrimSpace(strings.Join(cleaned, "\n"))
	return result, nil
}

// ExecuteCommands sends multiple commands in sequence and returns combined output.
func (c *Client) ExecuteCommands(cmds []string) (string, error) {
	var outputs []string
	for _, cmd := range cmds {
		out, err := c.Execute(cmd)
		if err != nil {
			return strings.Join(outputs, "\n"), fmt.Errorf("cmd %q: %w", cmd, err)
		}
		if out != "" {
			outputs = append(outputs, out)
		}
	}
	return strings.Join(outputs, "\n"), nil
}

// Close terminates the SSH session and connection.
func (c *Client) Close() error {
	if c.session != nil {
		c.session.Close()
	}
	if c.conn != nil {
		c.conn.Close()
	}
	return nil
}

func (c *Client) readUntilPrompt() (string, error) {
	c.buf.Reset()
	tmp := make([]byte, 4096)
	deadline := time.After(c.cfg.ReadTimeout)

	for {
		select {
		case <-deadline:
			return c.buf.String(), fmt.Errorf("read timeout after %s", c.cfg.ReadTimeout)
		default:
		}

		// Non-blocking read with short deadline via goroutine
		type readResult struct {
			n   int
			err error
		}
		ch := make(chan readResult, 1)
		go func() {
			n, err := c.stdout.Read(tmp)
			ch <- readResult{n, err}
		}()

		select {
		case <-deadline:
			return c.buf.String(), fmt.Errorf("read timeout after %s", c.cfg.ReadTimeout)
		case r := <-ch:
			if r.n > 0 {
				c.buf.Write(tmp[:r.n])
			}
			if r.err != nil {
				if r.err == io.EOF {
					return c.buf.String(), nil
				}
				return c.buf.String(), r.err
			}

			// Check if we've hit the prompt
			current := c.buf.String()
			// Check last few lines for prompt match
			lines := strings.Split(current, "\n")
			if len(lines) > 0 {
				lastLine := strings.TrimRight(lines[len(lines)-1], "\r ")
				if c.prompt.MatchString(lastLine) {
					return current, nil
				}
			}
		}
	}
}
