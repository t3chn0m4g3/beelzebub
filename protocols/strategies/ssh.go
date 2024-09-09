package strategies

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/gliderlabs/ssh"
	"github.com/google/uuid"
	"github.com/mariocandela/beelzebub/v3/parser"
	"github.com/mariocandela/beelzebub/v3/plugins"
	"github.com/mariocandela/beelzebub/v3/tracer"
	log "github.com/sirupsen/logrus"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

type SSHStrategy struct {
}

func (sshStrategy *SSHStrategy) Init(beelzebubServiceConfiguration parser.BeelzebubServiceConfiguration, tr tracer.Tracer) error {
	file, err := os.OpenFile("./configurations/log/beelzebub.json", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0770)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	multiWriter := io.MultiWriter(os.Stdout, file)
	log.SetOutput(multiWriter)
	log.SetFormatter(&log.JSONFormatter{
		TimestampFormat: time.RFC3339,
		FieldMap: log.FieldMap{
			log.FieldKeyTime: "timestamp",
		},
	})
	log.SetLevel(log.InfoLevel)
	go func() {
		// Load or generate SSH host key
		hostKey, err := loadOrGenerateHostKey("./configurations/key/ssh_host_key")
		if err != nil {
			log.Fatalf("Failed to load or generate host key: %v", err)
		}

		server := &ssh.Server{
			Addr:        beelzebubServiceConfiguration.Address,
			MaxTimeout:  time.Duration(beelzebubServiceConfiguration.DeadlineTimeoutSeconds) * time.Second,
			IdleTimeout: time.Duration(beelzebubServiceConfiguration.DeadlineTimeoutSeconds) * time.Second,
			Version:     beelzebubServiceConfiguration.ServerVersion,
			Handler: func(sess ssh.Session) {
				sessionStart := time.Now()
				uuidSession := uuid.New()

				src_ip, src_port, _ := net.SplitHostPort(sess.RemoteAddr().String())
				_, dest_port, _ := net.SplitHostPort(beelzebubServiceConfiguration.Address)
				clientVersion := sess.Context().ClientVersion()

				// SSH Inline Sessions

				if sess.RawCommand() != "" {
					for _, command := range beelzebubServiceConfiguration.Commands {
						matched, err := regexp.MatchString(command.Regex, sess.RawCommand())
						if err != nil {
							log.Errorf("Error regex: %s, %s", command.Regex, err.Error())
							continue
						}

						if matched {
							commandOutput := command.Handler

							if command.Plugin == plugins.LLMPluginName {

								llmModel, err := plugins.FromStringToLLMModel(beelzebubServiceConfiguration.Plugin.LLMModel)

								if err != nil {
									log.Errorf("Error fromString: %s", err.Error())
									commandOutput = "command not found"
								}

								llmHoneypot := plugins.LLMHoneypot{
									Histories:   make([]plugins.Message, 0),
									OpenAIKey:   beelzebubServiceConfiguration.Plugin.OpenAISecretKey,
									Protocol:    tracer.SSH,
									Host:        beelzebubServiceConfiguration.Plugin.Host,
									Model:       llmModel,
									OllamaModel: beelzebubServiceConfiguration.Plugin.OllamaModel,
								}

								llmHoneypotInstance := plugins.InitLLMHoneypot(llmHoneypot)

								if commandOutput, err = llmHoneypotInstance.ExecuteModel(sess.RawCommand()); err != nil {
									log.Errorf("Error ExecuteModel: %s, %s", sess.RawCommand(), err.Error())
									commandOutput = "command not found"
								}
							}

							sess.Write(append([]byte(commandOutput), '\n'))
							sessionDuration := time.Since(sessionStart).Seconds()
							log.WithFields(log.Fields{
								"message":  "New SSH Inline Session",
								"protocol": tracer.SSH.String(),
								"src_ip":   src_ip,
								"src_port": src_port,
								"status":   tracer.Start.String(),
								"session":  uuidSession.String(),
								"environ":  strings.Join(sess.Environ(), ","),
								"username": sess.User(),
								"service":  beelzebubServiceConfiguration.Description,
								"input":    sess.RawCommand(),
								"output":   commandOutput,
							}).Info("New SSH Inline Session")
							log.WithFields(log.Fields{
								"message":          "End SSH Inline Session",
								"src_ip":           src_ip,
								"src_port":         src_port,
								"dest_port":        dest_port,
								"status":           tracer.End.String(),
								"protocol":         tracer.SSH.String(),
								"session":          uuidSession.String(),
								"session_duration": fmt.Sprintf("%.2fs", sessionDuration), // Log seconds
							}).Info("End SSH Inline Session")
							return
						}
					}
				}

				// SSH Inline Sessions

				log.WithFields(log.Fields{
					"message":        "New SSH Session",
					"protocol":       tracer.SSH.String(),
					"src_ip":         src_ip,
					"src_port":       src_port,
					"dest_port":      dest_port,
					"status":         tracer.Start.String(),
					"session":        uuidSession.String(),
					"environ":        strings.Join(sess.Environ(), ","),
					"username":       sess.User(),
					"service":        beelzebubServiceConfiguration.Description,
					"input":          sess.RawCommand(),
					"client_version": clientVersion,
				}).Info("New SSH Session")

				term := term.NewTerminal(sess, buildPrompt(sess.User(), beelzebubServiceConfiguration.ServerName))
				var histories []plugins.Message
				for {
					commandStart := time.Now()
					commandInput, err := term.ReadLine()
					commandDuration := time.Since(commandStart).Seconds()

					if err != nil {
						break
					}

					if commandInput == "exit" {
						break
					}
					for _, command := range beelzebubServiceConfiguration.Commands {
						matched, err := regexp.MatchString(command.Regex, commandInput)
						if err != nil {
							log.Errorf("Error regex: %s, %s", command.Regex, err.Error())
							continue
						}

						if matched {
							commandOutput := command.Handler

							if command.Plugin == plugins.LLMPluginName {

								llmModel, err := plugins.FromStringToLLMModel(beelzebubServiceConfiguration.Plugin.LLMModel)

								if err != nil {
									log.Errorf("Error fromString: %s", err.Error())
									commandOutput = "command not found"
								}

								llmHoneypot := plugins.LLMHoneypot{
									Histories:   histories,
									OpenAIKey:   beelzebubServiceConfiguration.Plugin.OpenAISecretKey,
									Protocol:    tracer.SSH,
									Host:        beelzebubServiceConfiguration.Plugin.Host,
									Model:       llmModel,
									OllamaModel: beelzebubServiceConfiguration.Plugin.OllamaModel,
								}

								llmHoneypotInstance := plugins.InitLLMHoneypot(llmHoneypot)

								if commandOutput, err = llmHoneypotInstance.ExecuteModel(commandInput); err != nil {
									log.Errorf("Error ExecuteModel: %s, %s", commandInput, err.Error())
									commandOutput = "command not found"
								}
							}

							histories = append(histories, plugins.Message{Role: plugins.USER.String(), Content: commandInput})
							histories = append(histories, plugins.Message{Role: plugins.ASSISTANT.String(), Content: commandOutput})

							term.Write(append([]byte(commandOutput), '\n'))

							log.WithFields(log.Fields{
								"message":        "New SSH Terminal Session",
								"src_ip":         src_ip,
								"src_port":       src_port,
								"dest_port":      dest_port,
								"status":         tracer.Interaction.String(),
								"input":          commandInput,
								"input_duration": fmt.Sprintf("%.2fs", commandDuration), // Log seconds
								"output":         commandOutput,
								"session":        uuidSession.String(),
								"protocol":       tracer.SSH.String(),
								"service":        beelzebubServiceConfiguration.Description,
							}).Info("New SSH Terminal Session")
							break
						}
					}
				}

				sessionDuration := time.Since(sessionStart).Seconds()
				log.WithFields(log.Fields{
					"message":          "End SSH Session",
					"src_ip":           src_ip,
					"src_port":         src_port,
					"dest_port":        dest_port,
					"status":           tracer.End.String(),
					"protocol":         tracer.SSH.String(),
					"session":          uuidSession.String(),
					"session_duration": fmt.Sprintf("%.2fs", sessionDuration), // Log seconds
				}).Info("End SSH Session")
			},
			PasswordHandler: func(ctx ssh.Context, password string) bool {
				src_ip, src_port, _ := net.SplitHostPort(ctx.RemoteAddr().String())
				_, dest_port, _ := net.SplitHostPort(beelzebubServiceConfiguration.Address)
				clientVersion := ctx.ClientVersion()

				log.WithFields(log.Fields{
					"message":   "New SSH attempt",
					"protocol":  tracer.SSH.String(),
					"status":    tracer.Stateless.String(),
					"username":  ctx.User(),
					"password":  password,
					"client":    clientVersion,
					"src_ip":    src_ip,
					"src_port":  src_port,
					"dest_port": dest_port,
					"session":   uuid.New().String(),
					"service":   beelzebubServiceConfiguration.Description,
				}).Info("New SSH attempt")
				matched, err := regexp.MatchString(beelzebubServiceConfiguration.PasswordRegex, password)
				if err != nil {
					log.Errorf("Error regex: %s, %s", beelzebubServiceConfiguration.PasswordRegex, err.Error())
					return false
				}
				return matched
			},
			HostSigners: []ssh.Signer{hostKey},
		}

		err = server.ListenAndServe()
		if err != nil {
			log.Errorf("Error during init SSH Protocol: %s", err.Error())
		}
	}()

	log.WithFields(log.Fields{
		"port":     beelzebubServiceConfiguration.Address,
		"commands": len(beelzebubServiceConfiguration.Commands),
	}).Infof("GetInstance service %s", beelzebubServiceConfiguration.Protocol)
	return nil
}

func loadOrGenerateHostKey(path string) (ssh.Signer, error) {
	// Try to read an existing private key file
	privateBytes, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Generate a new private key
			privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				return nil, fmt.Errorf("failed to generate private key: %v", err)
			}

			privateBytes = pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
			})

			// Save the newly generated key to a file
			err = os.WriteFile(path, privateBytes, 0770)
			if err != nil {
				return nil, fmt.Errorf("failed to save private key: %v", err)
			}
		} else {
			return nil, fmt.Errorf("failed to read private key file: %v", err)
		}
	}

	// Parse the private key
	private, err := gossh.ParsePrivateKey(privateBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	return private, nil
}

func buildPrompt(user string, serverName string) string {
	return fmt.Sprintf("%s@%s:~$ ", user, serverName)
}
