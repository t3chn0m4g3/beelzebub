package strategies

import (
	"fmt"
	"github.com/mariocandela/beelzebub/v3/parser"
	"github.com/mariocandela/beelzebub/v3/plugins"
	"github.com/mariocandela/beelzebub/v3/tracer"
	"io"
	"net"
	"regexp"
	"strings"
	"time"
    "os"
	"github.com/gliderlabs/ssh"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh/terminal"
)

type SSHStrategy struct {
}

func (sshStrategy *SSHStrategy) Init(beelzebubServiceConfiguration parser.BeelzebubServiceConfiguration, tr tracer.Tracer) error {
	file, err := os.OpenFile("/configurations/logs/beelzebub.json", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
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
		server := &ssh.Server{
			Addr:        beelzebubServiceConfiguration.Address,
			MaxTimeout:  time.Duration(beelzebubServiceConfiguration.DeadlineTimeoutSeconds) * time.Second,
			IdleTimeout: time.Duration(beelzebubServiceConfiguration.DeadlineTimeoutSeconds) * time.Second,
			Version:     beelzebubServiceConfiguration.ServerVersion,
			Handler: func(sess ssh.Session) {
				uuidSession := uuid.New()

				src_ip, src_port, _ := net.SplitHostPort(sess.RemoteAddr().String())

				log.WithFields(log.Fields{
					"info":			"New SSH Session",
					"protocol":		tracer.SSH.String(),
					"src_ip":		src_ip,
					"src_port":		src_port,
					"status":		tracer.Start.String(),
					"id":			uuidSession.String(),
					"environ":		strings.Join(sess.Environ(), ","),
					"username":		sess.User(),
					"service":		beelzebubServiceConfiguration.Description,
					"command":		sess.RawCommand(),
				}).Info("New SSH Session")

				term := terminal.NewTerminal(sess, buildPrompt(sess.User(), beelzebubServiceConfiguration.ServerName))
				var histories []plugins.Message
				for {
					commandInput, err := term.ReadLine()
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
									Histories: 		histories,
									OpenAIKey: 		beelzebubServiceConfiguration.Plugin.OpenAISecretKey,
									Protocol:  		tracer.SSH,
									Host:      		beelzebubServiceConfiguration.Plugin.Host,
									Model:     		llmModel,
									OllamaModel:	beelzebubServiceConfiguration.Plugin.OllamaModel,
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
								"info":				"New SSH Terminal Session",
								"src_ip":			src_ip,
								"src_port":			src_port,
								"status":			tracer.Interaction.String(),
								"command":			commandInput,
								"commandoutput": 	commandOutput,
								"id":				uuidSession.String(),
								"protocol":			tracer.SSH.String(),
								"service":			beelzebubServiceConfiguration.Description,
							}).Info("New SSH Terminal Session")
							break
						}
					}
				}
				log.WithFields(log.Fields{
					"info":		"End SSH Session",
					"status":	tracer.End.String(),
					"id":		uuidSession.String(),
				}).Info("End SSH Session")
			},
			PasswordHandler: func(ctx ssh.Context, password string) bool {
				src_ip, src_port, _ := net.SplitHostPort(ctx.RemoteAddr().String())

				log.WithFields(log.Fields{
					"info":         "New SSH attempt",
					"protocol":		tracer.SSH.String(),
					"status":		tracer.Stateless.String(),
					"username":		ctx.User(),
					"password":		password,
					"client":		ctx.ClientVersion(),
					"src_ip":		src_ip,
					"src_port":		src_port,
					"id":			uuid.New().String(),
					"service":		beelzebubServiceConfiguration.Description,
				}).Info("New SSH attempt")
				matched, err := regexp.MatchString(beelzebubServiceConfiguration.PasswordRegex, password)
				if err != nil {
					log.Errorf("Error regex: %s, %s", beelzebubServiceConfiguration.PasswordRegex, err.Error())
					return false
				}
				return matched
			},
		}
		err := server.ListenAndServe()
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

func buildPrompt(user string, serverName string) string {
	return fmt.Sprintf("%s@%s:~$ ", user, serverName)
}
