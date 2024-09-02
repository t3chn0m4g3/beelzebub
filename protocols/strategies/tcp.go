package strategies

import (
	"fmt"
	"github.com/mariocandela/beelzebub/v3/parser"
	"github.com/mariocandela/beelzebub/v3/tracer"
	"io"
	"net"
	"os"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

type TCPStrategy struct {
}

func (tcpStrategy *TCPStrategy) Init(beelzebubServiceConfiguration parser.BeelzebubServiceConfiguration, tr tracer.Tracer) error {
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

	listen, err := net.Listen("tcp", beelzebubServiceConfiguration.Address)
	if err != nil {
		log.Errorf("Error during init TCP Protocol: %s", err.Error())
		return err
	}

	go func() {
		for {
			if conn, err := listen.Accept(); err == nil {
				go func() {
					conn.SetDeadline(time.Now().Add(time.Duration(beelzebubServiceConfiguration.DeadlineTimeoutSeconds) * time.Second))
					conn.Write([]byte(fmt.Sprintf("%s\n", beelzebubServiceConfiguration.Banner)))

					buffer := make([]byte, 1024)
					command := ""

					if n, err := conn.Read(buffer); err == nil {
						command = string(buffer[:n])
					}

					src_ip, src_port, _ := net.SplitHostPort(conn.RemoteAddr().String())

					log.WithFields(log.Fields{
						"message":		"New TCP attempt",
						"protocol":		tracer.TCP.String(),
						"command":		command,
						"status":		tracer.Stateless.String(),
						"src_ip":		src_ip,
						"src_port":		src_port,
						"session":		uuid.New().String(),
						"service":		beelzebubServiceConfiguration.Description,
					}).Info("New TCP attempt")
					conn.Close()
				}()
			}
		}
	}()

	log.WithFields(log.Fields{
		"port":   beelzebubServiceConfiguration.Address,
		"banner": beelzebubServiceConfiguration.Banner,
	}).Infof("Init service %s", beelzebubServiceConfiguration.Protocol)
	return nil
}
