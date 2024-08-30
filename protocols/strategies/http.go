package strategies

import (
	"fmt"
	"github.com/mariocandela/beelzebub/v3/parser"
	"github.com/mariocandela/beelzebub/v3/plugins"
	"github.com/mariocandela/beelzebub/v3/tracer"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
    "time"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

type HTTPStrategy struct {
	beelzebubServiceConfiguration parser.BeelzebubServiceConfiguration
}

func (httpStrategy HTTPStrategy) Init(beelzebubServiceConfiguration parser.BeelzebubServiceConfiguration, tr tracer.Tracer) error {
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

	httpStrategy.beelzebubServiceConfiguration = beelzebubServiceConfiguration
	serverMux := http.NewServeMux()

	serverMux.HandleFunc("/", func(responseWriter http.ResponseWriter, request *http.Request) {
		traceRequest(request, tr, beelzebubServiceConfiguration.Description)
		for _, command := range httpStrategy.beelzebubServiceConfiguration.Commands {
			matched, err := regexp.MatchString(command.Regex, request.RequestURI)
			if err != nil {
				log.Errorf("Error regex: %s, %s", command.Regex, err.Error())
				continue
			}

			if matched {
				responseHTTPBody := command.Handler

				if command.Plugin == plugins.LLMPluginName {

					llmModel, err := plugins.FromStringToLLMModel(beelzebubServiceConfiguration.Plugin.LLMModel)

					if err != nil {
						log.Errorf("Error fromString: %s", err.Error())
						responseHTTPBody = "404 Not Found!"
					}

					llmHoneypot := plugins.LLMHoneypot{
						Histories:		make([]plugins.Message, 0),
						OpenAIKey:		beelzebubServiceConfiguration.Plugin.OpenAISecretKey,
						Protocol:		tracer.HTTP,
						Host:			beelzebubServiceConfiguration.Plugin.Host,
						Model:			llmModel,
						OllamaModel:	beelzebubServiceConfiguration.Plugin.OllamaModel,
					}

					llmHoneypotInstance := plugins.InitLLMHoneypot(llmHoneypot)

					command := fmt.Sprintf("%s %s", request.Method, request.RequestURI)

					if completions, err := llmHoneypotInstance.ExecuteModel(command); err != nil {
						log.Errorf("Error ExecuteModel: %s, %s", command, err.Error())
						responseHTTPBody = "404 Not Found!"
					} else {
						responseHTTPBody = completions
					}

				}

				setResponseHeaders(responseWriter, command.Headers, command.StatusCode)
				fmt.Fprintf(responseWriter, responseHTTPBody)
				break
			}
		}
	})
	go func() {
		err := http.ListenAndServe(httpStrategy.beelzebubServiceConfiguration.Address, serverMux)
		if err != nil {
			log.Errorf("Error during init HTTP Protocol: %s", err.Error())
			return
		}
	}()

	log.WithFields(log.Fields{
		"port":     beelzebubServiceConfiguration.Address,
		"commands": len(beelzebubServiceConfiguration.Commands),
	}).Infof("Init service: %s", beelzebubServiceConfiguration.Description)
	return nil
}

func traceRequest(request *http.Request, tr tracer.Tracer, HoneypotDescription string) {
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

	bodyBytes, err := io.ReadAll(request.Body)
	body := ""
	if err == nil {
		body = string(bodyBytes)
		request.Body = io.NopCloser(strings.NewReader(body))

	}
	src_ip, src_port, _ := net.SplitHostPort(request.RemoteAddr)

	log.WithFields(log.Fields{
		"info":				"HTTP New request",
		"request_uri":		request.RequestURI,
		"protocol":			tracer.HTTP.String(),
		"request_method":	request.Method,
		"body":				body,
		"hostname":			request.Host,
		"userAgent":		request.UserAgent(),
		"request_cookies":	mapCookiesToString(request.Cookies()),
		"request_headers":	mapHeaderToString(request.Header),
		"status":			tracer.Stateless.String(),
		"src_ip":			src_ip,
		"src_port":			src_port,
		"id":				uuid.New().String(),
		"service":			HoneypotDescription,
	}).Info("HTTP New request")
}

func mapHeaderToString(headers http.Header) string {
	headersString := ""

	for key := range headers {
		for _, values := range headers[key] {
			headersString += fmt.Sprintf("[Key: %s, values: %s],", key, values)
		}
	}

	return headersString
}

func mapCookiesToString(cookies []*http.Cookie) string {
	cookiesString := ""

	for _, cookie := range cookies {
		cookiesString += cookie.String()
	}

	return cookiesString
}

func setResponseHeaders(responseWriter http.ResponseWriter, headers []string, statusCode int) {
	for _, headerStr := range headers {
		keyValue := strings.Split(headerStr, ":")
		if len(keyValue) > 1 {
			responseWriter.Header().Add(keyValue[0], keyValue[1])
		}
	}
	// http.StatusText(statusCode): empty string if the code is unknown.
	if len(http.StatusText(statusCode)) > 0 {
		responseWriter.WriteHeader(statusCode)
	}
}
