package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var (
	caCert     = os.Getenv("CA_CERT")
	clientCert = os.Getenv("CLIENT_CERT")
	clientKey  = os.Getenv("CLIENT_KEY")
	endpoint   = os.Getenv("ENDPOINT")
)

func main() {
	caCert, err := os.ReadFile(caCert)
	if err != nil {
		log.Fatalf("Unable to read CA cert: %v", err)
	}

	// Append the client certificates from CA
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Load client's certificate and private key
	clientCert, err := tls.LoadX509KeyPair(clientCert, clientKey)
	if err != nil {
		log.Fatalf("Unable to load client cert and key: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{clientCert},
		RootCAs:            caCertPool,
		InsecureSkipVerify: false,
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	client := &http.Client{Transport: transport}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
			resp, err := client.Get(fmt.Sprintf("%s?count=10", endpoint))
			if err != nil {
				fmt.Println(err)
				continue
			}
			data, err := io.ReadAll(resp.Body)
			if err != nil {
				fmt.Println(err)
				continue
			}
			var prettyJSON bytes.Buffer
			if err := json.Indent(&prettyJSON, data, "", "\t"); err != nil {
				fmt.Println(err)
				continue
			}
			fmt.Println(prettyJSON.String())
			resp.Body.Close()
		}
	}
}
