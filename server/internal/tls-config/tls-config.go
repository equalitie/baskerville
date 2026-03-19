package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"os"
	"path/filepath"
	"strconv"
)

func getCertificatePath(envVar string) string {
	path := os.Getenv(envVar)
	if path == "" {
		log.Fatalf("Expected %s to be non empty, got ''", envVar)
	}

	if filepath.IsAbs(path) {
		return path
	}
	workingDirectory, err := os.Getwd()
	if err != nil {
		log.Panicf("Unable to find working directory: %v", err)
	}
	return filepath.Join(workingDirectory, path)
}

func CreateKafkaTLSConfig() *tls.Config {
	caCertPath := getCertificatePath("CA_CERT_PATH")
	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		log.Panicf("Unable to read CA cert file: %v", err)
	}
	certPath := getCertificatePath("CERT_PATH")
	cert, err := os.ReadFile(certPath)
	if err != nil {
		log.Panicf("Unable to read cert file: %v", err)
	}
	keyPath := getCertificatePath("KEY_PATH")
	key, err := os.ReadFile(keyPath)
	if err != nil {
		log.Panicf("Unable to read key file: %v", err)
	}

	keyPair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		log.Panicf("Unable to create key pair: %v", err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	skipInsecureVerify, _ := strconv.ParseBool(os.Getenv("SKIP_INSECURE_VERIFY"))

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{keyPair},
		RootCAs:            caCertPool,
		InsecureSkipVerify: skipInsecureVerify, //Development only
	}

	if tlsConfig.InsecureSkipVerify {
		log.Println("WARNING: InsecureSkipVerify is true, DO NOT USE IN PRODUCTION")
	}

	return tlsConfig
}
