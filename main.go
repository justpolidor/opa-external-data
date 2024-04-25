package main

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/justpolidor/opa-external-data/data"
	"github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/sigstore/pkg/signature"
)

const (
	timeout    = 3 * time.Second
	apiVersion = "externaldata.gatekeeper.sh/v1beta1"
)

func main() {
	if os.Getenv("IS_LOCAL") == "yes" {
		server := &http.Server{
			Addr: ":8443",
		}

		http.HandleFunc("/validate", validateHandler)

		log.Printf("Starting HTTPS server on %s...", server.Addr)
		if err := server.ListenAndServe(); err != nil {
			log.Fatalf("Failed to listen and serve: %v", err)
		}
	} else {
		certFile := "/etc/tls/tls.crt"
		keyFile := "/etc/tls/tls.key"

		caCert, err := os.ReadFile("/tmp/gatekeeper/ca.crt")
		if err != nil {
			panic(err)
		}

		clientCAs := x509.NewCertPool()
		clientCAs.AppendCertsFromPEM(caCert)

		if !clientCAs.AppendCertsFromPEM(caCert) {
			log.Fatalf("Failed to append Gatekeeper's CA certificate")
		}

		// Configure TLS settings
		tlsConfig := &tls.Config{
			ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs:  clientCAs,
			MinVersion: tls.VersionTLS13,
		}

		server := &http.Server{
			Addr:      ":9443",
			TLSConfig: tlsConfig,
		}

		http.HandleFunc("/validate", validateHandler)

		log.Printf("Starting HTTPS server on %s...", server.Addr)
		if err := server.ListenAndServeTLS(certFile, keyFile); err != nil {
			log.Fatalf("Failed to listen and serve: %v", err)
		}
	}
}

func validateHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	var providerRequest externaldata.ProviderRequest
	if err := json.NewDecoder(req.Body).Decode(&providerRequest); err != nil {
		log.Printf("Error while decoding the providerRequest: %v", err)
		sendResponse(nil, err.Error(), w)
		return
	}

	results, err := processAttestations(req.Context(), providerRequest.Request.Keys)
	if err != nil {
		log.Printf("Error while procesing the attesation: %v", err)
		sendResponse(nil, err.Error(), w)
		return
	}

	log.Printf("Sending response: %v", results)
	sendResponse(results, "", w)
}

func processAttestations(ctx context.Context, keys []string) ([]externaldata.Item, error) {
	results := []externaldata.Item{}
	verifier, err := loadPublicKeyVerifier()
	if err != nil {
		return nil, err
	}

	for _, key := range keys {
		ref, err := name.ParseReference(key)
		if err != nil {
			return appendError(results, key, fmt.Sprintf("Error parsing reference: %v", err))
		}

		verifiedAttestations, _, err := cosign.VerifyImageAttestations(ctx, ref, &cosign.CheckOpts{
			SigVerifier:   verifier,
			ClaimVerifier: cosign.IntotoSubjectClaimVerifier,
			IgnoreTlog:    true,
		})

		log.Printf("Verified attestations %#v ", verifiedAttestations)

		if err != nil {
			return appendError(results, key, fmt.Sprintf("Failed to verify attestation: %v", err))
		}

		attestations, err := cosign.FetchAttestationsForReference(ctx, ref, "https://cosign.sigstore.dev/attestation/vuln/v1")
		if err != nil {
			return appendError(results, key, fmt.Sprintf("Failed to fetch attestations: %v", err))
		}

		for _, attestation := range attestations {
			// After cosign attestation verification, check for critical vulnerabilities
			if hasCritical, critVulns := checkCriticalVulnerabilities(attestation); hasCritical {
				results = append(results, externaldata.Item{Key: key, Error: fmt.Sprintf("Found critical vulnerabilities: %v", critVulns)})
			} else {
				results = append(results, externaldata.Item{Key: key, Value: key + "_valid"})
			}
		}
	}
	return results, nil
}

func checkCriticalVulnerabilities(attestation cosign.AttestationPayload) (bool, []string) {
	decodedPayload, err := base64.StdEncoding.DecodeString(attestation.PayLoad)
	if err != nil {
		log.Printf("Error decoding base64 payload: %v", err)
		return false, nil
	}

	var payload data.AttestationPayload
	if err = json.Unmarshal(decodedPayload, &payload); err != nil {
		log.Printf("Error unmarshalling JSON payload: %v", err)
		return false, nil
	}

	var criticalVulns []string
	for _, result := range payload.Predicate.Scanner.Result.Results {
		for _, vulnerability := range result.Vulnerabilities {
			if vulnerability.Severity == "CRITICAL" {
				criticalVulns = append(criticalVulns, vulnerability.VulnerabilityID)
			}
		}
	}

	return len(criticalVulns) > 0, criticalVulns
}

func loadPublicKeyVerifier() (signature.Verifier, error) {
	var pubKeyBytes []byte
	var err error
	if os.Getenv("IS_LOCAL") == "yes" {
		pubKeyBytes, err = os.ReadFile("/Users/justinpolidori/.cosign/cosign.pub")
	} else {
		pubKeyBytes, err = os.ReadFile("/etc/cosign/cosign.pub")
	}
	if err != nil {
		return nil, fmt.Errorf("error reading public key file: %v", err)
	}
	// Decode the PEM block
	block, _ := pem.Decode(pubKeyBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing public key or incorrect type")
	}

	// Convert PEM block to *x509.Certificate
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing PKIX public key: %v", err)
	}

	// Create a Verifier using the public key
	verifier, err := signature.LoadVerifier(pubKey, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("failed to load verifier: %v", err)
	}

	return verifier, nil
}

func appendError(results []externaldata.Item, key, errorMsg string) ([]externaldata.Item, error) {
	results = append(results, externaldata.Item{
		Key:   key,
		Error: errorMsg,
	})
	return results, fmt.Errorf(errorMsg)
}

func sendResponse(results []externaldata.Item, systemErr string, w http.ResponseWriter) {
	response := externaldata.ProviderResponse{
		APIVersion: apiVersion,
		Kind:       "ProviderResponse",
	}

	if len(results) > 0 {
		response.Response.Items = results
	} else {
		response.Response.SystemError = systemErr
	}

	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Failed to encode response: %v", err)
	}
}
