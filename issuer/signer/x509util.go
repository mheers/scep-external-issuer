/*
Copyright 2020 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package signer

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/micromdm/scep/v2/cryptoutil/x509util"
)

func parseKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	// extract PEM from request object
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("PEM block type must be RSA PRIVATE KEY")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func parseKeyPKCS8(pemBytes []byte) (*rsa.PrivateKey, error) {
	// extract PEM from request object
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("PEM block type must be RSA PRIVATE KEY")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return key.(*rsa.PrivateKey), nil
}

func parseCert(pemBytes []byte) (*x509.Certificate, error) {
	// extract PEM from request object
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("PEM block type must be CERTIFICATE")
	}
	return x509.ParseCertificate(block.Bytes)
}

func parseCSR(pemBytes []byte) (*x509.CertificateRequest, error) {
	// extract PEM from request object
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("PEM block type must be CERTIFICATE REQUEST")
	}
	return x509.ParseCertificateRequest(block.Bytes)
}

func selfSign(priv *rsa.PrivateKey, csr *x509.CertificateRequest) (*x509.Certificate, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %s", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour * 1)
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "SCEP SIGNER",
			Organization: csr.Subject.Organization,
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(derBytes)
}

func AddChallenge(csrBytes []byte, challenge string, privateKey *rsa.PrivateKey) ([]byte, error) {
	csrPEM, _ := pem.Decode(csrBytes)
	csrX509, err := x509.ParseCertificateRequest(csrPEM.Bytes)
	if err != nil {
		return nil, err
	}

	challengeAlreadyPresent, err := x509util.ParseChallengePassword(csrPEM.Bytes)
	if err != nil {
		return nil, err
	}
	if challengeAlreadyPresent != "" {
		return nil, fmt.Errorf("challenge password already present in CSR")
	}

	randReader := rand.Reader

	tmpl := &x509util.CertificateRequest{
		CertificateRequest: *csrX509,
		ChallengePassword:  challenge,
	}

	csrDER, err := x509util.CreateCertificateRequest(randReader, tmpl, privateKey)
	if err != nil {
		return nil, err
	}

	challengeInjected, err := x509util.ParseChallengePassword(csrDER)
	if err != nil {
		return nil, err
	}
	if challenge != challengeInjected {
		return nil, fmt.Errorf("challenge password not injected into CSR")
	}

	csrPEMResult := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	return csrPEMResult, nil
}
