package signer

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-logr/logr"
	scepissuerapi "github.com/mheers/scep-external-issuer/api/v1alpha1"
	"github.com/pkg/errors"

	scepclient "github.com/micromdm/scep/v2/client"
	"github.com/micromdm/scep/v2/scep"
)

const (
	certificatePEMBlockType = "CERTIFICATE"
	csrPEMBlockType         = "CERTIFICATE REQUEST"
)

func ScepSignerFromIssuerAndSecretData(issuerSpec *scepissuerapi.SCEPIssuerSpec, data map[string][]byte) (Signer, error) {
	challenge := string(data["challenge"])
	return &scepSigner{
		URL:       issuerSpec.URL,
		Challenge: challenge,
	}, nil
}

type scepSigner struct {
	URL       string
	Challenge string
	Log       logr.Logger
}

func (o *scepSigner) Check() error {
	return nil
}

func (o *scepSigner) SignWithPrivateKey(csrBytes []byte, key *rsa.PrivateKey) ([]byte, error) {
	// // mkdir
	// err := os.MkdirAll("/tmp/csr", 0755)
	// if err != nil {
	// 	return nil, err
	// }

	// // writes csr to file
	// csrFile, err := os.Create(fmt.Sprintf("/tmp/csr/%s.pem", time.Now().Format("2006-01-02_15:04:05")))
	// if err != nil {
	// 	return nil, errors.Wrap(err, "failed to create csr file")
	// }
	// defer csrFile.Close()
	// csrFile.Write(csrBytes)

	ctx := context.Background()
	logger := log.NewJSONLogger(log.NewSyncWriter(os.Stdout))

	csr, err := AddChallenge(csrBytes, o.Challenge, key)
	if err != nil {
		return nil, err
	}

	csrAugmented, err := parseCSR(csr)
	if err != nil {
		return nil, err
	}

	signerCert, err := signCSR(key, csrAugmented)
	if err != nil {
		return nil, err
	}

	// create a client connection to the scep server
	client, err := scepclient.New(o.URL, logger)
	if err != nil {
		return nil, err
	}

	caCertMsg := "" // TODO: message sent with GetCACert operation
	resp, certNum, err := client.GetCACert(ctx, caCertMsg)
	if err != nil {
		return nil, err
	}

	var certs []*x509.Certificate
	{
		if certNum > 1 {
			certs, err = scep.CACerts(resp)
			if err != nil {
				return nil, err
			}
		} else {
			certs, err = x509.ParseCertificates(resp)
			if err != nil {
				return nil, err
			}
		}
	}

	// var msgType scep.MessageType
	// {
	// 	// TODO validate CA and set UpdateReq if needed
	// 	if cert != nil {
	// 		msgType = scep.RenewalReq
	// 	} else {
	// 		msgType = scep.PKCSReq
	// 	}
	// }

	var msgType scep.MessageType = scep.PKCSReq
	// signerCert := cert

	// generate a signer certificate request

	tmpl := &scep.PKIMessage{
		MessageType: msgType,
		Recipients:  certs,
		SignerKey:   key,
		SignerCert:  signerCert,
	}

	if o.Challenge != "" && msgType == scep.PKCSReq {
		tmpl.CSRReqMessage = &scep.CSRReqMessage{
			ChallengePassword: o.Challenge,
		}
	}

	// TODO: maybe pass also a scep.WithCertsSelector(cfg.caCertsSelector) option
	msg, err := scep.NewCSRRequest(csrAugmented, tmpl, scep.WithLogger(logger))
	if err != nil {
		return nil, errors.Wrap(err, "creating csr pkiMessage")
	}

	var respMsg *scep.PKIMessage

	for {
		// loop in case we get a PENDING response which requires
		// a manual approval.

		respBytes, err := client.PKIOperation(ctx, msg.Raw)
		if err != nil {
			return nil, errors.Wrapf(err, "PKIOperation for %s", msgType)
		}

		respMsg, err = scep.ParsePKIMessage(respBytes, scep.WithLogger(logger), scep.WithCACerts(msg.Recipients))
		if err != nil {
			return nil, errors.Wrapf(err, "parsing pkiMessage response %s", msgType)
		}

		switch respMsg.PKIStatus {
		case scep.FAILURE:
			return nil, errors.Errorf("%s request failed, failInfo: %s", msgType, respMsg.FailInfo)
		case scep.PENDING:
			logger.Log("pkiStatus", "PENDING", "msg", "sleeping for 30 seconds, then trying again.")
			time.Sleep(30 * time.Second)
			continue
		}
		logger.Log("pkiStatus", "SUCCESS", "msg", "server returned a certificate.")
		break // on scep.SUCCESS
	}

	if err := respMsg.DecryptPKIEnvelope(signerCert, key); err != nil {
		return nil, errors.Wrapf(err, "decrypt pkiEnvelope, msgType: %s, status %s", msgType, respMsg.PKIStatus)
	}

	respCert := respMsg.CertRepMessage.Certificate

	return pemCert(respCert.Raw), nil
}

func (o *scepSigner) Sign(csrBytes []byte) ([]byte, error) {
	// generate a random rsa2048 key for the SCEP client
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	return o.SignWithPrivateKey(csrBytes, key)
}

func pemCert(derBytes []byte) []byte {
	pemBlock := &pem.Block{
		Type:    certificatePEMBlockType,
		Headers: nil,
		Bytes:   derBytes,
	}
	out := pem.EncodeToMemory(pemBlock)
	return out
}

func signCSR(priv *rsa.PrivateKey, csr *x509.CertificateRequest) (*x509.Certificate, error) {
	self, err := selfSign(priv, csr)
	if err != nil {
		return nil, err
	}
	return self, nil
}
