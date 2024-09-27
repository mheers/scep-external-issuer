package signer

import (
	"encoding/pem"
	"testing"

	scepissuerapi "github.com/mheers/scep-external-issuer/api/v1alpha1"
	"github.com/stretchr/testify/require"

	"github.com/micromdm/scep/v2/cryptoutil/x509util"
)

var (
	csrCertManager = []byte(`
-----BEGIN CERTIFICATE REQUEST-----
MIIDDDCCAfQCAQAwKTERMA8GA1UEChMIamV0c3RhY2sxFDASBgNVBAMTC2V4YW1w
bGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA24WEMVcAMc0e
OhVAnv/vsR5UTLmnXd6lhwC11UIve5b84bqW7HNB3kXzFsEN4agjPuf1PLmZTsdS
fSco0tiCl4/VhaZT+I7jyExtya3p8TE23zsxO7spaEflNKIuHy0PdkCma/PUG8aW
LYz/z/dKl3tEloknLlb45IeFI6/MZZlayz8JYsrRbJXZAwlWCT+k51bRWR6uw5d/
6sMSJBUOCTpMQ2nSizOWQtgn8gLigmr5HjkNerBnYGRX1A7SUJ078knoBEtLoDrt
Tt0VBWc4oc67rxMgV/dMYzk+ewwqsI5PYHWgwPEpK9V2WPFTgDzCslKlxwghaqTk
yMY6NOxNHwIDAQABoIGdMIGaBgkqhkiG9w0BCQ4xgYwwgYkwWwYDVR0RBFQwUoIL
ZXhhbXBsZS5jb22CD3d3dy5leGFtcGxlLmNvbYcEwKgABYYsc3BpZmZlOi8vY2x1
c3Rlci5sb2NhbC9ucy9zYW5kYm94L3NhL2V4YW1wbGUwCwYDVR0PBAQDAgAAMB0G
A1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjANBgkqhkiG9w0BAQsFAAOCAQEA
c6LtWCakrv9qsZ7fKolP7l5rDTFSYoSukyDQJDVsENvUPgtgbxwRPciuJbbJdtwD
pgja6d2EJrGkuI4usBCQoDtLykW7phucDODJbWDgmY0VjLLTz8D+x2VOuQFuj+Ms
cLlH2ICNQOCQPNrFIR/JOUV6mexSvOIhwIFF7fRx//o/yS6PNH9dTDmlQ/9ENBhI
lOl28KuXSf3WtO8kUjlH6+fGufo+k0xIomT+TsPGX7GdQ2aGUqzuFwRvyD5vD8m1
MrJ/Bf4tL7hBJjcbKqBEKoG6DOTeduYfgQz7ATIM3BL4LiNFFHG6DR/5uBkYaqnL
QcfXImU787rSpUK6VvdepA==
-----END CERTIFICATE REQUEST-----
`)

	keyCertManager = []byte(`
-----BEGIN RSA PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC3xisif45B+ix6
Ma0gqN6gKRqIFP8pV6W77UtxxDuKwY6THNZ5+p57TorAsf1w1C95QSHCBcc2n0tR
5XwXxtbdaOb8Yon4Xa4+YpXfQxceQfzSESOokhDE8pa5WfSLqZHiSTRouhIssn+Y
Ra2LCL8jjbLdQKeSshz9MYfTsnzOg37tDV20HhOuAiQs18txGzzwCFumS5Q6Z/W/
sKOT91QPgArgzIkElX8srzqJsvLZRH0sBKLKlM1Ia4O94DYejCnW9G3iRuvnEud8
47B7HKKj3U5oDE2P9zeqM5/zHbGHNohFzcP91LNLQj47NPxXKhnOclHMTApTXtvA
kW1QIlenAgMBAAECggEBAJC3JNCN0eByuQOgiszlLirBM3tlzWko9AIA4yA7fwfN
VBDU7LAxgwtm1izX/NQUwy2g9IxtMGr7FbzwEcBHfHvuV7b3gd5rJwNJbuvZUSMq
o4RoqsPcAgiVX8ul4sT4S0D+lJ7Dp/w6s++dLwQFZz8AHpHMkCkcyWc40dULAO09
md9O4KwDDTz8I3zNNs1KNz63KgSkJgxOseW7XVm0Mj+DKo+kPV7H9EaHDUa9wEr3
MNk6gKiZd8q+JJyvlwnPu3Efmapy2cnbfCkNEcPtCzUV5XKqQVAsEmz/NVTK2Pxe
aCxoVWClErITmxuj0rmM6yxYFO+nF7UsdbRyOJZ7P0ECgYEA2pvS/kz8jXzFeHSd
PgUaWQVOHsoMLSX/le9/QsC4Iy923abShW8+kdq1GFLVatng3HSA3lFNmnsp/n8P
1hyINXIMlfSrP0+tlwLnsYUnIKT9j+r2TyXO/+4EVrp9LL/4Q81nWkJWr4OpwwX/
M2fCx8r4NKQMkJMG3CyVc7sOF90CgYEA1zUMf5JyeQ6L6ruZLisdjyXTE32wueXB
eSYzgX/dErJzt6EpDdiyOWbLaDAQfXAsSioa1Y/jJ1oamAqb5QVa4DDdeOAX3QWc
cehMlGeory9SiWOSGtscLj7QyZQOu0SbdkyWLvS0PvPP0H30rATLf5qdyINXhvHj
Wn00xvE+11MCgYAT3tgV31+RaMb2RPtJ+OLFNrM8HzduHycVNNjHc4cJQ7Y1PYWj
NVJlpZCSbm0Rsk47G6ffDVrVcN6HUHtbBernmL9GHiA2uAJaWJxAyY6d7AFURJIw
7YncP4FLdNYN7EEfwJrlXGROvdP/cxsYTBUrXeqjtkmiFosoFjFbfKQyTQKBgGRU
7SDEy+24ZG7pSz8FBuDoB4I8xRnGDe9Hahfj3tOKsvxXfGZiMqUkUYyfa/CvTVa+
Tohmbsa38VIVEB0z4+xFm9twzm9S4F8SqDFAKpqR+27mJwWyRW8iBgEUr9GK6Ne8
WQBHQYlf7fEL5/gSvDUfhpQm97WILDDR0rs1WdDVAoGAaCT1XL4a81YnGuWieb9k
iY8oG6QjOLL1kKzsvWIWqWoZC5wgTEB0TLSvulnsTdjjFbC4W8Ed/5YGjwotoB2l
alCrQ7NQ2vNsMBOPqcegYxtYSidUMnTF+dfCaVaCxpVVmWB6ph6uFflzhxNa7Akr
VqZUCQd1IEsA+Wv/29JFbLI=
-----END RSA PRIVATE KEY-----
	`)

	csrSCEP = []byte(`
-----BEGIN CERTIFICATE REQUEST-----
MIICpjCCAY4CAQAwSjELMAkGA1UEBhMCREUxFTATBgNVBAoTDGFjbWUtc2NlcC1j
YTEQMA4GA1UECxMHQUNNRSBDQTESMBAGA1UEAxMJbXktY2xpZW50MIIBIjANBgkq
hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuaAKumAuEepyahjDYKoLuCRsIFdPRwj+
a0gT7/mFSmXLyfb+EU0wtFLznW/BVouQE9T4pPJhvDzkQHBY/rK21i41cyG88bSx
k2S7q2H2t5Fqnp1Y1PHQMgLk5RiirJuYRxrI4RC5tOZOd8XOwx02nHmhWVnV3nvy
5Tvz4kKkELICx+aCQ8Xm1hr0Pit2ttDQZrCOwotODANW38R1D53KoR/RSFvwwDg8
jWjaRlvuXMmWfQsgwAVAnzS0E79R1lLNDmPDBGKsWI6G7ZUzcv0vm9RxkyHL+eb+
eFG3WPrOT2ggEUfmRFEGix8dfV6OZRgalQzLMghQmUmDFGfwMdrSWQIDAQABoBcw
FQYJKoZIhvcNAQkHMQgTBnNlY3JldDANBgkqhkiG9w0BAQsFAAOCAQEANOxgA5/z
iYObtTgF9KO2bcS1RaZIyXKeJLSt+aMxU+F2BpXaxzsShcb7shNpPoMRrmVRG/CT
VPHwLja3to2M64NtklAQmGPEQlgMyrxmyvV+68kl8mIRsRFkL82w+hrtMBuHYfnX
FOYvNksgw22Xx7HaPFYN1iwrtPYbvZkT3iYNfxyfMy/D8LBCaEK1/+K5XRjaKdq+
6ti6tAgIxgHw/JGdZ/9YWbXzUXgGkn45BMc8Sx4rLhvCGaKGWeur4KJ+GPzqGj1/
PQPxqde2xgyzMpGeAsvu+p9Yw6sQ5D/v6kIqqZdl9MUu8LmhIdsbvJUGliU3fYlF
ZBKjC0cx6CqQQA==
-----END CERTIFICATE REQUEST-----
`)

	csrOpenSSLWithChallange = []byte(`
-----BEGIN CERTIFICATE REQUEST-----
MIICpjCCAY4CAQAwGjEYMBYGA1UEAxMPd3d3LmV4YW1wbGUuY29tMIIBIjANBgkq
hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyUeTPGsimS0wc3zO+tgRfhg6nRfWXFJF
dMH/THkk4VyMIbjezicvptavi5W4cbbSkLfN+SJWQfuYLZ6tL4UF2x4rYsWDDqR/
xggK2QMc6l3Aza9SE8/E0bAFwwmQciAgoL4WoUTejWHsqGiVdCM/cwSO10VBvdtw
BIcuy3/INWdG2AZ/T1UIawr4qDQsKvmNcpO9sBjYPLViIyZYEq9hjz7oCYwSaRPd
8NdHFC8d3YyB07QOdDBWrae9BZoPCVnb39p7YKjP72pNCTKfRr8CWRfQqRItlKYd
h+LEpGw8qAi7fCJgIsDkPaZTv24uCy3WvbOlQxYBFXavh6L9fiC62QIDAQABoEcw
FQYJKoZIhvcNAQkHMQgTBnNlY3JldDAuBgkqhkiG9w0BCQ4xITAfMB0GA1UdEQEB
/wQTMBGCD3d3dy5leGFtcGxlLmNvbTANBgkqhkiG9w0BAQsFAAOCAQEAcdY9NwQM
7W9HnwwDEQyjghQnZ9D07sV9qhA9fSqg9/XkmxR1hg+tikIb8nmtrbm5eM4vH23k
KD3tvhCeAwO+p8EIIgB9fY7CTVecSXVVYly3Iv4wTvD6wuVx0h8N1l6KYqMsq+Wd
YkBFwdzx7fZTH5kG/d1gOeMf1GA+RYvdaKQry22sFs+5+GdnGrjaWaiGIFI9phdO
FofW26y+gVCPFh1wxloV3WA7HyRitza6P5IVVTBdODGsY9/crtda4Tnf+2jKDv6I
GVaH5Eb7wKRXr18Btyj1oaF9k6ZDovA7flAURpwYMdYBBhIZm2W+U8b8sBj5iANp
xuQZQXOkOAlxdQ==
-----END CERTIFICATE REQUEST-----	
`)

	csrOpenSSLWithoutChallange = []byte(`
-----BEGIN CERTIFICATE REQUEST-----
MIICjzCCAXcCAQAwGjEYMBYGA1UEAxMPd3d3LmV4YW1wbGUuY29tMIIBIjANBgkq
hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyUeTPGsimS0wc3zO+tgRfhg6nRfWXFJF
dMH/THkk4VyMIbjezicvptavi5W4cbbSkLfN+SJWQfuYLZ6tL4UF2x4rYsWDDqR/
xggK2QMc6l3Aza9SE8/E0bAFwwmQciAgoL4WoUTejWHsqGiVdCM/cwSO10VBvdtw
BIcuy3/INWdG2AZ/T1UIawr4qDQsKvmNcpO9sBjYPLViIyZYEq9hjz7oCYwSaRPd
8NdHFC8d3YyB07QOdDBWrae9BZoPCVnb39p7YKjP72pNCTKfRr8CWRfQqRItlKYd
h+LEpGw8qAi7fCJgIsDkPaZTv24uCy3WvbOlQxYBFXavh6L9fiC62QIDAQABoDAw
LgYJKoZIhvcNAQkOMSEwHzAdBgNVHREBAf8EEzARgg93d3cuZXhhbXBsZS5jb20w
DQYJKoZIhvcNAQELBQADggEBAG8QxEqCW5BgYH8zCRuun+x4MfIabZdmtDPNPfUc
Q1IoTTMFskCf1sYAByLPkF7VSl+j/jNGYP0iSVTapLO0y8M5FBQPJWA7z6HyWVK4
fZciBPfcmSkmR99EQl9gHpKvXT3X7T0voKN0tveO8XW5wam9uVVBoqG7Hmq7GWNN
8PR02mydFGSrNuCMMuHAE+WBgK4dJ043mWuyTEn277u7nOsk11vZqGEFdbrWQgwG
Hu7J1l2V/6gYkXqQDnF5GSLeLQkB+iiHKzJgdbdyE06zONVcb9doh326LaARqa03
S3YVcB3tiDe7jnZj3gkFA87KkTHC74xEGl840QSSU3tdiqw=
-----END CERTIFICATE REQUEST-----
`)
)

func TestSignScepSignerFromIssuerAndSecretData(t *testing.T) {
	issuerSpec := &scepissuerapi.SCEPIssuerSpec{
		URL:            "http://127.0.0.1:2016/scep",
		AuthSecretName: "can-be-ignored-here",
	}
	data := map[string][]byte{
		"challenge": []byte("secret"),
	}
	signer, err := ScepSignerFromIssuerAndSecretData(issuerSpec, data)
	require.Nil(t, err)
	require.NotNil(t, signer)

	csr, err := parseCSR(csrCertManager)
	require.Nil(t, err)

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr.Raw,
	})

	// csr := csrSCEP
	key, err := parseKeyPKCS8(keyCertManager)
	require.Nil(t, err)

	signed, err := signer.SignWithPrivateKey(csrPEM, key)
	require.Nil(t, err)
	require.NotNil(t, signed)
}

func TestReadChallenge(t *testing.T) {
	csr := csrOpenSSLWithChallange
	csrPEM, _ := pem.Decode(csr)
	csrDER := csrPEM.Bytes

	challenge, err := x509util.ParseChallengePassword(csrDER)
	require.Nil(t, err)
	require.NotNil(t, challenge)
}

func TestAddChallenge(t *testing.T) {
	// data preperation
	csr := csrCertManager
	csrData, _ := pem.Decode(csr)
	csrDER := csrData.Bytes

	key, err := parseKeyPKCS8(keyCertManager)
	require.Nil(t, err)

	// make sure the challenge is not there
	challenge, err := x509util.ParseChallengePassword(csrDER)
	require.Nil(t, err)
	require.Equal(t, "", challenge)

	// add challenge
	augmentedCSRPEM, err := AddChallenge(csrCertManager, "secret", key)
	require.Nil(t, err)

	// make sure the challenge is there
	augmentedCSRDER, _ := pem.Decode(augmentedCSRPEM)
	challenge, err = x509util.ParseChallengePassword(augmentedCSRDER.Bytes)
	require.Nil(t, err)
	require.Equal(t, "secret", challenge)
}
