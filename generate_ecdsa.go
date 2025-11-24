package main

import (
	"crypto/rand"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"crypto/elliptic"
	"fmt"
	"os"
	"time"
	"bytes"
	"math/big"
	"crypto/x509/pkix"
)

func WriteECDSAKeys(caPrivKey *ecdsa.PrivateKey, pubKeyFilename string,
	privKeyFilename string) error {

	pubFile, err := os.Create(pubKeyFilename)
	if err != nil {
		return err
	}
	defer pubFile.Close()

	caPubKeyBytes, err := x509.MarshalPKIXPublicKey(&caPrivKey.PublicKey)
	if err != nil {
		return err
	}
	
	caPubKeyPEM := new(bytes.Buffer)
	pem.Encode(caPubKeyPEM, &pem.Block{
		Type: "ECDSA PUBLIC KEY",
		Bytes: caPubKeyBytes,
	})

	_, err = pubFile.Write(caPubKeyPEM.Bytes())
	if err != nil {
		return err
	}

	privFile, err := os.Create(privKeyFilename)
	if err != nil {
		return err
	}
	defer privFile.Close()

	caPrivateKeyBytes, err := x509.MarshalECPrivateKey(caPrivKey)
	if err != nil {
		return err
	}
	
	caPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(caPrivKeyPEM, &pem.Block{
		Type: "ECDSA PRIVATE KEY",
		Bytes: caPrivateKeyBytes,
	})

	_, err = privFile.Write(caPrivKeyPEM.Bytes())
	if err != nil {
		return err
	}

	os.Chmod(privKeyFilename, 0600)
	return nil
}

func WriteX509Cert(caBytes []byte, certFilename string) error {

	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type: "CERTIFICATE",
		Bytes: caBytes,
	})

	file, err := os.Create(certFilename)
	if err != nil {
		return err
	}

	_, err = file.Write(caPEM.Bytes())
	if err != nil {
		return err
	}

	return nil
}

func main() {

	//
	// ECDSA keys
	//
	
	caPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating ECDSA key: %s", err)
		return
	}

	err = WriteECDSAKeys(caPrivKey, "public.pem", "private.key");
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing ECDSA keys")
		return
	}

	//
	// X509 Certificate
	//

	ca := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()), // unique identifier
		Subject: pkix.Name{
			Organization: []string{"Example Issuer"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(10, 0, 0),
		IsCA:      true,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// Self signed certificate
	caBytes, err := x509.CreateCertificate(rand.Reader, &ca, &ca,
		&caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating x509 certificate: %s", err)
		return
	}

	err = WriteX509Cert(caBytes, "cert.crt")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing X509 cert: %s", err)
		return
	}
	
	return
}
