package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/creasty/defaults"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"time"
)

type Gocerts struct {
	Certs  []Cert `default:"[]" yaml:"certs"`
	Config Config `yaml:"config"`
}

func (g *Gocerts) UnmarshalYAML(unmarshal func(interface{}) error) error {
	defaults.Set(g)

	type plain Gocerts
	if err := unmarshal((*plain)(g)); err != nil {
		return err
	}

	return nil
}

type Cert struct {
	Cn  string   `default:"" yaml:"cn"`
	Dns []string `default:"[]" yaml:"dns"`
	Ips []string `default:"[]" yaml:"ips"`
}

func (c *Cert) UnmarshalYAML(unmarshal func(interface{}) error) error {
	defaults.Set(c)

	type plain Cert
	if err := unmarshal((*plain)(c)); err != nil {
		return err
	}

	return nil
}

type Config struct {
	Organization string `default:"SCC" yaml:"organization"`
	Country      string `default:"FR" yaml:"country"`
	Locality     string `default:"Nanterre" yaml:"locality"`
	Name         string `default:"github.com/arnoSCC/gocerts CA" yaml:"name"`
}

func (c *Config) UnmarshalYAML(unmarshal func(interface{}) error) error {
	defaults.Set(c)

	type plain Config
	if err := unmarshal((*plain)(c)); err != nil {
		return err
	}

	return nil
}

func bigIntHash(n *big.Int) []byte {
	h := sha1.New()
	h.Write(n.Bytes())
	return h.Sum(nil)
}

func generateCa(config Config) (*rsa.PrivateKey, *x509.Certificate, error) {
	fmt.Printf("Generating CA\n")
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(int64(time.Now().Year())),
		Subject: pkix.Name{
			Organization: []string{config.Organization},
			Country:      []string{config.Country},
			Locality:     []string{config.Locality},
			CommonName:   config.Name,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, err
	}
	caPEM, err := os.Create("ca.crt")
	if err != nil {
		return nil, nil, err
	}
	defer caPEM.Close()
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})
	caPrivKeyPEM, err := os.Create("ca.key")
	if err != nil {
		return nil, nil, err
	}
	defer caPrivKeyPEM.Close()
	pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})
	return caPrivKey, ca, nil
}

func generateCert(config Config, cn string, dns []string, ips []string, ca *x509.Certificate, pk *rsa.PrivateKey) error {
	fmt.Printf("Generating certificate for %v\n", cn)
	ipaddresses := make([]net.IP, 0)
	for _, ip := range ips {
		ipa := net.ParseIP(ip)
		if ipa != nil {
			ipaddresses = append(ipaddresses, ipa)
		}
	}
	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(int64(time.Now().Year())),
		Subject: pkix.Name{
			Organization: []string{config.Organization},
			Country:      []string{config.Country},
			Locality:     []string{config.Locality},
			CommonName:   cn,
		},
		IPAddresses:  ipaddresses,
		DNSNames:     dns,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: bigIntHash(certPrivKey.N),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, &certPrivKey.PublicKey, pk)
	if err != nil {
		return err
	}

	certPEM, err := os.Create(fmt.Sprintf("%v.crt", cn))
	if err != nil {
		return err
	}
	defer certPEM.Close()
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	certPrivKeyPEM, err := os.Create(fmt.Sprintf("%v.key", cn))
	if err != nil {
		return err
	}
	defer certPrivKeyPEM.Close()
	pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})
	return nil
}

func main() {
	certFile := "gocerts.yaml"
	content, err := ioutil.ReadFile(certFile)
	if err != nil {
		fmt.Printf("ERROR: %v not readable => %v\n", certFile, err)
		os.Exit(1)
	}
	gocerts := Gocerts{}
	err = yaml.Unmarshal([]byte(content), &gocerts)
	if err != nil {
		fmt.Printf("ERROR: %v not readable => %v\n", certFile, err)
		os.Exit(1)
	}
	pk, ca, err := generateCa(gocerts.Config)
	if err != nil {
		fmt.Printf("ERROR: not able to generate CA => %v\n", err)
		os.Exit(1)
	}
	for _, cert := range gocerts.Certs {
		if cert.Cn != "" {
			err = generateCert(gocerts.Config, cert.Cn, cert.Dns, cert.Ips, ca, pk)
			if err != nil {
				fmt.Printf("ERROR: not able to generate certificate for %v => %v\n", cert.Cn, err)
				os.Exit(1)
			}
		}
	}
}
