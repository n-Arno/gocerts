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
	"software.sslmate.com/src/go-pkcs12"
	"time"
)

// root structure of the yaml file
type Gocerts struct {
	Certs  []Cert `default:"[]" yaml:"certs"`
	Config Config `yaml:"config"`
}

// parse default values for root structure
func (g *Gocerts) UnmarshalYAML(unmarshal func(interface{}) error) error {
	defaults.Set(g)

	type plain Gocerts
	if err := unmarshal((*plain)(g)); err != nil {
		return err
	}

	return nil
}

// cert structure of the yaml file
type Cert struct {
	File string   `default:"" yaml:"file"`
	Cn   string   `default:"" yaml:"cn"`
	Dns  []string `default:"[]" yaml:"dns"`
	Ips  []string `default:"[]" yaml:"ips"`
	Ca   bool     `default:"false" yaml:"ca"`
}

// parse default values for cert structure
func (c *Cert) UnmarshalYAML(unmarshal func(interface{}) error) error {
	defaults.Set(c)

	type plain Cert
	if err := unmarshal((*plain)(c)); err != nil {
		return err
	}

	return nil
}

// config structure of the yaml file
type Config struct {
	Organization string `default:"SCC" yaml:"organization"`
	Country      string `default:"FR" yaml:"country"`
	Locality     string `default:"Nanterre" yaml:"locality"`
	Name         string `default:"github.com/arnoSCC/gocerts CA" yaml:"name"`
}

// parse default values for config structure
func (c *Config) UnmarshalYAML(unmarshal func(interface{}) error) error {
	defaults.Set(c)

	type plain Config
	if err := unmarshal((*plain)(c)); err != nil {
		return err
	}

	return nil
}

// generate CA
func generateCa(config Config) (*rsa.PrivateKey, *x509.Certificate, error) {
	fmt.Printf("Generating CA\n")
	// generate private key
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}
	// create certificate template
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
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
	// generate and self-sign certificate
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, err
	}
	// re-read certificate (a bit overkill, ca object could be used, but better play safe)
	caCert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		return nil, nil, err
	}
	// generate pfx from key and cert
	caPfxBytes, err := pkcs12.Encode(rand.Reader, caPrivKey, caCert, []*x509.Certificate{caCert}, pkcs12.DefaultPassword)
	if err != nil {
		return nil, nil, err
	}
	// encode and write certificate
	caPEM, err := os.Create("ca.crt")
	if err != nil {
		return nil, nil, err
	}
	defer caPEM.Close()
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})
	// encode and write key
	caPrivKeyPEM, err := os.Create("ca.key")
	if err != nil {
		return nil, nil, err
	}
	defer caPrivKeyPEM.Close()
	pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})
	// write pfx
	caPfx, err := os.Create("ca.pfx")
	if err != nil {
		return nil, nil, err
	}
	defer caPfx.Close()
	_, err = caPfx.Write(caPfxBytes)
	if err != nil {
		return nil, nil, err
	}
	return caPrivKey, caCert, nil
}

// generate a hash for certificate subject key id
func bigIntHash(n *big.Int) []byte {
	h := sha1.New()
	h.Write(n.Bytes())
	return h.Sum(nil)
}

// get first non empty string from a list
func firstNonEmpty(l []string) string {
	for _, s := range l {
		if s != "" {
			return s
		}
	}
	return ""
}

// generate certificate
func generateCert(config Config, c Cert, ca *x509.Certificate, pk *rsa.PrivateKey) error {
	// filename is either provided or CN
	fileName := firstNonEmpty([]string{c.File, c.Cn})
	fmt.Printf("Generating certificate for %v\n", fileName)
	// convert list of string ip to list of net.IP objects
	ipaddresses := make([]net.IP, 0)
	for _, ip := range c.Ips {
		ipa := net.ParseIP(ip)
		if ipa != nil {
			ipaddresses = append(ipaddresses, ipa)
		}
	}
	// generate private key
	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}
	// create certificate template
	keyUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	if c.Ca {
		keyUsage = keyUsage | x509.KeyUsageCertSign
	}
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization: []string{config.Organization},
			Country:      []string{config.Country},
			Locality:     []string{config.Locality},
			CommonName:   c.Cn,
		},
		IPAddresses:           ipaddresses,
		DNSNames:              c.Dns,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		SubjectKeyId:          bigIntHash(certPrivKey.N),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              keyUsage,
		IsCA:                  c.Ca,
		BasicConstraintsValid: true,
	}
	// generate and sign certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, &certPrivKey.PublicKey, pk)
	if err != nil {
		return err
	}
	// re-read signed certificate
	cert, err = x509.ParseCertificate(certBytes)
	if err != nil {
		return err
	}
	// generate pfx from key and cert
	certPfxBytes, err := pkcs12.Encode(rand.Reader, certPrivKey, cert, []*x509.Certificate{ca}, pkcs12.DefaultPassword)
	if err != nil {
		return err
	}
	// encode and write certificate
	certPEM, err := os.Create(fmt.Sprintf("%v.crt", fileName))
	if err != nil {
		return err
	}
	defer certPEM.Close()
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	// encode and write key
	certPrivKeyPEM, err := os.Create(fmt.Sprintf("%v.key", fileName))
	if err != nil {
		return err
	}
	defer certPrivKeyPEM.Close()
	pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})
	// write pfx
	certPfx, err := os.Create(fmt.Sprintf("%v.pfx", fileName))
	if err != nil {
		return err
	}
	defer certPfx.Close()
	_, err = certPfx.Write(certPfxBytes)
	if err != nil {
		return err
	}
	return nil
}

func main() {
	// hardcoded source file name
	certFile := "gocerts.yaml"
	// read content of file
	content, err := ioutil.ReadFile(certFile)
	if err != nil {
		fmt.Printf("ERROR: %v not readable => %v\n", certFile, err)
		os.Exit(1)
	}
	// parse yaml
	gocerts := Gocerts{}
	err = yaml.Unmarshal([]byte(content), &gocerts)
	if err != nil {
		fmt.Printf("ERROR: %v not readable => %v\n", certFile, err)
		os.Exit(1)
	}
	// generate ca
	pk, ca, err := generateCa(gocerts.Config)
	if err != nil {
		fmt.Printf("ERROR: not able to generate CA => %v\n", err)
		os.Exit(1)
	}
	// for each certificate "request" with a cn provided, generate certificate
	for _, cert := range gocerts.Certs {
		if cert.Cn != "" {
			err = generateCert(gocerts.Config, cert, ca, pk)
			if err != nil {
				fmt.Printf("ERROR: not able to generate certificate for %v => %v\n", firstNonEmpty([]string{cert.File, cert.Cn}), err)
				os.Exit(1)
			}
		}
	}
}
