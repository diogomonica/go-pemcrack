// Showcases the insuficient validation of encrypted PEM decoding in go.
// http://golang.org/pkg/encoding/pem/#Decode returns successfully with
// invalid passwords for the encrypted PEM blob.
//
// The password for the encrypted PEM file in privateKeyString is
// "omgomgponies"
// This can be verified using openssl:
// openssl rsa -in private.pem -outform PEM -pubout -out public.pem
package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

var privateKeyString = `
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,68CA28419ADC598B

0ro1rMiglCY/LVpL4nC3/+JvfcmE84nx317uz1+uXzu5Y+OXxekejTWZrk7hWBeA
chl8anQM8zPEZ+sJ13qMWH+1lUbbd/5ZsCpOlERkgDrut8yHEKkRFRj5MQtrg1Vn
eEpd0B7P2UD1ctJb0T8uBo1hhzFyxDI8sG47fSYU/oTnBqqofTom8S+lXPBvKZEm
LcU9ZuJg6M9Q1HO1D3uIbjEGlYP9VH8AZpEdMpcJDnbCZxJ+FBufuq5pIBiHwQW8
SuDoc47iliArbymlbq8ple7rsXxUrzvjjqYKFUz/0DsLeaJLt1CL1dcke3w1sMNS
Gy+//b+/Q255lZ94MgYj7ag7zLoCnoEr4AXItKD7mgqDQ7BuCa/UCiW/M9+r+V5Z
MKoE2SEN2BDZSEc53RD2eXKDn1OtwLnNd36dpbHaSqtVPQ6QJDIQKo/GXo/sTVst
AEFCJYBHmrwFw3YNKtCywBmUieeQeHPhooCzoGaXQf8kb5bVoJT5YxlK0lQNV9TQ
lDoim27w11aJMwQg9RCdl3/rHpmnkpiFFFKx3IYGhQko5QrBRmZ67IJUGbgj31/w
q448ZR3s5sIoREaHfGW5XpQA8s2wj88TFm5K4vxoGrMwJeZBQG61/1InAGRC8dX4
jwZS7qB/eWLWr6HalY2yi4G/12TJB84yRCnIlFFnbUU9oLJ3xPhhehdqlS9YsARX
awvJTb58ZTo68wN7UKBEw/yz/pKrtCBTMtnIJ9khfhTHnUI18wf7a1KBYv2iZZzp
4jhVaCDOFPv70ydRkoURJTRXyMpTAtAyflLPRNNkvtFMzzLst7Ex367xcAg2af9+
7UYdrIp0q8JOClCdzNkb6+Iy00G2HBAyCfhnf8TupU8SCADNjRReGUzioWOIRu24
TnX8o6fv2G8wGHANJfrS2BGmtBOWW3wdo08WScyCxKQ/lrHMhKW+xeZ+UqCgKfiT
AHKagheEH1+nm0RDZzII0hDDVGLUzZzT6DGrYp5xW5WgOJHDTZCU4dEyZ30N2wkJ
FI2dEGx3lY/YmE7X4knE7UXccjHNJq7NmCbhLzeFfT38FNCwraWIxbRVpdeHClAx
dSYENqn04wER4bSXRsfF9fcDrjAGtb1CGk0PPoEs0D0OoYpyyLVgWw+qnxBMKuvz
5z+mSBDJ8QMybC3x7SOF/kdXsIyXUqknInaUBzJ5qOigRVD+/g4VjZoRtD/eeM4X
mpKtZ4THx9WYz0ZeJijYwUeYBrGt0kglwf/VrMZFSTeYTvxm5BmDkf8+jRB09mV0
YcPPuqGeJvcgrAJqUJ0iny1SyagpSJp4wPFwTYd9xOxjBJzYWgafCfaEdrLpAUSk
YvAVmfVhj591LWzg7r2pATK4Zi75E4nBRORcOlAqyea2zibfKYI0kmtZw8JRj9IL
u3N5piXDAqgQlGqoY2y+GgvMk4vFhF/SO/ZeQaUplYG0XMQlViArE5n/2bIY4Jh4
h4vl6GSXvOWYEhi4NmF0kY34ABmfxbcS8Sngym+tYGPWUb4t+o74DzYvGl+rJ/9Z
lOb1XwXRJvKsaHMI7ujCRu3nhqVgsRlTjCIkWExc5/MnK5leiUVWLHmsfLqC3Kht
-----END RSA PRIVATE KEY-----
`

func checkPassword(pem *pem.Block, password string) {
	key, err := x509.DecryptPEMBlock(pem, []byte(password))
	if err == nil {
		validKey := false
		_, err = x509.ParsePKCS8PrivateKey(key)
		if err == nil {
			validKey = true
		}

		_, err = x509.ParsePKCS1PrivateKey(key)
		if err == nil {
			validKey = true
		}

		if validKey == true {
			fmt.Println("Valid password found: " + password)
		}
	}
}

func main() {
	decodedPEM, _ := pem.Decode([]byte(privateKeyString))

	checkPassword(decodedPEM, "ruvf")
	checkPassword(decodedPEM, "omgomgponies")
}
