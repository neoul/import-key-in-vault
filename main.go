package main

import (
	"bytes"
	"crypto/aes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"

	"github.com/google/tink/go/kwp/subtle"
	// "github.com/google/tink/go/kwp/subtle"
)

func main() {
	// [willing] Generate an importing ed25519 keypair.
	reader := rand.Reader
	bitSize := 2048
	ed25519PublicKey, ed25519PrivateKey, err := ed25519.GenerateKey(reader)
	fmt.Printf("ed25519PublicKey %d %x\n", len(ed25519PublicKey), ed25519PublicKey)
	fmt.Printf("ed25519PrivateKey %d %x\n", len(ed25519PrivateKey), ed25519PrivateKey)
	fmt.Printf("err %v\n", err)

	// [willing] Generate an RSA keypair that imitates a Vault import key.
	// The keypair will be used to test the Vault key import mechanism.
	rsaPrivateKey, err := rsa.GenerateKey(reader, bitSize)
	fmt.Printf("rsaPrivateKey %x\n", rsaPrivateKey)
	fmt.Printf("err %v\n", err)
	fmt.Printf("rsaPrivateKey.PublicKey %x\n", rsaPrivateKey.PublicKey)

	// [willing] Check how to encode the PEM format of the Vault public key.
	// It will simulate and verify the Vault import key format.
	publickey := &rsaPrivateKey.PublicKey
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publickey)
	fmt.Printf("publicKeyBytes %x\n", publicKeyBytes)
	fmt.Printf("err %v\n", err)
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	publicKeyEncodedToPem := pem.EncodeToMemory(publicKeyBlock)
	fmt.Printf("publicKeyEncodedToPem\n%s\n", publicKeyEncodedToPem)
	wrappingKeyString := string(publicKeyEncodedToPem)

	// [willing] You have to take a RSA public key from a Vault server if you want to import your keypair.
	// wrappingKey is provided by Vault
	// 	wrappingKeyString = `
	// -----BEGIN PUBLIC KEY-----
	// MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA/RoHfrn3mxZFKQ51hUY2
	// JoqvaSiTfOMMbbz/a1dfqb5Wwor53D+d1V5slf54twE0vJCkOP4FvlontJ6C7dwx
	// y0Pl8VLlFz0YIB7Dpx2gffQYF82Ko55QbPWCuSKqR7Tr+nHMi3Gp07xzsEs8Qubh
	// vAJ1/1dYXaz9MQdtopnBfuvr15W9TLe6/hrpuyDjVc5/b7TsTlCgrDmkBMAfhVeB
	// QFNOWm5j4bafZOLb7h5u6bXXUgtVG7iLIcQzc/8U1TYclFGIrVxd+jHayno1LLVp
	// AzJcy5DzCw3+PIJjEMIDZxtXzlnzqIYQJw3w2N7sJLJ1LQGgqlW66ejuL3xsBw/5
	// FPxdGnjY5HrykqxpMqG3xqTAZpJS6BwU/v7ld6EDAwJIBWVTTd74fOSycmd+Zq95
	// fIZPQryq/9LbV1kzH4YFrKpPhoTTHf6rhowSQLhOIFNbCvjVNwGhLeM+BwRa1Nyj
	// u5XG+2l+yCBIqUS/57FWbZygSma3YDkqIJN2wYsM5bp2QIx1k+FfIno97QEZl+66
	// +AFLW5xDqyjLjITlWzLFsOHh+4ysMZYmRpN45MrAFqW54VpPPka8SeFyIQgXEDdw
	// aC3hCznnjZCLnrl9/jB+SxQHWPujFU91wI7XxaJAVKxWw0kigSb6dpGJnVEouQyf
	// 5mhIEL204GM/b2iU6qlxYzcCAwEAAQ==
	// -----END PUBLIC KEY-----
	// `

	// [willing] Decode the PEM format to the raw bytes key (DES).
	// This public key will be used to encrypt an ephemeral AES key and send it to the vault server.
	// The Vault server will receive and decrypt the ehpemeral AES key on it in further work.
	keyBlock, _ := pem.Decode([]byte(wrappingKeyString))
	parsedKey, err := x509.ParsePKIXPublicKey(keyBlock.Bytes)
	wrappingKey := parsedKey.(*rsa.PublicKey)
	fmt.Printf("wrappingKey %v\n", parsedKey)
	fmt.Printf("err %v\n", err)

	// [willing] Generate an ephemeral AES key for two phases key wrapping.
	// 1st wrapping - encrypt the targetKey by by the ephemeralAESKey
	// 2nd wrapping - encrypt the ephemeralAESKey by wrappingKey (Vault import key)
	ephemeralAESKey := make([]byte, 32)
	_, err = rand.Read(ephemeralAESKey)

	fmt.Printf("ephemeralAESKey %v\n", ephemeralAESKey)
	fmt.Printf("err %v\n", err)

	// Test to encrypt and decrypt a message by the ephemeral AES key.
	aesCipherBlock, err := aes.NewCipher(ephemeralAESKey)
	fmt.Printf("aesCipherBlock %v\n", aesCipherBlock)
	fmt.Printf("aesCipherBlock.BlockSize() %v\n", aesCipherBlock.BlockSize())
	fmt.Printf("err %v\n", err)

	plaintext := "This is a secret .."
	ciphertext := make([]byte, len(plaintext))
	aesCipherBlock.Encrypt(ciphertext, []byte(plaintext))
	fmt.Println("ciphertext", hex.EncodeToString(ciphertext))
	plaintext2 := make([]byte, len(plaintext))
	aesCipherBlock.Decrypt(plaintext2, []byte(ciphertext))
	fmt.Println("plaintext2", string(plaintext2))

	// Encrypt the targetKey by ephemeralAESKey
	wrapKWP, err := subtle.NewKWP(ephemeralAESKey)
	fmt.Printf("wrapKWP %v\n", wrapKWP)
	fmt.Printf("err %v\n", err)
	wrappedTargetKey, err := wrapKWP.Wrap(ed25519PrivateKey)
	fmt.Printf("wrappedTargetKey %x\n", wrappedTargetKey)
	fmt.Printf("err %v\n", err)

	// The encrypted (wrapped) target key verification
	unwrappedTargetKey, err := wrapKWP.Unwrap(wrappedTargetKey)
	fmt.Printf("unwrappedTargetKey %x\n", unwrappedTargetKey)
	fmt.Printf("err %v\n", err)
	res := bytes.Compare(ed25519PrivateKey, unwrappedTargetKey)
	fmt.Println("compare ed25519PrivateKey and unwrappedTargetKey", res == 0)

	// encrypt ephemeralAESKey by wrappingKey (RSA public key)
	wrappedAESKey, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		wrappingKey,
		ephemeralAESKey,
		[]byte{},
	)
	fmt.Printf("wrappedAESKey %x\n", wrappedAESKey)
	fmt.Printf("err %v\n", err)

	// The encrypted (wrapped) ephemeral AES key verification
	unwrappedAESKey, err := rsa.DecryptOAEP(
		sha256.New(),
		rand.Reader,
		rsaPrivateKey,
		wrappedAESKey,
		[]byte{},
	)
	fmt.Printf("unwrappedAESKey %x\n", unwrappedAESKey)
	fmt.Printf("err %v\n", err)
	res = bytes.Compare(ephemeralAESKey, unwrappedAESKey)
	fmt.Println("compare ephemeralAESKey and unwrappedAESKey", res == 0)

	fmt.Println("len(wrappedAESKey), len(wrappedTargetKey)", len(wrappedAESKey), len(wrappedTargetKey))
	combinedCiphertext := append(wrappedAESKey, wrappedTargetKey...)
	fmt.Println(combinedCiphertext)
	fmt.Println(len(combinedCiphertext))
	base64Ciphertext := base64.StdEncoding.EncodeToString(combinedCiphertext)
	fmt.Println(base64Ciphertext)
	fmt.Println(len(base64Ciphertext))
}
