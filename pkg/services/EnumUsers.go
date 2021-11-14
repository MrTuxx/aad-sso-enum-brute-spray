package services

import (
	"aad-sso-enum-brute-spray/pkg/clients"
	"bufio"
	"io"
	"log"
	"os"
	"strings"
	"sync"
)

type EnumUsers struct {
	usersFile string
	password string
	azureClient *clients.AzureClient
	wg *sync.WaitGroup
	writer io.Writer
}

func NewEnumUsers(usersFile string, password string, azureClient *clients.AzureClient, wg *sync.WaitGroup, writer io.Writer) *EnumUsers {
	return &EnumUsers{usersFile: usersFile, password: password, azureClient: azureClient, wg: wg, writer: writer}
}

func (eu *EnumUsers) Execute() {
	users, err := os.Open(eu.usersFile)
	if err != nil {
		log.Fatal(err)
	}
	defer users.Close()
	scannerUsers := bufio.NewScanner(users)
	for scannerUsers.Scan() {
		eu.wg.Add(1)
		user := scannerUsers.Text()
		domain := strings.Split(user, "@")[1]
		go eu.azureClient.GetAzureActiveDirectory(domain, user, eu.password, eu.wg, eu.writer)
	}
	if err := scannerUsers.Err(); err != nil {
		log.Fatal(err)
	}
}
