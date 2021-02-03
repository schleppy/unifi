package unifi

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

type APIClientConfig struct {
	Host     string `yaml:"host"`
	Timeout  int    `yaml:"timeout"` // seconds
	User     string `yaml:"user"`
	Password string `yaml:"password"`
}

type APIClient struct {
	baseURL    string
	httpClient *http.Client
	loggedIn   bool
	conf       APIClientConfig
}

// NewAPIClient returns an instance of APIClient
func NewAPIClient(conf APIClientConfig) (*APIClient, error) {

	jar, err := cookiejar.New(nil)
	if err != nil {
		log.Fatal(err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		Timeout: time.Duration(conf.Timeout) * time.Second,
		Jar:     jar,
	}

	formattedURL := fmt.Sprintf("https://%s", strings.TrimRight(conf.Host, "/"))
	base, err := url.Parse(formattedURL)

	if err != nil {
		return nil, fmt.Errorf("failed to parse base url %s", formattedURL)
	}

	apiClient := &APIClient{
		httpClient: client,
		baseURL:    base.String(),
		conf:       conf,
	}

	err = apiClient.Login()

	return apiClient, err
}

func (c *APIClient) Login() error {

	if c.loggedIn {
		return nil
	}

	authRequest, err := json.Marshal(map[string]interface{}{
		"username": c.conf.User,
		"password": c.conf.Password},
	)
	if err != nil {
		return err
	}

	request, err := http.NewRequest(http.MethodPost, c.baseURL+"/api/login", bytes.NewReader(authRequest))

	if err != nil {
		return fmt.Errorf("failed to create new request: %s", err)
	}

	request.Header.Set("Content-Type", "application/json")
	response, err := c.httpClient.Do(request)
	if err != nil {
		if isNetworkTimeout(err) {
			return errors.New("request timed out")
		}
		return err
	}

	defer response.Body.Close()

	if response.StatusCode != 200 {
		return fmt.Errorf("bad status code: %d", response.StatusCode)
	}

	responseBytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return err
	}

	resp := &loginResponse{}

	err = json.Unmarshal(responseBytes, resp)
	if err != nil {
		return err
	}

	if resp.MetaData.ResponseCode != "ok" {
		log.Println(string(responseBytes))
		return fmt.Errorf("response code: %s", resp.MetaData.ResponseCode)
	}

	fmt.Println(string(responseBytes))
	c.loggedIn = true
	return nil

}

func (c *APIClient) FirewallList() (ResponseFirewallRules, error) {
	resp := ResponseFirewallRules{}
	data, err := c.Get("/api/s/default/rest/firewallrule")
	if err != nil {
		return resp, err
	}
	err = json.Unmarshal(data, &resp)
	if err != nil {
		return resp, err
	}
	return resp, nil
}

func (c *APIClient) UnBlockIP(ipaddress string) error {
	list, err := c.FirewallList()
	if err != nil {
		return fmt.Errorf("could not get firewall list [%s]", err)
	}
	var id string
	for _, item := range list.Data {
		if item.SrcAddress == ipaddress {
			id = item.ID
		}
	}
	if id == "" {
		return errors.New("could not find existing src address")
	}

	deleteResponse, err := c.Delete("/api/s/default/rest/firewallrule/" + id)
	if err != nil {
		return err
	}

	fmt.Println(string(deleteResponse))
	return nil

}

func (c *APIClient) BlockIP(ipaddress string) error {
	list, err := c.FirewallList()
	if err != nil {
		return fmt.Errorf("could not get firewall list [%s]", err)
	}
	indexMax := 0
	for _, item := range list.Data {
		if item.SrcAddress == ipaddress {
			return errors.New("ip is already present in block list")
		}
		if item.RuleIndex > indexMax {
			indexMax = item.RuleIndex
		}
	}

	ip := net.ParseIP(ipaddress)
	if ip == nil {
		return errors.New("ip address did not parse")
	}
	data := ResponseFirewallRulesData{
		Ruleset:             "WAN_IN",
		RuleIndex:           indexMax + 1,
		Name:                "Block ip " + ipaddress,
		Enabled:             true,
		Action:              "drop",
		SrcAddress:          ipaddress,
		Protocol:            "all",
		SrcFirewallgroupIds: []string{},
		SrcNetworkconfType:  "NETv4",
		DstFirewallgroupIds: []string{},
		DstNetworkconfType:  "NETv4",
	}
	resp, err := c.Post("/api/s/default/rest/firewallrule", data)
	if err != nil {
		return err
	}
	fmt.Println(string(resp))
	return nil
}

func (c *APIClient) Delete(endpoint string) ([]byte, error) {
	request, err := http.NewRequest(http.MethodDelete, c.baseURL+endpoint, nil) // , bytes.NewBuffer(authRequest))

	response, err := c.httpClient.Do(request)
	if err != nil {
		if isNetworkTimeout(err) {
			return nil, errors.New("request timed out")
		}
		return nil, err
	}

	defer response.Body.Close()

	if response.StatusCode != 200 {
		return nil, fmt.Errorf("bad status code: %d", response.StatusCode)
	}

	return ioutil.ReadAll(response.Body)
}

func (c *APIClient) Get(endpoint string) ([]byte, error) {
	request, err := http.NewRequest(http.MethodGet, c.baseURL+endpoint, nil) // , bytes.NewBuffer(authRequest))

	response, err := c.httpClient.Do(request)
	if err != nil {
		if isNetworkTimeout(err) {
			return nil, errors.New("request timed out")
		}
		return nil, err
	}

	defer response.Body.Close()

	if response.StatusCode != 200 {
		return nil, fmt.Errorf("bad status code: %d", response.StatusCode)
	}

	return ioutil.ReadAll(response.Body)
}

type loginResponse struct {
	MetaData Meta   `json:"meta"`
	Data     []byte `json:"dta"`
}

type Meta struct {
	ResponseCode string `json:"rc"`
}

func (c *APIClient) Post(endpoint string, data interface{}) ([]byte, error) {
	bodyBytes, err := json.Marshal(data)
	if err != nil {
		return bodyBytes, err
	}
	fmt.Println(string(bodyBytes))
	request, err := http.NewRequest(http.MethodPost, c.baseURL+endpoint, bytes.NewReader(bodyBytes)) // , bytes.NewBuffer(authRequest))
	request.Header.Set("Content-Type", "application/json")

	response, err := c.httpClient.Do(request)
	if err != nil {
		if isNetworkTimeout(err) {
			return nil, errors.New("request timed out")
		}
		return nil, err
	}

	defer response.Body.Close()

	if response.StatusCode != 200 {
		d, err := ioutil.ReadAll(response.Body)
		if err == nil {
			fmt.Println(string(d))
		}
		return nil, fmt.Errorf("bad status code: %d", response.StatusCode)
	}

	return ioutil.ReadAll(response.Body)
}

// isNetworkTimeout checks the error to see if it is an indication if an i/o timeout
func isNetworkTimeout(err error) bool {
	switch err := err.(type) {
	case *url.Error:
		if err, ok := err.Err.(net.Error); ok && err.Timeout() {
			return true
		}
	case net.Error:
		if err.Timeout() {
			return true
		}
	}

	return false
}
