package unifi

import (
	"bytes"
	"context"
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
	"path"
	"strings"
	"time"
)

var (
	routeFirewallRule = "/api/s/default/rest/firewallrule/"
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
func NewAPIClient(ctx context.Context, conf APIClientConfig) (*APIClient, error) {

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

	formattedURL := fmt.Sprintf("https://%s", strings.TrimSuffix(strings.TrimPrefix(conf.Host, "/"), "/"))
	fmt.Printf("formatted url: %s\n", formattedURL)
	base, err := url.Parse(formattedURL)
	fmt.Printf("base url: %s\n", base.String())

	if err != nil {
		return nil, fmt.Errorf("failed to parse base url %s", formattedURL)
	}

	apiClient := &APIClient{
		httpClient: client,
		baseURL:    base.String(),
		conf:       conf,
	}

	err = apiClient.Login(ctx)

	return apiClient, err
}

func (c *APIClient) Login(ctx context.Context) error {

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

func (c *APIClient) FirewallList(ctx context.Context) (ResponseFirewallRules, error) {
	resp := ResponseFirewallRules{}
	data, err := c.Get(ctx, routeFirewallRule) // "/api/s/default/rest/firewallrule")
	if err != nil {
		return resp, err
	}
	err = json.Unmarshal(data, &resp)
	if err != nil {
		return resp, err
	}
	return resp, nil
}

type connDir string

var (
	srcAddr connDir = "in"
	dstAddr connDir = "out"
)

func (c *APIClient) UnBlockIP(ctx context.Context, ipaddress string, dir string) error {
	list, err := c.FirewallList(ctx)
	if err != nil {
		return fmt.Errorf("could not get firewall list [%s]", err)
	}
	var id string
	for _, item := range list.Data {
		switch connDir(dir) {
		case srcAddr:
			if item.SrcAddress == ipaddress {
				id = item.ID
			}
		case dstAddr:
			if item.DstAddress == ipaddress {
				id = item.ID
			}
		}
	}
	if id == "" {
		return fmt.Errorf("could not find existing address [%s]", dir)
	}

	deleteResponse, err := c.Delete(ctx, "/api/s/default/rest/firewallrule/" + id)
	if err != nil {
		return err
	}

	fmt.Println(string(deleteResponse))
	return nil

}

type BlockRequest struct {
	Name    string `json:"name"`
	Interface    string `json:"interface"`
	RuleLocation string `json:"location"`
	SrcAddress   string `json:"src"`
	DstAddress   string `json:"dst"`
	Protocol     string `json:"protocol"`
	Action       string `json:"action"`
	location *position
	validated bool
}

type position struct {
	idx int
	last bool
}

const (
	locationFirst = "first"
	locationLast = "last"

	interfaceWANIN = "WAN_IN"
	interfaceWANOUT = "WAN_OUT"

	protocolTCP = "tcp"
	protocolUDP = "udp"
	protocolTCPAndUDP = protocolTCP + "_" + protocolUDP

	actionDrop = "drop"
	actionAccept = "accept"
	actionReject = "reject"
)

func (b *BlockRequest) Validate() error {
	if b.SrcAddress == "" && b.DstAddress == "" {
		return errors.New("must specity at least one src or dst address")
	}

	if b.SrcAddress != "" {
		ip := net.ParseIP(b.SrcAddress)
		if ip == nil {
			return errors.New("src ip address did not parse")
		}
	}
	if b.DstAddress != "" {
		ip := net.ParseIP(b.DstAddress)
		if ip == nil {
			return errors.New("dst ip address did not parse")
		}
	}

	b.RuleLocation = strings.ToLower(b.RuleLocation)
	switch b.RuleLocation {
	case "":
		b.RuleLocation = locationLast
	case locationFirst:
		b.location = &position{
			idx: 4999,
		}
	case locationLast:
		b.location = &position{
			idx:  2000,
			last: true,
		}
	default:
		return errors.New("only first and last are valid locations.  empty defaults to last")
	}

	b.Interface = strings.ToUpper(b.Interface)
	switch b.Interface {
	case interfaceWANIN:
	case interfaceWANOUT:
	default:
		return errors.New("only WAN_IN and WAN_OUT are valid locations")
	}

	b.Protocol = strings.ToLower(b.Protocol)
	switch b.Protocol {
	case protocolTCP:
	case protocolUDP:
	case protocolTCPAndUDP:
	default:
		return errors.New("only tcp, udp and tcp_udp are valid protcols")
	}

	b.Action = strings.ToLower(b.Action)
	switch b.Action {
	case actionAccept:
	case actionDrop:
	case actionReject:
	default:
		return fmt.Errorf("unknown action: %s.  acceptable values are %s", b.Action, strings.Join([]string{actionAccept, actionDrop, actionReject}, ","))
	}

	if b.Name == "" {
		description, err := b.Description()
		if err != nil {
			return err
		}
		b.Name = fmt.Sprintf("Generated rule: %s", description)
	}

	b.validated = true
	return nil
}

func (b *BlockRequest) Description() (string, error) {
	if !b.validated {
		err := b.Validate()
		if err != nil {
			return "", err
		}
	}
	args := []interface{}{b.Interface, b.Action, b.Protocol}
	baseDescription := "on %s %s %s => "
	if b.DstAddress != "" {
		baseDescription += " dstAddress: %s"
		args = append(args, b.DstAddress)
	}
	if b.SrcAddress != "" {
		baseDescription += " srcAddress: %s"
		args = append(args, b.SrcAddress)
	}
	return fmt.Sprintf(baseDescription, args...), nil
}

func (b *BlockRequest) update(pos int) {
	b.location.update(pos)
}

func (b *BlockRequest) Index() int {
	return b.location.idx
}


func (p *position) update(idx int) {
	if p.last && idx >= p.idx {
		p.idx = idx+1
	} else if !p.last && idx <= p.idx && idx >= 1 {
		p.idx = idx-1
	}
}
func (c *APIClient) DeleteFirewallRule(ctx context.Context, id string) ([]byte, error) {
	return c.Delete(ctx, path.Join(routeFirewallRule, id))
}

func (c *APIClient) Block(ctx context.Context, req BlockRequest) ([]byte, error) {
	list, err := c.FirewallList(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not get firewall list [%s]", err)
	}

	if err = req.Validate(); err != nil {
		return nil, err
	}

	for _, item := range list.Data {
		req.update(item.RuleIndex)
	}

	data := req.AsFirewallRule()

	resp, err := c.Post(ctx, routeFirewallRule, data)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func(b BlockRequest) AsFirewallRule() FirewallRule {
	return FirewallRule{
		Ruleset:               b.Interface,
		RuleIndex:             b.Index(),
		Name:                  b.Name,
		Enabled:               true,
		Action:                b.Action,
		ProtocolMatchExcepted: false,
		Logging:               false,
		StateNew:              false,
		StateEstablished:      false,
		StateInvalid:          false,
		StateRelated:          false,
		Ipsec:                 "",
		SrcFirewallgroupIds:   []string{},
		DstFirewallgroupIds:   []string{},
		DstAddress:            b.DstAddress,
		SrcAddress:            b.SrcAddress,
		Protocol:              b.Protocol,
		SrcNetworkconfType:    "NETv4",
		DstNetworkconfType:    "NETv4",
		SiteID:                "default",
	}
}

func (c *APIClient) BlockIP(ctx context.Context, ipaddress string, dir string) error {
	list, err := c.FirewallList(ctx)
	if err != nil {
		return fmt.Errorf("could not get firewall list [%s]", err)
	}
	indexMax := 0
	for _, item := range list.Data {
		switch connDir(dir) {
		case srcAddr:
			if item.SrcAddress == ipaddress {
				return errors.New("ip is already present in block list")
			}
		case dstAddr:
			if item.DstAddress == ipaddress {
				return errors.New("ip is already present in block list")
			}
		}
		if item.RuleIndex > indexMax {
			indexMax = item.RuleIndex
		}
	}

	ip := net.ParseIP(ipaddress)
	if ip == nil {
		return errors.New("ip address did not parse")
	}
	data := FirewallRule{
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
	resp, err := c.Post(ctx, "/api/s/default/rest/firewallrule", data)
	if err != nil {
		return err
	}
	fmt.Println(string(resp))
	return nil
}

func (c *APIClient) route(endpoint string) string {
	return strings.TrimSuffix(c.baseURL, "/") + "/" + strings.TrimPrefix(endpoint, "/")
}

func (c *APIClient) Delete(ctx context.Context, endpoint string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.route(endpoint), nil)
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

func (c *APIClient) Get(ctx context.Context, endpoint string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.route(endpoint), nil)

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

func (c *APIClient) Post(ctx context.Context, endpoint string, data interface{}) ([]byte, error) {
	bodyBytes, err := json.Marshal(data)
	if err != nil {
		return bodyBytes, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.route(endpoint), bytes.NewReader(bodyBytes))
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

type loginResponse struct {
	MetaData Meta   `json:"meta"`
	Data     []byte `json:"dta"`
}

type Meta struct {
	ResponseCode string `json:"rc"`
}

