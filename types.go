package unifi

import "encoding/json"

type ResponseEnvelope struct {
	Meta ResponseMetaData `json:"meta"`
	Data *json.RawMessage `json:"data"`
}

type ResponseFirewallRules struct {
	Meta ResponseMetaData            `json:"meta"`
	Data []ResponseFirewallRulesData `json:"data"`
}

type ResponseMetaData struct {
	Rc string `json:"rc"`
}

type ResponseFirewallRulesData struct {
	ID                    string   `json:"_id,omitempty"`
	Ruleset               string   `json:"ruleset"`
	RuleIndex             int      `json:"rule_index"`
	Name                  string   `json:"name"`
	Enabled               bool     `json:"enabled"`
	Action                string   `json:"action"`
	ProtocolMatchExcepted bool     `json:"protocol_match_excepted"`
	Logging               bool     `json:"logging"`
	StateNew              bool     `json:"state_new"`
	StateEstablished      bool     `json:"state_established"`
	StateInvalid          bool     `json:"state_invalid"`
	StateRelated          bool     `json:"state_related"`
	Ipsec                 string   `json:"ipsec"`
	SrcFirewallgroupIds   []string `json:"src_firewallgroup_ids"`
	SrcMacAddress         string   `json:"src_mac_address"`
	DstFirewallgroupIds   []string `json:"dst_firewallgroup_ids"`
	DstAddress            string   `json:"dst_address"`
	SrcAddress            string   `json:"src_address"`
	Protocol              string   `json:"protocol"`
	IcmpTypename          string   `json:"icmp_typename"`
	SrcNetworkconfID      string   `json:"src_networkconf_id"`
	SrcNetworkconfType    string   `json:"src_networkconf_type"`
	DstNetworkconfID      string   `json:"dst_networkconf_id"`
	DstNetworkconfType    string   `json:"dst_networkconf_type"`
	SiteID                string   `json:"site_id"`
}
