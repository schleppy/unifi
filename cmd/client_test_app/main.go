package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/Schleppy/unifi"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"os"
	"time"
)

func main() {

	var cfg unifi.APIClientConfig
	var cfgPath string

	flag.StringVar(&cfgPath, "c", "config.yaml", "Config yaml file")
	flag.Parse()

	configData, err := ioutil.ReadFile(cfgPath)
	if err != nil {
		log.Printf("Error: %s", err)
		os.Exit(1)
	}
	err = yaml.Unmarshal(configData, &cfg)
	if err != nil {
		log.Printf("Error: %s", err)
		os.Exit(1)
	}

	client, err := unifi.NewAPIClient(cfg)
	if err != nil {
		log.Fatal(err.Error())
	}

	response, err := client.FirewallList()
	if err != nil {
		log.Fatal(err.Error())
	}

	for _, rule := range response.Data {
		//fmt.Printf("Rule %02d. %s %s src %s => dst %s (%s)\n", i, rule.Name, rule.Ruleset, rule.SrcAddress, rule.DstAddress, rule.Action)
		itemBytes, err := json.MarshalIndent(rule, "", "    ")
		if err != nil {
			continue
		}
		fmt.Println(string(itemBytes))
	}

	ip := "42.0.42.3"
	err = client.BlockIP(ip)
	if err != nil {
		fmt.Println(err.Error())
	} else {
		fmt.Printf("%s blocked\n", ip)
	}

	time.Sleep(15 * time.Second)

	err = client.UnBlockIP(ip)
	if err != nil {
		fmt.Println(err.Error())
	} else {
		fmt.Printf("%s unblocked\n", ip)
	}





}


