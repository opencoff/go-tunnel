// conf.go -- config file processing.
//
// Author: Sudhi Herle <sudhi@herle.net>
//
// This software does not come with any express or implied
// warranty; it is provided "as is". No claim  is made to its
// suitability for any purpose.

package main

import (
	"fmt"
	yaml "gopkg.in/yaml.v2"
	"io/ioutil"
	"net"
)

// List of config entries
type Conf struct {
	Logging  string `yaml:"log"`
	LogLevel string `yaml:"loglevel"`
	URLlog   string `yaml:"urllog"`
	Http     []ListenConf
	Socks    []ListenConf
}

type ListenConf struct {
	Listen string   `yaml:"listen"`
	Bind   string   `yaml:"bind"`
	Allow  []subnet `yaml:"allow"`
	Deny   []subnet `yaml:"deny"`

	// rate limit -- perhost and global
	Ratelimit RateLimit `yaml:"ratelimit"`
}

type RateLimit struct {
	Global  int `yaml:"global"`
	PerHost int `yaml:"perhost"`
}

// An IP/Subnet
type subnet struct {
	net.IPNet
}

// Custom unmarshaler for IPNet
func (ipn *subnet) UnmarshalYAML(unm func(v interface{}) error) error {
	var s string

	// First unpack the bytes as a string. We then parse the string
	// as a CIDR
	err := unm(&s)
	if err != nil {
		return err
	}

	_, net, err := net.ParseCIDR(s)
	if err == nil {
		ipn.IP = net.IP
		ipn.Mask = net.Mask
	}
	return err
}

// Parse config file in YAML format and return
func ReadYAML(fn string) (*Conf, error) {
	yml, err := ioutil.ReadFile(fn)
	if err != nil {
		return nil, fmt.Errorf("Can't read config file %s: %s", fn, err)
	}

	var cfg Conf
	err = yaml.Unmarshal(yml, &cfg)
	if err != nil {
		return nil, fmt.Errorf("Can't parse config file %s: %s", fn, err)
	}

	return &cfg, nil
}
