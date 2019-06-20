/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package loadbalancer

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/aws/aws-sdk-go/service/elbv2"
	"github.com/golang/glog"
	"github.com/kubernetes-sigs/aws-alb-ingress-controller/internal/aws"
	"github.com/kubernetes-sigs/aws-alb-ingress-controller/internal/ingress/annotations/parser"
	"github.com/kubernetes-sigs/aws-alb-ingress-controller/internal/ingress/errors"
	"github.com/kubernetes-sigs/aws-alb-ingress-controller/internal/ingress/resolver"
)

type PortData struct {
	Port   int64
	Scheme string
}

type Config struct {
	Scheme        *string
	IPAddressType *string
	WebACLId      *string

	InboundCidrs     []string
	Ports            []PortData
	SecurityGroups   []string
	Subnets          []string
	Attributes       []*elbv2.LoadBalancerAttribute
	GlobalInstanceLb bool
}

type loadBalancer struct {
	r resolver.Resolver
}

const (
	DefaultIPAddressType = elbv2.IpAddressTypeIpv4
	DefaultScheme        = elbv2.LoadBalancerSchemeEnumInternal
)

// NewParser creates a new target group annotation parser
func NewParser(r resolver.Resolver) parser.IngressAnnotation {
	return loadBalancer{r}
}

// Parse parses the annotations contained in the resource
func (lb loadBalancer) Parse(ing parser.AnnotationInterface) (interface{}, error) {
	// support legacy waf-acl-id annotation
	webACLId, _ := parser.GetStringAnnotation("waf-acl-id", ing)
	w, err := parser.GetStringAnnotation("web-acl-id", ing)
	if err == nil {
		webACLId = w
	}

	ipAddressType, err := parser.GetStringAnnotation("ip-address-type", ing)
	if err != nil {
		ipAddressType = aws.String(DefaultIPAddressType)
	}

	if *ipAddressType != elbv2.IpAddressTypeIpv4 && *ipAddressType != elbv2.IpAddressTypeDualstack {
		return nil, errors.NewInvalidAnnotationContentReason(fmt.Sprintf("IP address type must be either `%v` or `%v`", elbv2.IpAddressTypeIpv4, elbv2.IpAddressTypeDualstack))
	}

	scheme, err := parser.GetStringAnnotation("scheme", ing)
	if err != nil {
		scheme = aws.String(DefaultScheme)
	}

	if *scheme != elbv2.LoadBalancerSchemeEnumInternal && *scheme != elbv2.LoadBalancerSchemeEnumInternetFacing {
		return nil, errors.NewInvalidAnnotationContentReason(fmt.Sprintf("ALB scheme must be either `%v` or `%v`", elbv2.LoadBalancerSchemeEnumInternal, elbv2.LoadBalancerSchemeEnumInternetFacing))
	}

	ports, err := parsePorts(ing)
	if err != nil {
		return nil, err
	}

	attributes, err := parseAttributes(ing)
	if err != nil {
		return nil, err
	}

	securityGroups := parser.GetStringSliceAnnotation("security-groups", ing)
	subnets := parser.GetStringSliceAnnotation("subnets", ing)

	cidrs, err := parseCidrs(ing)
	if err != nil {
		return nil, err
	}

	globalInstanceLb := true
	if _, err := parser.GetBoolAnnotation("global-instance-sg", ing); err != nil {
		globalInstanceLb = false
	}

	return &Config{
		WebACLId:      webACLId,
		Scheme:        scheme,
		IPAddressType: ipAddressType,

		Attributes:   attributes,
		InboundCidrs: cidrs,
		Ports:        ports,

		Subnets:        subnets,
		SecurityGroups: securityGroups,

		GlobalInstanceLb: globalInstanceLb,
	}, nil
}

func parseAttributes(ing parser.AnnotationInterface) ([]*elbv2.LoadBalancerAttribute, error) {
	var badAttrs []string
	var lbattrs []*elbv2.LoadBalancerAttribute

	attrs := parser.GetStringSliceAnnotation("load-balancer-attributes", ing)
	oldattrs := parser.GetStringSliceAnnotation("attributes", ing)
	if len(attrs) == 0 && len(oldattrs) != 0 {
		attrs = oldattrs
	}

	if attrs == nil {
		return nil, nil
	}

	for _, attr := range attrs {
		parts := strings.Split(attr, "=")
		switch {
		case attr == "":
			continue
		case len(parts) != 2:
			badAttrs = append(badAttrs, attr)
			continue
		}
		lbattrs = append(lbattrs, &elbv2.LoadBalancerAttribute{
			Key:   aws.String(strings.TrimSpace(parts[0])),
			Value: aws.String(strings.TrimSpace(parts[1])),
		})
	}

	if len(badAttrs) > 0 {
		return nil, fmt.Errorf("unable to parse `%s` into Key=Value pair(s)", strings.Join(badAttrs, ", "))
	}
	return lbattrs, nil
}

// parsePorts takes a JSON array describing what ports and protocols should be used. When the JSON
// is empty, implying the annotation was not present, desired ports are set to the default. The
// default port value is 80 when a certArn is not present and 443 when it is.
func parsePorts(ing parser.AnnotationInterface) ([]PortData, error) {
	lps := []PortData{}
	p, err := parser.GetStringAnnotation("listen-ports", ing)
	if err != nil {
		// If port data is empty, default to port 80 or 443 contingent on whether a certArn was specified.
		_, err = parser.GetStringAnnotation("certificate-arn", ing)
		if err != nil {
			lps = append(lps, PortData{int64(80), elbv2.ProtocolEnumHttp})
		} else {
			lps = append(lps, PortData{int64(443), elbv2.ProtocolEnumHttps})
		}
		return lps, nil
	}

	// Container to hold json in structured format after unmarshaling.
	c := []map[string]int64{}
	err = json.Unmarshal([]byte(*p), &c)
	if err != nil {
		return nil, fmt.Errorf("listen-ports JSON structure was invalid: %s", err.Error())
	}

	// Iterate over listeners in list. Validate port and protcol are correct, then inject them into
	// the list of ListenerPorts.
	for _, l := range c {
		for k, v := range l {
			// Verify port value is valid for ALB.
			// ALBS (from AWS): Ports need to be a number between 1 and 65535
			if v < 1 || v > 65535 {
				return nil, fmt.Errorf("Invalid port provided. Must be between 1 and 65535. It was %d", v)
			}
			switch {
			case k == elbv2.ProtocolEnumHttp:
				lps = append(lps, PortData{v, k})
			case k == elbv2.ProtocolEnumHttps:
				lps = append(lps, PortData{v, k})
			default:
				return nil, fmt.Errorf("Invalid protocol provided. Must be HTTP or HTTPS and in order to use HTTPS you must have specified a certificate ARN")
			}
		}
	}

	return lps, nil
}

func parseCidrs(ing parser.AnnotationInterface) (out []string, err error) {
	cidrConfig := parser.GetStringSliceAnnotation("security-group-inbound-cidrs", ing)
	if len(cidrConfig) != 0 {
		glog.Warningf("`security-group-inbound-cidrs` annotation is deprecated, use `inbound-cidrs` instead")
	} else {
		cidrConfig = parser.GetStringSliceAnnotation("inbound-cidrs", ing)
	}

	for _, inboundCidr := range cidrConfig {
		ip, _, err := net.ParseCIDR(inboundCidr)
		if err != nil {
			return out, err
		}

		if ip.To4() == nil {
			return out, fmt.Errorf("CIDR must use an IPv4 address: %v", inboundCidr)
		}
		out = append(out, inboundCidr)
	}
	if len(out) == 0 {
		out = append(out, "0.0.0.0/0")
	}
	return out, nil
}

func Dummy() *Config {
	return &Config{
		Scheme:        aws.String(elbv2.LoadBalancerSchemeEnumInternal),
		IPAddressType: aws.String(elbv2.IpAddressTypeIpv4),
		Ports: []PortData{
			{Scheme: elbv2.ProtocolEnumHttp, Port: int64(80)},
		},
	}
}
