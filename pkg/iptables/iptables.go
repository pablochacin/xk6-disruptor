// Package iptables implements helpers for manipulating the iptables.
// Requires the iptables command to be installed.
// Requires 'NET_ADMIN' capabilities for manipulating the iptables.
package iptables

import (
	"errors"
	"fmt"
	"strings"

	"github.com/grafana/xk6-disruptor/pkg/agent/protocol"
	"github.com/grafana/xk6-disruptor/pkg/runtime"
)

// The four rules defined in the constants below achieve the following purposes:
// - Redirect traffic to the target application through the proxy, excluding traffic from the proxy itself.
// - Reset existing, non-redirected connections to the target application, except those of the proxy itself.
// Excluding traffic from the proxy from the goals above is not entirely straightforward, mainly because the proxy,
// just like `kubectl port-forward` and sidecars, connect _from_ the loopback address 127.0.0.1.
//
// To achieve this, we take advantage of the fact that the proxy knows the pod IP and connects to it, instead of to the
// loopback address like sidecars and kubectl port-forward does. This allows us to distinguish the proxy traffic from
// port-forwarded traffic, as while both traverse the `lo` interface, the former targets the pod IP while the latter
// targets the loopback IP.
//

// +-----------+---------------+------------------------+
// | Interface | From/To       | What                   |
// +-----------+---------------+------------------------+
// | ! lo      | Anywhere      | Outside traffic        |
// +-----------+---------------+------------------------+
// | lo        | 127.0.0.0/8   | Port-forwarded traffic |
// +-----------+---------------+------------------------+
// | lo        | ! 127.0.0.0/8 | Proxy traffic          |
// +-----------+---------------+------------------------+

// redirectLocalRule is a netfilter rule that intercepts locally-originated traffic, such as that coming from sidecars
// or `kubectl port-forward, directed to the application and redirects it to the proxy.
// As per https://upload.wikimedia.org/wikipedia/commons/3/37/Netfilter-packet-flow.svg, locally originated traffic
// traverses OUTPUT instead of PREROUTING.
// Traffic created by the proxy itself to the application also traverses this chain, but is not redirected by this rule
// as the proxy targets the pod IP and not the loopback address.
const redirectLocalRule = "OUTPUT " + // For local traffic
	"-t nat " + // Traversing the nat table
	"-s 127.0.0.0/8 -d 127.0.0.0/8 " + // Coming from and directed to the loopback address, i.e. not the pod IP.
	"-p tcp --dport %s " + // Sent to the upstream application's port
	"-j REDIRECT --to-port %s" // Forward it to the proxy address

// redirectExternalRule is a netfilter rule that intercepts external traffic directed to the application and redirects
// it to the proxy.
// Traffic created by the proxy itself to the application traverses is not redirected by this rule as it traverses the
// OUTPUT chain, not PREROUTING.
const redirectExternalRule = "PREROUTING " + // For remote traffic
	"-t nat " + // Traversing the nat table
	"! -i lo " + // Not coming form loopback. This is technically not needed, but doesn't hurt and helps readability.
	"-p tcp --dport %s " + // Sent to the upstream application's port
	"-j REDIRECT --to-port %s" // Forward it to the proxy address

// resetLocalRule is a netfilter rule that resets established connections (i.e. that have not been redirected) coming
// to and from the loopback address.
// This rule matches connections from sidecars and `kubectl port-forward`.
// Connections from the proxy itself do not match this rule, as they are directed to the pod's external IP and not
// loopback.
const resetLocalRule = "INPUT " + // For traffic traversing the INPUT chain
	"-i lo " + // On the loopback interface
	"-s 127.0.0.0/8 -d 127.0.0.0/8 " + // Coming from and directed to the loopback address
	"-p tcp --dport %s " + // Directed to the upstream application's port
	"-m state --state ESTABLISHED " + // That are already ESTABLISHED, i.e. not before they are redirected
	"-j REJECT --reject-with tcp-reset" // Reject it

// resetExternalRule is a netfilter rule that resets established connections (i.e. that have not been redirected) coming
// from anywhere except the local IP.
// This rule matches external connections to the pod's IP address.
// Connections from the proxy itself do not match this rule, as they are originated from the loopback address.
const resetExternalRule = "INPUT " + // For traffic traversing the INPUT chain
	"! -i lo " + // Not coming form loopback. This is technically not needed, but doesn't hurt and helps readability.
	"-p tcp --dport %s " + // Directed to the upstream application's port
	"-m state --state ESTABLISHED " + // That are already ESTABLISHED, i.e. not before they are redirected
	"-j REJECT --reject-with tcp-reset" // Reject it

// TrafficRedirectionSpec specifies the redirection of traffic to a destination
type TrafficRedirectionSpec struct {
	// ProxyPort is the port where the proxy is listening at.
	ProxyPort string
	// TargetPort is the port of for the upstream application.
	TargetPort string
}

// trafficRedirect defines an instance of a TrafficRedirector
type redirector struct {
	*TrafficRedirectionSpec
	executor runtime.Executor
}

// NewTrafficRedirector creates instances of an iptables traffic redirector
func NewTrafficRedirector(
	tr *TrafficRedirectionSpec,
	executor runtime.Executor,
) (protocol.TrafficRedirector, error) {
	if tr.TargetPort == "" || tr.ProxyPort == "" {
		return nil, fmt.Errorf("TargetPort and ProxyPort must be specified")
	}

	if tr.TargetPort == tr.ProxyPort {
		return nil, fmt.Errorf("TargetPort (%s) and ProxyPort (%s) must be different", tr.TargetPort, tr.ProxyPort)
	}

	return &redirector{
		TrafficRedirectionSpec: tr,
		executor:               executor,
	}, nil
}

func (tr *redirector) redirectRules() []string {
	return []string{
		fmt.Sprintf(
			redirectLocalRule,
			tr.TargetPort,
			tr.ProxyPort,
		),
		fmt.Sprintf(
			redirectExternalRule,
			tr.TargetPort,
			tr.ProxyPort,
		),
	}
}

func (tr *redirector) resetRules() []string {
	return []string{
		fmt.Sprintf(
			resetLocalRule,
			tr.TargetPort,
		),
		fmt.Sprintf(
			resetExternalRule,
			tr.TargetPort,
		),
	}
}

// execIptables runs performs the specified action ("-A" or "-D") for the supplied rule.
func (tr *redirector) execIptables(action string, rule string) error {
	cmd := fmt.Sprintf("%s %s", action, rule)
	out, err := tr.executor.Exec("iptables", strings.Split(cmd, " ")...)
	if err != nil {
		return fmt.Errorf("error executing iptables command %q: %w %s", cmd, err, string(out))
	}

	return nil
}

// Start applies the TrafficRedirect
func (tr *redirector) Start() error {
	for _, rule := range tr.redirectRules() {
		err := tr.execIptables("-A", rule)
		if err != nil {
			return err
		}
	}

	for _, rule := range tr.resetRules() {
		err := tr.execIptables("-A", rule)
		if err != nil {
			return err
		}
	}

	return nil
}

// Stop stops the TrafficRedirect.
// Stop will continue attempting to remove all the rules it deployed even if removing one fails.
// TODO: The error returned does not wrap original errors.
func (tr *redirector) Stop() error {
	var errs []string

	// TODO: Replace this homemade error aggregation with errors.Join when we upgrade from Go 1.19 to 1.20.
	for _, rule := range tr.redirectRules() {
		err := tr.execIptables("-D", rule)
		if err != nil {
			errs = append(errs, err.Error())
		}
	}

	for _, rule := range tr.resetRules() {
		err := tr.execIptables("-D", rule)
		if err != nil {
			errs = append(errs, err.Error())
		}
	}

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}

	return nil
}
