// Copyright 2016 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package prober

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"

	"github.com/prometheus/client_golang/prometheus"
)

// Returns the IP for the IPProtocol and lookup time.
func chooseProtocol(ctx context.Context, IPProtocol string, fallbackIPProtocol bool, target string, registry *prometheus.Registry, logger log.Logger) (ip *net.IPAddr, lookupTime float64, err error) {
	var fallbackProtocol string
	probeDNSLookupTimeSeconds := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_dns_lookup_time_seconds",
		Help: "Returns the time taken for probe dns lookup in seconds",
	})

	probeIPProtocolGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_ip_protocol",
		Help: "Specifies whether probe ip protocol is IP4 or IP6",
	})
	registry.MustRegister(probeIPProtocolGauge)
	registry.MustRegister(probeDNSLookupTimeSeconds)

	if IPProtocol == "ip6" || IPProtocol == "" {
		IPProtocol = "ip6"
		fallbackProtocol = "ip4"
	} else {
		IPProtocol = "ip4"
		fallbackProtocol = "ip6"
	}

	level.Info(logger).Log("msg", "Resolving target address", "ip_protocol", IPProtocol)
	resolveStart := time.Now()

	defer func() {
		lookupTime = time.Since(resolveStart).Seconds()
		probeDNSLookupTimeSeconds.Add(lookupTime)
	}()

	resolver := &net.Resolver{}
	ips, err := resolver.LookupIPAddr(ctx, target)
	if err != nil {
		level.Error(logger).Log("msg", "Resolution with IP protocol failed", "err", err)
		return nil, 0.0, err
	}

	// Return the IP in the requested protocol.
	var fallback *net.IPAddr
	for _, ip := range ips {
		switch IPProtocol {
		case "ip4":
			if ip.IP.To4() != nil {
				level.Info(logger).Log("msg", "Resolved target address", "ip", ip)
				probeIPProtocolGauge.Set(4)
				return &ip, lookupTime, nil
			}

			// ip4 as fallback
			fallback = &ip

		case "ip6":

			if ip.IP.To4() == nil {
				level.Info(logger).Log("msg", "Resolved target address", "ip", ip)
				probeIPProtocolGauge.Set(6)
				return &ip, lookupTime, nil
			}

			// ip6 as fallback
			fallback = &ip
		}
	}

	// Unable to find ip and no fallback set.
	if fallback == nil {
		return nil, 0.0, fmt.Errorf("unable to find ip; no fallback")
	}

	// Use fallback ip protocol.
	if fallbackProtocol == "ip4" {
		probeIPProtocolGauge.Set(4)
	} else {
		probeIPProtocolGauge.Set(6)
	}
	return fallback, lookupTime, nil
}

func readJsonData(resp *http.Response) (interface{}, error) {
	bytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var jsonData interface{}
	err = json.Unmarshal([]byte(bytes), &jsonData)
	if err != nil {
		return nil, err
	}

	return jsonData, nil
}

type ReceiverFunc func(key string, value float64)

func (receiver ReceiverFunc) Receive(key string, value float64) {
	receiver(key, value)
}

type Receiver interface {
	Receive(key string, value float64)
}

func walkJSON(path string, jsonData interface{}, receiver Receiver, logger log.Logger) {
	switch v := jsonData.(type) {
	case int:
		receiver.Receive(path, float64(v))
	case float64:
		receiver.Receive(path, v)
	case bool:
		n := 0.0
		if v {
			n = 1.0
		}
		receiver.Receive(path, n)
	case string:
		timeFormat := "2006/01/02"
		licenseDate, err := time.Parse(timeFormat, v)
		if err != nil {
			level.Error(logger).Log("msg", "Unable to parse the license date: "+v, "err")
			return
		}
		// timeDiff := time.Since(licenseDate)
		// receiver.Receive(path, float64(int(timeDiff.Hours()/-24)))
		receiver.Receive(path, float64(licenseDate.Unix()))
	case nil:
		// ignore
	case []interface{}:
		prefix := path + "__"
		for i, x := range v {
			walkJSON(fmt.Sprintf("%s%d", prefix, i), x, receiver, logger)
		}
	case map[string]interface{}:
		prefix := ""
		if path != "" {
			prefix = path + "::"
		}
		for k, x := range v {
			walkJSON(fmt.Sprintf("%s%s", prefix, k), x, receiver, logger)
		}
	default:
		level.Error(logger).Log("msg", "unkown type", "err")
	}
}
