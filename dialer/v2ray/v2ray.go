package v2ray

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"

	jsoniter "github.com/json-iterator/go"
	"github.com/tearsful/outbound/common"
	"github.com/tearsful/outbound/dialer"
	"github.com/tearsful/outbound/netproxy"
	"github.com/tearsful/outbound/protocol"
	"github.com/tearsful/outbound/protocol/direct"
	"github.com/tearsful/outbound/protocol/http"
	"github.com/tearsful/outbound/transport/grpc"
	"github.com/tearsful/outbound/transport/httpupgrade"
	"github.com/tearsful/outbound/transport/meek"
	"github.com/tearsful/outbound/transport/tls"
	"github.com/tearsful/outbound/transport/ws"
)

func init() {
	dialer.FromLinkRegister("vmess", NewV2Ray)
	dialer.FromLinkRegister("vless", NewV2Ray)
}

type V2Ray struct {
	Ps            string `json:"ps"`
	Add           string `json:"add"`
	Port          string `json:"port"`
	ID            string `json:"id"`
	Aid           string `json:"aid"`
	Net           string `json:"net"`
	Type          string `json:"type"`
	Host          string `json:"host"`
	SNI           string `json:"sni"`
	Path          string `json:"path"`
	TLS           string `json:"tls"`
	Flow          string `json:"flow,omitempty"`
	Alpn          string `json:"alpn,omitempty"`
	AllowInsecure bool   `json:"allowInsecure"`
	Fingerprint   string `json:"fp,omitempty"`
	PublicKey     string `json:"pbk,omitempty"`
	ShortId       string `json:"sid,omitempty"`
	SpiderX       string `json:"spx,omitempty"`
	V             string `json:"v"`
	Protocol      string `json:"protocol"`
	// 新增 VLESS 兼容参数
	Encryption string `json:"encryption,omitempty"` // 加密方式
	Level      uint32 `json:"level,omitempty"`      // 用户级别
	Seed       string `json:"seed,omitempty"`       // 种子参数
	// 动态端口支持
	DynamicPort string `json:"dynamicPort,omitempty"` // 动态端口配置
	PortRange   string `json:"portRange,omitempty"`   // 端口范围
	// Xray-core 新参数支持
	Mldsa65Seed   string `json:"mldsa65Seed,omitempty"`   // MLDSA65 种子
	Mldsa65Verify string `json:"mldsa65Verify,omitempty"` // MLDSA65 验证密钥
	Mode          string `json:"mode,omitempty"`          // XHTTP 模式
	Pqv           string `json:"pqv,omitempty"`           // Post-Quantum 验证
	// 衍生字段：从 Encryption 中拆出的 0-RTT token
	O0rttToken string `json:"o0rttToken,omitempty"`
}

func NewV2Ray(option *dialer.ExtraOption, nextDialer netproxy.Dialer, link string) (netproxy.Dialer, *dialer.Property, error) {
	var (
		s   *V2Ray
		err error
	)
	switch {
	case strings.HasPrefix(link, "vmess://"):
		s, err = ParseVmessURL(link)
		if err != nil {
			return nil, nil, err
		}
		if s.Aid != "0" && s.Aid != "" {
			return nil, nil, fmt.Errorf("%w: aid: %v, we only support AEAD encryption", dialer.UnexpectedFieldErr, s.Aid)
		}
	case strings.HasPrefix(link, "vless://"):
		s, err = ParseVlessURL(link)
		if err != nil {
			return nil, nil, err
		}
	default:
		return nil, nil, dialer.InvalidParameterErr
	}
	return s.Dialer(option, nextDialer)
}

func securityUsesTLS(security string) bool {
	switch strings.ToLower(security) {
	case "tls", "xtls":
		return true
	default:
		return false
	}
}

func isGRPCMultiMode(mode string) bool {
	switch strings.ToLower(mode) {
	case "multi", "guna":
		return true
	default:
		return false
	}
}

func securityUsesTLSOrReality(security string) bool {
	return securityUsesTLS(security) || strings.EqualFold(security, "reality")
}

func (s *V2Ray) Dialer(option *dialer.ExtraOption, nextDialer netproxy.Dialer) (npd netproxy.Dialer, property *dialer.Property, err error) {
	d := nextDialer
	switch s.Protocol {
	case "vmess", "vless":
	default:
		return nil, nil, fmt.Errorf("V2Ray.Dialer: unexpected protocol: %v", s.Protocol)
	}

	if s.TLS == "reality" {
		if s.Protocol != "vless" {
			return nil, nil, fmt.Errorf("only VLESS supports reality")
		}
	}

	flow := strings.TrimSpace(s.Flow)
	if flow != "" && !strings.EqualFold(flow, "none") {
		netName := strings.ToLower(s.Net)
		if netName != "" && netName != "tcp" {
			return nil, nil, fmt.Errorf("flow %q requires tcp transport, got %q", s.Flow, s.Net)
		}
		if !securityUsesTLSOrReality(s.TLS) {
			return nil, nil, fmt.Errorf("flow %q requires tls or reality", s.Flow)
		}
	}

	switch strings.ToLower(s.Net) {
	case "ws":
		scheme := "ws"
		if securityUsesTLSOrReality(s.TLS) {
			scheme = "wss"
		}
		sni := s.SNI
		if sni == "" {
			sni = s.Host
		}
		u := url.URL{
			Scheme: scheme,
			Host:   net.JoinHostPort(s.Add, s.Port),
			Path:   s.Path,
			RawQuery: url.Values{
				"host":          []string{s.Host},
				"sni":           []string{sni},
				"allowInsecure": []string{common.BoolToString(s.AllowInsecure || option.AllowInsecure)},
			}.Encode(),
		}
		d, _, err = ws.NewWs(option, d, u.String())
		if err != nil {
			return nil, nil, err
		}
	case "tcp":
		if securityUsesTLSOrReality(s.TLS) {
			sni := s.SNI
			if sni == "" {
				sni = s.Host
			}
			if s.TLS == "reality" {
				u := url.URL{
					Scheme: "reality",
					Host:   net.JoinHostPort(s.Add, s.Port),
					RawQuery: url.Values{
						"sni": []string{sni},
						"fp":  []string{s.Fingerprint},
						"sid": []string{s.ShortId},
						"pbk": []string{s.PublicKey},
						"spx": []string{s.SpiderX},
					}.Encode(),
				}
				d, err = tls.NewReality(u.String(), d)
			} else {
				// tls and legacy xtls both need a real TLS handshake layer.
				u := url.URL{
					Scheme: option.TlsImplementation,
					Host:   net.JoinHostPort(s.Add, s.Port),
					RawQuery: url.Values{
						"sni":           []string{sni},
						"allowInsecure": []string{common.BoolToString(s.AllowInsecure || option.AllowInsecure)},
						"utlsImitate":   []string{option.UtlsImitate},
					}.Encode(),
				}
				d, _, err = tls.NewTls(option, d, u.String())
			}
			if err != nil {
				return nil, nil, err
			}

		}
		if s.Type != "none" && s.Type != "" {
			return nil, nil, fmt.Errorf("%w: type: %v", dialer.UnexpectedFieldErr, s.Type)
		}
	case "grpc":
		sni := s.SNI
		if sni == "" {
			sni = s.Host
		}
		serviceName := s.Path
		if serviceName == "" {
			serviceName = "GunService"
		}
		mode := strings.ToLower(s.Mode)
		d = &grpc.Dialer{
			NextDialer:    d,
			ServiceName:   serviceName,
			ServerName:    sni,
			AllowInsecure: s.AllowInsecure || option.AllowInsecure,
			// security=none means h2c; tls/xtls/reality use TLS credentials.
			PlainText: strings.EqualFold(s.TLS, "none") || s.TLS == "",
			MultiMode: isGRPCMultiMode(mode),
		}
	case "http", "http2", "h2":
		sni := s.SNI
		if sni == "" {
			sni = s.Add
		}
		scheme := "http"
		if securityUsesTLS(s.TLS) {
			scheme = "https"
		}
		u := url.URL{
			Scheme: scheme,
			Host:   net.JoinHostPort(s.Add, s.Port),
			Path:   s.Path,
			RawQuery: url.Values{
				"sni":               []string{sni},
				"allowInsecure":     []string{common.BoolToString(s.AllowInsecure || option.AllowInsecure)},
				"tlsImplementation": []string{option.TlsImplementation},
				"utlsImitate":       []string{option.UtlsImitate},
				"host":              []string{s.Host},
				"alpn":              []string{s.Alpn},
				"transport":         []string{"1"},
			}.Encode(),
		}
		d, err = http.NewHTTPProxy(&u, direct.SymmetricDirect)
		if err != nil {
			return nil, nil, err
		}
	case "meek":
		if strings.HasPrefix(s.Path, "https://") && !securityUsesTLS(s.TLS) && s.TLS != "utls" {
			return nil, nil, fmt.Errorf("%w: meek: tls should be enabled", dialer.InvalidParameterErr)
		}

		u := url.URL{
			Scheme: "meek",
			Host:   net.JoinHostPort(s.Add, s.Port),
			RawQuery: url.Values{
				"url":           []string{s.Path},
				"alpn":          []string{s.Alpn},
				"serverName":    []string{s.SNI},
				"allowInsecure": []string{common.BoolToString(s.AllowInsecure || option.AllowInsecure)},
			}.Encode(),
		}

		d, err = meek.NewDialer(u.String(), d)
		if err != nil {
			return nil, nil, err
		}
	case "httpupgrade":
		scheme := "http"
		if securityUsesTLS(s.TLS) {
			scheme = "https"
		}
		u := url.URL{
			Scheme: scheme,
			Host:   net.JoinHostPort(s.Add, s.Port),
			RawQuery: url.Values{
				"host":          []string{s.Host},
				"path":          []string{s.Path},
				"allowInsecure": []string{common.BoolToString(s.AllowInsecure || option.AllowInsecure)},
				"serverName":    []string{s.SNI},
			}.Encode(),
		}
		d, err = httpupgrade.NewDialer(u.String(), d)
		if err != nil {
			return nil, nil, err
		}
	case "xhttp":
		// 对于 xhttp，底层仍使用 TCP 拨号；若开启 Reality，则先包一层 Reality
		if s.TLS == "reality" {
			sni := s.SNI
			if sni == "" {
				sni = s.Host
			}
			u := url.URL{
				Scheme: "reality",
				Host:   net.JoinHostPort(s.Add, s.Port),
				RawQuery: url.Values{
					"sni": []string{sni},
					"fp":  []string{s.Fingerprint},
					"sid": []string{s.ShortId},
					"pbk": []string{s.PublicKey},
					"spx": []string{s.SpiderX},
				}.Encode(),
			}
			var err error
			d, err = tls.NewReality(u.String(), d)
			if err != nil {
				return nil, nil, err
			}
		}
	default:
		return nil, nil, fmt.Errorf("%w: network: %v", dialer.UnexpectedFieldErr, s.Net)
	}

	// 解析 encryption 中的 .0rtt.<token>
	baseEnc := s.Encryption
	var o0rtt string
	if strings.Contains(s.Encryption, ".0rtt.") {
		parts := strings.SplitN(s.Encryption, ".0rtt.", 2)
		baseEnc = parts[0] + ".0rtt"
		if len(parts) == 2 {
			o0rtt = parts[1]
			s.O0rttToken = o0rtt
		}
	}

	extra := map[string]string{}
	if o0rtt != "" {
		extra["o0rtt"] = o0rtt
	}
	if s.Pqv != "" {
		extra["pqv"] = s.Pqv
	}
	if strings.ToLower(s.Net) == "xhttp" {
		if s.Path != "" {
			extra["xhttp.path"] = s.Path
		}
		if s.Mode != "" {
			extra["xhttp.mode"] = s.Mode
		}
		if s.Host != "" {
			extra["xhttp.headers"] = "Host:" + s.Host
		}
	}

	if d, err = protocol.NewDialer(s.Protocol, d, protocol.Header{
		ProxyAddress: net.JoinHostPort(s.Add, s.Port),
		Cipher:       getAutoCipher(),
		Password:     s.ID,
		IsClient:     true,
		Feature1:     s.Flow,
		Feature2:     baseEnc,
		Feature3:     s.Net,
		Feature4:     s.Mldsa65Seed,
		Feature5:     s.Mldsa65Verify,
		Extra:        extra,
		//Flags:        protocol.Flags_VMess_UsePacketAddr,
	}); err != nil {
		return nil, nil, err
	}
	return d, &dialer.Property{
		Name:     s.Ps,
		Address:  net.JoinHostPort(s.Add, s.Port),
		Protocol: s.Protocol,
		Link:     s.ExportToURL(),
	}, nil
}

func ParseVlessURL(vless string) (data *V2Ray, err error) {
	u, err := url.Parse(vless)
	if err != nil {
		return nil, err
	}
	query := u.Query()
	data = &V2Ray{
		Ps:            u.Fragment,
		Add:           u.Hostname(),
		Port:          u.Port(),
		ID:            u.User.String(),
		Net:           query.Get("type"),
		Type:          query.Get("headerType"),
		Host:          query.Get("host"),
		SNI:           query.Get("sni"),
		Path:          query.Get("path"),
		TLS:           query.Get("security"),
		Flow:          query.Get("flow"),
		Alpn:          query.Get("alpn"),
		AllowInsecure: common.QueryBoolTrue(query, "allowInsecure", "allow_insecure", "allowinsecure", "skipVerify"),
		Fingerprint:   query.Get("fp"),
		PublicKey:     query.Get("pbk"),
		ShortId:       query.Get("sid"),
		SpiderX:       query.Get("spx"),
		V:             "2",
		Protocol:      "vless",
		// 新增 VLESS 参数解析
		Encryption:  query.Get("encryption"),
		Seed:        query.Get("seed"),
		DynamicPort: query.Get("dynamicPort"),
		PortRange:   query.Get("portRange"),
		// Xray-core 新参数支持
		Mldsa65Seed:   query.Get("mldsa65Seed"),
		Mldsa65Verify: query.Get("mldsa65Verify"),
		Mode:          query.Get("mode"),
		Pqv:           query.Get("pqv"),
	}
	if data.Net == "" {
		data.Net = "tcp"
	}
	if data.Net == "grpc" {
		data.Path = query.Get("serviceName")
	}
	if data.Net == "meek" {
		data.Path = query.Get("url")
	}
	if data.Type == "" {
		data.Type = "none"
	}
	if data.TLS == "" {
		data.TLS = "none"
	}
	// Clients sometimes serialize empty flow as "none"; dialer only accepts "" or real flow ids.
	if strings.EqualFold(data.Flow, "none") {
		data.Flow = ""
	}
	if data.Type == "mkcp" || data.Type == "kcp" {
		data.Path = query.Get("seed")
	}
	return data, nil
}

func ParseVmessURL(vmess string) (data *V2Ray, err error) {
	var info V2Ray
	// perform base64 decoding and unmarshal to VmessInfo
	raw, err := common.Base64StdDecode(vmess[8:])
	if err != nil {
		raw, err = common.Base64UrlDecode(vmess[8:])
	}
	if err != nil {
		// not in json format, try to resolve as vmess://BASE64(Security:ID@Add:Port)?remarks=Ps&obfsParam=Host&Path=Path&obfs=Net&tls=TLS
		var u *url.URL
		u, err = url.Parse(vmess)
		if err != nil {
			return
		}
		re := regexp.MustCompile(`.*:(.+)@(.+):(\d+)`)
		s := strings.Split(vmess[8:], "?")[0]
		s, err = common.Base64StdDecode(s)
		if err != nil {
			s, _ = common.Base64UrlDecode(s)
		}
		subMatch := re.FindStringSubmatch(s)
		if subMatch == nil {
			err = fmt.Errorf("unrecognized vmess address")
			return
		}
		q := u.Query()
		ps := q.Get("remarks")
		if ps == "" {
			ps = q.Get("remark")
		}
		obfs := q.Get("obfs")
		obfsParam := q.Get("obfsParam")
		path := q.Get("path")
		if obfs == "kcp" || obfs == "mkcp" {
			m := make(map[string]string)
			//cater to v2rayN definition
			_ = jsoniter.Unmarshal([]byte(obfsParam), &m)
			path = m["seed"]
			obfsParam = ""
		}
		aid := q.Get("alterId")
		if aid == "" {
			aid = q.Get("aid")
		}
		sni := q.Get("peer")
		info = V2Ray{
			ID:            subMatch[1],
			Add:           subMatch[2],
			Port:          subMatch[3],
			Ps:            ps,
			Host:          jsoniter.Get([]byte(obfsParam), "host").ToString(),
			Path:          path,
			Net:           obfs,
			Aid:           aid,
			TLS:           map[string]string{"1": "tls"}[q.Get("tls")],
			SNI:           sni,
			AllowInsecure: false,
		}
		if info.Net == "websocket" {
			info.Net = "ws"
		}
	} else {
		err = jsoniter.Unmarshal([]byte(raw), &info)
		if err != nil {
			return
		}
	}
	// correct the wrong vmess as much as possible
	if strings.HasPrefix(info.Host, "/") && info.Path == "" {
		info.Path = info.Host
		info.Host = ""
	}
	if info.Aid == "" {
		info.Aid = "0"
	}
	info.Protocol = "vmess"
	return &info, nil
}

func (s *V2Ray) ExportToURL() string {
	switch s.Protocol {
	case "vless":
		// https://github.com/reality/Xray-core/issues/91
		var query = make(url.Values)
		common.SetValue(&query, "type", s.Net)
		common.SetValue(&query, "security", s.TLS)
		switch s.Net {
		case "websocket", "ws", "http", "h2", "httpupgrade":
			common.SetValue(&query, "path", s.Path)
			common.SetValue(&query, "host", s.Host)
		case "mkcp", "kcp":
			common.SetValue(&query, "headerType", s.Type)
			common.SetValue(&query, "seed", s.Path)
		case "tcp":
			common.SetValue(&query, "headerType", s.Type)
			common.SetValue(&query, "host", s.Host)
			common.SetValue(&query, "path", s.Path)
		case "grpc":
			common.SetValue(&query, "serviceName", s.Path)
			if s.Mode != "" && s.Mode != "gun" {
				common.SetValue(&query, "mode", s.Mode)
			}
		case "meek":
			common.SetValue(&query, "url", s.Host)
		}

		// QUIC 传输支持 - 需要额外的 QUIC 传输层实现
		if s.Net == "quic" {
			// QUIC 参数处理
			common.SetValue(&query, "security", s.TLS)
			common.SetValue(&query, "type", "none") // QUIC 使用内置的传输层
			common.SetValue(&query, "key", s.Path)  // QUIC 密钥
		}
		if s.TLS != "none" {
			common.SetValue(&query, "sni", s.SNI)
			common.SetValue(&query, "alpn", s.Alpn)
			if s.Flow != "" && !strings.EqualFold(s.Flow, "none") {
				common.SetValue(&query, "flow", s.Flow)
			}
			common.SetValue(&query, "fp", s.Fingerprint)
		}
		if s.AllowInsecure {
			common.SetValue(&query, "allowInsecure", "1")
		}

		// 添加 VLESS 特定参数
		if s.Encryption != "" && s.Encryption != "none" {
			common.SetValue(&query, "encryption", s.Encryption)
		}
		if s.Seed != "" {
			common.SetValue(&query, "seed", s.Seed)
		}
		if s.DynamicPort != "" {
			common.SetValue(&query, "dynamicPort", s.DynamicPort)
		}
		if s.PortRange != "" {
			common.SetValue(&query, "portRange", s.PortRange)
		}

		// 添加 Xray-core 新参数
		if s.Mldsa65Seed != "" {
			common.SetValue(&query, "mldsa65Seed", s.Mldsa65Seed)
		}
		if s.Mldsa65Verify != "" {
			common.SetValue(&query, "mldsa65Verify", s.Mldsa65Verify)
		}
		if s.Net != "grpc" && s.Mode != "" {
			common.SetValue(&query, "mode", s.Mode)
		}
		if s.Pqv != "" {
			common.SetValue(&query, "pqv", s.Pqv)
		}

		U := url.URL{
			Scheme:   "vless",
			User:     url.User(s.ID),
			Host:     net.JoinHostPort(s.Add, s.Port),
			RawQuery: query.Encode(),
			Fragment: s.Ps,
		}
		return U.String()
	case "vmess":
		s.V = "2"
		b, _ := jsoniter.Marshal(s)
		return "vmess://" + strings.TrimSuffix(base64.StdEncoding.EncodeToString(b), "=")
	}
	//log.Warn("unexpected protocol: %v", v.Protocol)
	return ""
}
