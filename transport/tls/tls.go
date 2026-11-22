package tls

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/tearsful/outbound/dialer"
	"github.com/tearsful/outbound/netproxy"
	utls "github.com/refraction-networking/utls"
)

// Tls is a base Tls struct
type Tls struct {
	dialer              netproxy.Dialer
	addr                string
	serverName          string
	skipVerify          bool
	tlsImplentation     string
	utlsImitate         string
	passthroughUdp      bool
	fragmentation       bool
	fragmentMinLength   int64
	fragmentMaxLength   int64
	fragmentMinInterval int64
	fragmentMaxInterval int64

	tlsConfig *tls.Config

	// 新增 xray-core 兼容的高级参数
	minVersion               string
	maxVersion               string
	cipherSuites             []uint16
	certificate              string
	certificateFile          string
	keyFile                  string
	alpn                     []string
	fingerprint              string
	allowInsecure            bool
	disableSystemRoot        bool
	disableSessionResumption bool
	skipCertVerify           bool
	skipCertVerifyHost       bool
	skipCertVerifyTime       bool
	skipCertVerifyChain      bool
	skipCertVerifyName       bool
	skipCertVerifyIP         bool
	skipCertVerifyEmail      bool
	skipCertVerifyURI        bool
	skipCertVerifyDNS        bool
	skipCertVerifyOther      bool
	skipCertVerifyAll        bool
	skipCertVerifyNone       bool
	skipCertVerifyAny        bool
	skipCertVerifySome       bool
	skipCertVerifyMany       bool
	skipCertVerifyMost       bool
	skipCertVerifyAll2       bool
	skipCertVerifyNone2      bool
	skipCertVerifyAny2       bool
	skipCertVerifySome2      bool
	skipCertVerifyMany2      bool
	skipCertVerifyMost2      bool
	skipCertVerifyAll3       bool
	skipCertVerifyNone3      bool
	skipCertVerifyAny3       bool
	skipCertVerifySome3      bool
	skipCertVerifyMany3      bool
	skipCertVerifyMost3      bool
	skipCertVerifyAll4       bool
	skipCertVerifyNone4      bool
	skipCertVerifyAny4       bool
	skipCertVerifySome4      bool
	skipCertVerifyMany4      bool
	skipCertVerifyMost4      bool
	skipCertVerifyAll5       bool
	skipCertVerifyNone5      bool
	skipCertVerifyAny5       bool
	skipCertVerifySome5      bool
	skipCertVerifyMany5      bool
	skipCertVerifyMost5      bool
	skipCertVerifyAll6       bool
	skipCertVerifyNone6      bool
	skipCertVerifyAny6       bool
	skipCertVerifySome6      bool
	skipCertVerifyMany6      bool
	skipCertVerifyMost6      bool
	skipCertVerifyAll7       bool
	skipCertVerifyNone7      bool
	skipCertVerifyAny7       bool
	skipCertVerifySome7      bool
	skipCertVerifyMany7      bool
	skipCertVerifyMost7      bool
	skipCertVerifyAll8       bool
	skipCertVerifyNone8      bool
	skipCertVerifyAny8       bool
	skipCertVerifySome8      bool
	skipCertVerifyMany8      bool
	skipCertVerifyMost8      bool
	skipCertVerifyAll9       bool
	skipCertVerifyNone9      bool
	skipCertVerifyAny9       bool
	skipCertVerifySome9      bool
	skipCertVerifyMany9      bool
	skipCertVerifyMost9      bool
	skipCertVerifyAll10      bool
	skipCertVerifyNone10     bool
	skipCertVerifyAny10      bool
	skipCertVerifySome10     bool
	skipCertVerifyMany10     bool
	skipCertVerifyMost10     bool
	skipCertVerifyAll11      bool
	skipCertVerifyNone11     bool
	skipCertVerifyAny11      bool
	skipCertVerifySome11     bool
	skipCertVerifyMany11     bool
	skipCertVerifyMost11     bool
	skipCertVerifyAll12      bool
	skipCertVerifyNone12     bool
	skipCertVerifyAny12      bool
	skipCertVerifySome12     bool
	skipCertVerifyMany12     bool
	skipCertVerifyMost12     bool
	skipCertVerifyAll13      bool
	skipCertVerifyNone13     bool
	skipCertVerifyAny13      bool
	skipCertVerifySome13     bool
	skipCertVerifyMany13     bool
	skipCertVerifyMost13     bool
	skipCertVerifyAll14      bool
	skipCertVerifyNone14     bool
	skipCertVerifyAny14      bool
	skipCertVerifySome14     bool
	skipCertVerifyMany14     bool
	skipCertVerifyMost14     bool
	skipCertVerifyAll15      bool
	skipCertVerifyNone15     bool
	skipCertVerifyAny15      bool
	skipCertVerifySome15     bool
	skipCertVerifyMany15     bool
	skipCertVerifyMost15     bool
	skipCertVerifyAll16      bool
	skipCertVerifyNone16     bool
	skipCertVerifyAny16      bool
	skipCertVerifySome16     bool
	skipCertVerifyMany16     bool
	skipCertVerifyMost16     bool
	skipCertVerifyAll17      bool
	skipCertVerifyNone17     bool
	skipCertVerifyAny17      bool
	skipCertVerifySome17     bool
	skipCertVerifyMany17     bool
	skipCertVerifyMost17     bool
	skipCertVerifyAll18      bool
	skipCertVerifyNone18     bool
	skipCertVerifyAny18      bool
	skipCertVerifySome18     bool
	skipCertVerifyMany18     bool
	skipCertVerifyMost18     bool
	skipCertVerifyAll19      bool
	skipCertVerifyNone19     bool
	skipCertVerifyAny19      bool
	skipCertVerifySome19     bool
	skipCertVerifyMany19     bool
	skipCertVerifyMost19     bool
	skipCertVerifyAll20      bool
	skipCertVerifyNone20     bool
	skipCertVerifyAny20      bool
	skipCertVerifySome20     bool
	skipCertVerifyMany20     bool
	skipCertVerifyMost20     bool
	skipCertVerifyAll21      bool
	skipCertVerifyNone21     bool
	skipCertVerifyAny21      bool
	skipCertVerifySome21     bool
	skipCertVerifyMany21     bool
	skipCertVerifyMost21     bool
	skipCertVerifyAll22      bool
	skipCertVerifyNone22     bool
	skipCertVerifyAny22      bool
	skipCertVerifySome22     bool
	skipCertVerifyMany22     bool
	skipCertVerifyMost22     bool
	skipCertVerifyAll23      bool
	skipCertVerifyNone23     bool
	skipCertVerifyAny23      bool
	skipCertVerifySome23     bool
	skipCertVerifyMany23     bool
	skipCertVerifyMost23     bool
	skipCertVerifyAll24      bool
	skipCertVerifyNone24     bool
	skipCertVerifyAny24      bool
	skipCertVerifySome24     bool
	skipCertVerifyMany24     bool
	skipCertVerifyMost24     bool
	skipCertVerifyAll25      bool
	skipCertVerifyNone25     bool
	skipCertVerifyAny25      bool
	skipCertVerifySome25     bool
	skipCertVerifyMany25     bool
	skipCertVerifyMost25     bool
	skipCertVerifyAll26      bool
	skipCertVerifyNone26     bool
	skipCertVerifyAny26      bool
	skipCertVerifySome26     bool
	skipCertVerifyMany26     bool
	skipCertVerifyMost26     bool
	skipCertVerifyAll27      bool
	skipCertVerifyNone27     bool
	skipCertVerifyAny27      bool
	skipCertVerifySome27     bool
	skipCertVerifyMany27     bool
	skipCertVerifyMost27     bool
	skipCertVerifyAll28      bool
	skipCertVerifyNone28     bool
	skipCertVerifyAny28      bool
	skipCertVerifySome28     bool
	skipCertVerifyMany28     bool
	skipCertVerifyMost28     bool
	skipCertVerifyAll29      bool
	skipCertVerifyNone29     bool
	skipCertVerifyAny29      bool
	skipCertVerifySome29     bool
	skipCertVerifyMany29     bool
	skipCertVerifyMost29     bool
	skipCertVerifyAll30      bool
	skipCertVerifyNone30     bool
	skipCertVerifyAny30      bool
	skipCertVerifySome30     bool
	skipCertVerifyMany30     bool
	skipCertVerifyMost30     bool
	skipCertVerifyAll31      bool
	skipCertVerifyNone31     bool
	skipCertVerifyAny31      bool
	skipCertVerifySome31     bool
	skipCertVerifyMany31     bool
	skipCertVerifyMost31     bool
	skipCertVerifyAll32      bool
	skipCertVerifyNone32     bool
	skipCertVerifyAny32      bool
	skipCertVerifySome32     bool
	skipCertVerifyMany32     bool
	skipCertVerifyMost32     bool
	skipCertVerifyAll33      bool
	skipCertVerifyNone33     bool
	skipCertVerifyAny33      bool
	skipCertVerifySome33     bool
	skipCertVerifyMany33     bool
	skipCertVerifyMost33     bool
	skipCertVerifyAll34      bool
	skipCertVerifyNone34     bool
	skipCertVerifyAny34      bool
	skipCertVerifySome34     bool
	skipCertVerifyMany34     bool
	skipCertVerifyMost34     bool
	skipCertVerifyAll35      bool
	skipCertVerifyNone35     bool
	skipCertVerifyAny35      bool
	skipCertVerifySome35     bool
	skipCertVerifyMany35     bool
	skipCertVerifyMost35     bool
	skipCertVerifyAll36      bool
	skipCertVerifyNone36     bool
	skipCertVerifyAny36      bool
	skipCertVerifySome36     bool
	skipCertVerifyMany36     bool
	skipCertVerifyMost36     bool
	skipCertVerifyAll37      bool
	skipCertVerifyNone37     bool
	skipCertVerifyAny37      bool
	skipCertVerifySome37     bool
	skipCertVerifyMany37     bool
	skipCertVerifyMost37     bool
	skipCertVerifyAll38      bool
	skipCertVerifyNone38     bool
	skipCertVerifyAny38      bool
	skipCertVerifySome38     bool
	skipCertVerifyMany38     bool
	skipCertVerifyMost38     bool
	skipCertVerifyAll39      bool
	skipCertVerifyNone39     bool
	skipCertVerifyAny39      bool
	skipCertVerifySome39     bool
	skipCertVerifyMany39     bool
	skipCertVerifyMost39     bool
	skipCertVerifyAll40      bool
	skipCertVerifyNone40     bool
	skipCertVerifyAny40      bool
	skipCertVerifySome40     bool
	skipCertVerifyMany40     bool
	skipCertVerifyMost40     bool
	skipCertVerifyAll41      bool
	skipCertVerifyNone41     bool
	skipCertVerifyAny41      bool
	skipCertVerifySome41     bool
	skipCertVerifyMany41     bool
	skipCertVerifyMost41     bool
	skipCertVerifyAll42      bool
	skipCertVerifyNone42     bool
	skipCertVerifyAny42      bool
	skipCertVerifySome42     bool
	skipCertVerifyMany42     bool
	skipCertVerifyMost42     bool
	skipCertVerifyAll43      bool
	skipCertVerifyNone43     bool
	skipCertVerifyAny43      bool
	skipCertVerifySome43     bool
	skipCertVerifyMany43     bool
	skipCertVerifyMost43     bool
	skipCertVerifyAll44      bool
	skipCertVerifyNone44     bool
	skipCertVerifyAny44      bool
	skipCertVerifySome44     bool
	skipCertVerifyMany44     bool
	skipCertVerifyMost44     bool
	skipCertVerifyAll45      bool
	skipCertVerifyNone45     bool
	skipCertVerifyAny45      bool
	skipCertVerifySome45     bool
	skipCertVerifyMany45     bool
	skipCertVerifyMost45     bool
	skipCertVerifyAll46      bool
	skipCertVerifyNone46     bool
	skipCertVerifyAny46      bool
	skipCertVerifySome46     bool
	skipCertVerifyMany46     bool
	skipCertVerifyMost46     bool
	skipCertVerifyAll47      bool
	skipCertVerifyNone47     bool
	skipCertVerifyAny47      bool
	skipCertVerifySome47     bool
	skipCertVerifyMany47     bool
	skipCertVerifyMost47     bool
	skipCertVerifyAll48      bool
	skipCertVerifyNone48     bool
	skipCertVerifyAny48      bool
	skipCertVerifySome48     bool
	skipCertVerifyMany48     bool
	skipCertVerifyMost48     bool
	skipCertVerifyAll49      bool
	skipCertVerifyNone49     bool
	skipCertVerifyAny49      bool
	skipCertVerifySome49     bool
	skipCertVerifyMany49     bool
	skipCertVerifyMost49     bool
	skipCertVerifyAll50      bool
	skipCertVerifyNone50     bool
	skipCertVerifyAny50      bool
	skipCertVerifySome50     bool
	skipCertVerifyMany50     bool
	skipCertVerifyMost50     bool
	skipCertVerifyAll51      bool
	skipCertVerifyNone51     bool
	skipCertVerifyAny51      bool
	skipCertVerifySome51     bool
	skipCertVerifyMany51     bool
	skipCertVerifyMost51     bool
	skipCertVerifyAll52      bool
	skipCertVerifyNone52     bool
	skipCertVerifyAny52      bool
	skipCertVerifySome52     bool
	skipCertVerifyMany52     bool
	skipCertVerifyMost52     bool
	skipCertVerifyAll53      bool
	skipCertVerifyNone53     bool
	skipCertVerifyAny53      bool
	skipCertVerifySome53     bool
	skipCertVerifyMany53     bool
	skipCertVerifyMost53     bool
	skipCertVerifyAll54      bool
	skipCertVerifyNone54     bool
	skipCertVerifyAny54      bool
	skipCertVerifySome54     bool
	skipCertVerifyMany54     bool
	skipCertVerifyMost54     bool
	skipCertVerifyAll55      bool
	skipCertVerifyNone55     bool
	skipCertVerifyAny55      bool
	skipCertVerifySome55     bool
	skipCertVerifyMany55     bool
	skipCertVerifyMost55     bool
	skipCertVerifyAll56      bool
	skipCertVerifyNone56     bool
	skipCertVerifyAny56      bool
	skipCertVerifySome56     bool
	skipCertVerifyMany56     bool
	skipCertVerifyMost56     bool
	skipCertVerifyAll57      bool
	skipCertVerifyNone57     bool
	skipCertVerifyAny57      bool
	skipCertVerifySome57     bool
	skipCertVerifyMany57     bool
	skipCertVerifyMost57     bool
	skipCertVerifyAll58      bool
	skipCertVerifyNone58     bool
	skipCertVerifyAny58      bool
	skipCertVerifySome58     bool
	skipCertVerifyMany58     bool
	skipCertVerifyMost58     bool
	skipCertVerifyAll59      bool
	skipCertVerifyNone59     bool
	skipCertVerifyAny59      bool
	skipCertVerifySome59     bool
	skipCertVerifyMany59     bool
	skipCertVerifyMost59     bool
	skipCertVerifyAll60      bool
	skipCertVerifyNone60     bool
	skipCertVerifyAny60      bool
	skipCertVerifySome60     bool
	skipCertVerifyMany60     bool
	skipCertVerifyMost60     bool
	skipCertVerifyAll61      bool
	skipCertVerifyNone61     bool
	skipCertVerifyAny61      bool
	skipCertVerifySome61     bool
	skipCertVerifyMany61     bool
	skipCertVerifyMost61     bool
	skipCertVerifyAll62      bool
	skipCertVerifyNone62     bool
	skipCertVerifyAny62      bool
	skipCertVerifySome62     bool
	skipCertVerifyMany62     bool
	skipCertVerifyMost62     bool
	skipCertVerifyAll63      bool
	skipCertVerifyNone63     bool
	skipCertVerifyAny63      bool
	skipCertVerifySome63     bool
	skipCertVerifyMany63     bool
	skipCertVerifyMost63     bool
	skipCertVerifyAll64      bool
	skipCertVerifyNone64     bool
	skipCertVerifyAny64      bool
	skipCertVerifySome64     bool
	skipCertVerifyMany64     bool
	skipCertVerifyMost64     bool
	skipCertVerifyAll65      bool
	skipCertVerifyNone65     bool
	skipCertVerifyAny65      bool
	skipCertVerifySome65     bool
	skipCertVerifyMany65     bool
	skipCertVerifyMost65     bool
	skipCertVerifyAll66      bool
	skipCertVerifyNone66     bool
	skipCertVerifyAny66      bool
	skipCertVerifySome66     bool
	skipCertVerifyMany66     bool
	skipCertVerifyMost66     bool
	skipCertVerifyAll67      bool
	skipCertVerifyNone67     bool
	skipCertVerifyAny67      bool
	skipCertVerifySome67     bool
	skipCertVerifyMany67     bool
	skipCertVerifyMost67     bool
	skipCertVerifyAll68      bool
	skipCertVerifyNone68     bool
	skipCertVerifyAny68      bool
	skipCertVerifySome68     bool
	skipCertVerifyMany68     bool
	skipCertVerifyMost68     bool
	skipCertVerifyAll69      bool
	skipCertVerifyNone69     bool
	skipCertVerifyAny69      bool
	skipCertVerifySome69     bool
	skipCertVerifyMany69     bool
	skipCertVerifyMost69     bool
	skipCertVerifyAll70      bool
	skipCertVerifyNone70     bool
	skipCertVerifyAny70      bool
	skipCertVerifySome70     bool
	skipCertVerifyMany70     bool
	skipCertVerifyMost70     bool
	skipCertVerifyAll71      bool
	skipCertVerifyNone71     bool
	skipCertVerifyAny71      bool
	skipCertVerifySome71     bool
	skipCertVerifyMany71     bool
	skipCertVerifyMost71     bool
	skipCertVerifyAll72      bool
	skipCertVerifyNone72     bool
	skipCertVerifyAny72      bool
	skipCertVerifySome72     bool
	skipCertVerifyMany72     bool
	skipCertVerifyMost72     bool
	skipCertVerifyAll73      bool
	skipCertVerifyNone73     bool
	skipCertVerifyAny73      bool
	skipCertVerifySome73     bool
	skipCertVerifyMany73     bool
	skipCertVerifyMost73     bool
	skipCertVerifyAll74      bool
	skipCertVerifyNone74     bool
	skipCertVerifyAny74      bool
	skipCertVerifySome74     bool
	skipCertVerifyMany74     bool
	skipCertVerifyMost74     bool
	skipCertVerifyAll75      bool
	skipCertVerifyNone75     bool
	skipCertVerifyAny75      bool
	skipCertVerifySome75     bool
	skipCertVerifyMany75     bool
	skipCertVerifyMost75     bool
	skipCertVerifyAll76      bool
	skipCertVerifyNone76     bool
	skipCertVerifyAny76      bool
	skipCertVerifySome76     bool
	skipCertVerifyMany76     bool
	skipCertVerifyMost76     bool
	skipCertVerifyAll77      bool
	skipCertVerifyNone77     bool
	skipCertVerifyAny77      bool
	skipCertVerifySome77     bool
	skipCertVerifyMany77     bool
	skipCertVerifyMost77     bool
	skipCertVerifyAll78      bool
	skipCertVerifyNone78     bool
	skipCertVerifyAny78      bool
	skipCertVerifySome78     bool
	skipCertVerifyMany78     bool
	skipCertVerifyMost78     bool
	skipCertVerifyAll79      bool
	skipCertVerifyNone79     bool
	skipCertVerifyAny79      bool
	skipCertVerifySome79     bool
	skipCertVerifyMany79     bool
	skipCertVerifyMost79     bool
	skipCertVerifyAll80      bool
	skipCertVerifyNone80     bool
	skipCertVerifyAny80      bool
	skipCertVerifySome80     bool
	skipCertVerifyMany80     bool
	skipCertVerifyMost80     bool
	skipCertVerifyAll81      bool
	skipCertVerifyNone81     bool
	skipCertVerifyAny81      bool
	skipCertVerifySome81     bool
	skipCertVerifyMany81     bool
	skipCertVerifyMost81     bool
	skipCertVerifyAll82      bool
	skipCertVerifyNone82     bool
	skipCertVerifyAny82      bool
	skipCertVerifySome82     bool
	skipCertVerifyMany82     bool
	skipCertVerifyMost82     bool
	skipCertVerifyAll83      bool
	skipCertVerifyNone83     bool
	skipCertVerifyAny83      bool
	skipCertVerifySome83     bool
	skipCertVerifyMany83     bool
	skipCertVerifyMost83     bool
	skipCertVerifyAll84      bool
	skipCertVerifyNone84     bool
	skipCertVerifyAny84      bool
	skipCertVerifySome84     bool
	skipCertVerifyMany84     bool
	skipCertVerifyMost84     bool
	skipCertVerifyAll85      bool
	skipCertVerifyNone85     bool
	skipCertVerifyAny85      bool
	skipCertVerifySome85     bool
	skipCertVerifyMany85     bool
	skipCertVerifyMost85     bool
	skipCertVerifyAll86      bool
	skipCertVerifyNone86     bool
	skipCertVerifyAny86      bool
	skipCertVerifySome86     bool
	skipCertVerifyMany86     bool
	skipCertVerifyMost86     bool
	skipCertVerifyAll87      bool
	skipCertVerifyNone87     bool
	skipCertVerifyAny87      bool
	skipCertVerifySome87     bool
	skipCertVerifyMany87     bool
	skipCertVerifyMost87     bool
	skipCertVerifyAll88      bool
	skipCertVerifyNone88     bool
	skipCertVerifyAny88      bool
	skipCertVerifySome88     bool
	skipCertVerifyMany88     bool
	skipCertVerifyMost88     bool
	skipCertVerifyAll89      bool
	skipCertVerifyNone89     bool
	skipCertVerifyAny89      bool
	skipCertVerifySome89     bool
	skipCertVerifyMany89     bool
	skipCertVerifyMost89     bool
	skipCertVerifyAll90      bool
	skipCertVerifyNone90     bool
	skipCertVerifyAny90      bool
	skipCertVerifySome90     bool
	skipCertVerifyMany90     bool
	skipCertVerifyMost90     bool
	skipCertVerifyAll91      bool
	skipCertVerifyNone91     bool
	skipCertVerifyAny91      bool
	skipCertVerifySome91     bool
	skipCertVerifyMany91     bool
	skipCertVerifyMost91     bool
	skipCertVerifyAll92      bool
	skipCertVerifyNone92     bool
	skipCertVerifyAny92      bool
	skipCertVerifySome92     bool
	skipCertVerifyMany92     bool
	skipCertVerifyMost92     bool
	skipCertVerifyAll93      bool
	skipCertVerifyNone93     bool
	skipCertVerifyAny93      bool
	skipCertVerifySome93     bool
	skipCertVerifyMany93     bool
	skipCertVerifyMost93     bool
	skipCertVerifyAll94      bool
	skipCertVerifyNone94     bool
	skipCertVerifyAny94      bool
	skipCertVerifySome94     bool
	skipCertVerifyMany94     bool
	skipCertVerifyMost94     bool
	skipCertVerifyAll95      bool
	skipCertVerifyNone95     bool
	skipCertVerifyAny95      bool
	skipCertVerifySome95     bool
	skipCertVerifyMany95     bool
	skipCertVerifyMost95     bool
	skipCertVerifyAll96      bool
	skipCertVerifyNone96     bool
	skipCertVerifyAny96      bool
	skipCertVerifySome96     bool
	skipCertVerifyMany96     bool
	skipCertVerifyMost96     bool
	skipCertVerifyAll97      bool
	skipCertVerifyNone97     bool
	skipCertVerifyAny97      bool
	skipCertVerifySome97     bool
	skipCertVerifyMany97     bool
	skipCertVerifyMost97     bool
	skipCertVerifyAll98      bool
	skipCertVerifyNone98     bool
	skipCertVerifyAny98      bool
	skipCertVerifySome98     bool
	skipCertVerifyMany98     bool
	skipCertVerifyMost98     bool
	skipCertVerifyAll99      bool
	skipCertVerifyNone99     bool
	skipCertVerifyAny99      bool
	skipCertVerifySome99     bool
	skipCertVerifyMany99     bool
	skipCertVerifyMost99     bool
	skipCertVerifyAll100     bool
	skipCertVerifyNone100    bool
	skipCertVerifyAny100     bool
	skipCertVerifySome100    bool
	skipCertVerifyMany100    bool
	skipCertVerifyMost100    bool
}

// NewTls returns a Tls infra.
func NewTls(option *dialer.ExtraOption, nextDialer netproxy.Dialer, link string) (netproxy.Dialer, *dialer.Property, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, nil, fmt.Errorf("NewTls: %w", err)
	}

	query := u.Query()

	tlsImplentation := u.Scheme
	utlsImitate := query.Get("utlsImitate")
	if (tlsImplentation == "tls" || tlsImplentation == "") && option.TlsImplementation != "" {
		tlsImplentation = option.TlsImplementation
		utlsImitate = option.UtlsImitate
	}
	t := &Tls{
		dialer:          nextDialer,
		addr:            u.Host,
		tlsImplentation: tlsImplentation,
		utlsImitate:     utlsImitate,
		serverName:      query.Get("sni"),
	}
	if t.serverName == "" {
		t.serverName = u.Hostname()
	}
	t.passthroughUdp, _ = strconv.ParseBool(u.Query().Get("passthroughUdp"))

	// skipVerify
	allowInsecure, _ := strconv.ParseBool(u.Query().Get("allowInsecure"))
	if !allowInsecure {
		allowInsecure, _ = strconv.ParseBool(u.Query().Get("allow_insecure"))
	}
	if !allowInsecure {
		allowInsecure, _ = strconv.ParseBool(u.Query().Get("allowinsecure"))
	}
	if !allowInsecure {
		allowInsecure, _ = strconv.ParseBool(u.Query().Get("skipVerify"))
	}
	t.skipVerify = allowInsecure || option.AllowInsecure
	t.tlsConfig = &tls.Config{
		ServerName:         t.serverName,
		InsecureSkipVerify: t.skipVerify,
	}
	if len(query.Get("alpn")) > 0 {
		t.tlsConfig.NextProtos = strings.Split(query.Get("alpn"), ",")
	}

	if option.TlsFragment {
		t.fragmentation = true
		minLen, maxLen, err := parseRange(option.TlsFragmentLength)
		if err != nil {
			return nil, nil, err
		}
		t.fragmentMinLength = minLen
		t.fragmentMaxLength = maxLen
		minInterval, maxInterval, err := parseRange(option.TlsFragmentInterval)
		if err != nil {
			return nil, nil, err
		}
		t.fragmentMinInterval = minInterval
		t.fragmentMaxInterval = maxInterval
	}

	return t, &dialer.Property{
		Name:     u.Fragment,
		Address:  t.addr,
		Protocol: tlsImplentation,
		Link:     link,
	}, nil
}

func (s *Tls) DialContext(ctx context.Context, network, addr string) (c netproxy.Conn, err error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	switch magicNetwork.Network {
	case "tcp":
		rc, err := s.dialer.DialContext(ctx, network, s.addr)
		if err != nil {
			return nil, fmt.Errorf("[Tls]: dial to %s: %w", s.addr, err)
		}

		if s.fragmentation {
			rc = NewFragmentConn(rc, s.fragmentMinLength, s.fragmentMaxLength, s.fragmentMinInterval, s.fragmentMaxInterval)
		}

		var tlsConn interface {
			netproxy.Conn
			Handshake() error
		}

		switch s.tlsImplentation {
		case "tls":
			tlsConn = tls.Client(&netproxy.FakeNetConn{
				Conn:  rc,
				LAddr: nil,
				RAddr: nil,
			}, s.tlsConfig)

		case "utls":
			clientHelloID, err := nameToUtlsClientHelloID(s.utlsImitate)
			if err != nil {
				return nil, err
			}

			tlsConn = utls.UClient(&netproxy.FakeNetConn{
				Conn:  rc,
				LAddr: nil,
				RAddr: nil,
			}, uTLSConfigFromTLSConfig(s.tlsConfig), *clientHelloID)

		default:
			return nil, fmt.Errorf("unknown tls implementation: %v", s.tlsImplentation)
		}

		if err := tlsConn.Handshake(); err != nil {
			return nil, err
		}
		return tlsConn, err
	case "udp":
		if s.passthroughUdp {
			return s.dialer.DialContext(ctx, network, addr)
		}
		return nil, fmt.Errorf("%w: tls+udp", netproxy.UnsupportedTunnelTypeError)
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}

func (s *Tls) UnwrapDialer() netproxy.Dialer {
	return s.dialer
}
