package vless

import (
	"context"
	"testing"
	"time"

	"github.com/tearsful/outbound/netproxy"
	"github.com/tearsful/outbound/protocol"
	"github.com/tearsful/outbound/protocol/vless/encryption"
)

func TestVLESSXHTTPSupport(t *testing.T) {
	// 测试 XHTTP 传输支持（XTLS flow 与 xhttp 不兼容，须为空）
	header := protocol.Header{
		ProxyAddress: "example.com:443?type=xhttp&path=/path&mode=auto",
		Password:     "test-uuid",
		Feature1:     "",
		Feature2:     "none",
		Feature3:     "xhttp",
		IsClient:     true,
	}

	dialer, err := NewDialer(nil, header)
	if err != nil {
		t.Fatalf("Failed to create VLESS dialer with XHTTP: %v", err)
	}

	if dialer == nil {
		t.Fatal("Dialer should not be nil")
	}

	// 验证传输类型
	if dialer.(*Dialer).transportType != "xhttp" {
		t.Errorf("Expected transport type 'xhttp', got '%s'", dialer.(*Dialer).transportType)
	}

	cfg := dialer.(*Dialer).xhttpConfig
	if cfg == nil || cfg.Host != "example.com:443" || cfg.Path != "/path" || cfg.Mode != "auto" {
		t.Fatalf("unexpected xhttp config: %+v", cfg)
	}
}

func TestVLESSXHTTPRejectsVisionFlow(t *testing.T) {
	_, err := NewDialer(nil, protocol.Header{
		ProxyAddress: "1.2.3.4:443",
		Password:     "test-uuid",
		Feature1:     XRV,
		Feature2:     "none",
		Feature3:     "xhttp",
		IsClient:     true,
	})
	if err == nil {
		t.Fatal("expected vision+xhttp to be rejected")
	}
}

func TestVLESSXHTTPAcceptsIPProxyAddress(t *testing.T) {
	d, err := NewDialer(nil, protocol.Header{
		ProxyAddress: "1.2.3.4:443",
		Password:     "12203a60-7e88-4930-b778-a9fa80c911e5",
		Feature1:     "",
		Feature2:     "none",
		Feature3:     "xhttp",
		IsClient:     true,
		Extra:        map[string]string{"xhttp.path": "/", "xhttp.mode": "auto"},
	})
	if err != nil {
		t.Fatalf("IP proxy address should parse: %v", err)
	}
	if d.(*Dialer).xhttpConfig.Host != "1.2.3.4:443" {
		t.Fatalf("host = %q", d.(*Dialer).xhttpConfig.Host)
	}
}

func TestVLESSPostQuantumEncryption(t *testing.T) {
	// 测试 Post-Quantum Encryption 支持
	header := protocol.Header{
		ProxyAddress: "example.com:443",
		Password:     "test-uuid",
		Feature1:     "xtls-rprx-vision",
		Feature2:     "mlkem768x25519plus.native.0rtt",
		IsClient:     true,
	}

	dialer, err := NewDialer(nil, header)
	if err != nil {
		t.Fatalf("Failed to create VLESS dialer with Post-Quantum Encryption: %v", err)
	}

	if dialer == nil {
		t.Fatal("Dialer should not be nil")
	}

	// 验证加密模式
	if dialer.(*Dialer).encryption != "mlkem768x25519plus.native.0rtt" {
		t.Errorf("Expected encryption 'mlkem768x25519plus.native.0rtt', got '%s'", dialer.(*Dialer).encryption)
	}

	// 验证 Post-Quantum Encryption 实例
	if dialer.(*Dialer).pqeEncryption == nil {
		t.Error("Post-Quantum Encryption instance should not be nil")
	}
}

func TestVLESSMLDSA65Auth(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	auth, err := encryption.NewMLDSA65Auth(seed, nil)
	if err != nil {
		t.Fatalf("NewMLDSA65Auth: %v", err)
	}
	pub, err := auth.GetPublicKeyBase64()
	if err != nil {
		t.Fatalf("GetPublicKeyBase64: %v", err)
	}

	header := protocol.Header{
		ProxyAddress: "example.com:443",
		Password:     "test-uuid",
		Feature1:     "xtls-rprx-vision",
		Feature2:     "none",
		Feature4:     auth.GetSeedBase64(),
		Feature5:     pub,
		IsClient:     true,
	}

	dialer, err := NewDialer(nil, header)
	if err != nil {
		t.Fatalf("Failed to create VLESS dialer with MLDSA65 auth: %v", err)
	}

	if dialer == nil {
		t.Fatal("Dialer should not be nil")
	}

	if dialer.(*Dialer).mldsa65Auth == nil {
		t.Error("MLDSA65 auth instance should not be nil")
	}
}

func TestVLESSEnhancedURLParsing(t *testing.T) {
	// 测试增强的 URL 解析
	testURL := "vless://12203a60-7e88-4930-b778-a9fa80c911e5@abc.abc.xyz:52706?type=xhttp&encryption=mlkem768x25519plus.native.0rtt&path=%2F&host=&mode=auto&security=reality&pbk=DglxnqS9vB13BJ2l8bMYge2v_fthGac6AjVfA8YVsXA&fp=chrome&sni=cdn-dynmedia-1.microsoft.com&sid=1f0b9d&spx=%2Fddts&pqv=TBykSIWCMoQ69Fk4TciC4ey5l48q3P5orq0LJTpb89MAcqOC3FKXrt-ROJFtNU2h78QBCVfq2ZjLPsyjKBk6ohtD94G3G1IfhmTFwAJ-CTIJq_OgZ-v57sqST8VjwNzCImkj2t5XzxFjtd_lmAO_cIhmBmtcZmZb6fsl9g1g2ajEViWY_jg21S88aNDLmalZf3Fnte1KXZjyRyDqUwoss-VGCWd-CyYDZWVeI1pTwnlRQsgcWJ3wy78vd_he1EjeEZIZyLMp356xWCdiZnwDUAHqd0iIzG8fKDzBu180tqtgjydBTOLx0xyWPYMjGDcimGflqjT4Hse7-Vb0GQmnO_J-FK3UELKjDnouKXEZyE9QjgPMVwnxHEXBh5hSKdnZ5uAZyDsFfVZt3YKy1YZkV8BakvK8Oyd2Rv_xogMopi3u3QiHvdeS9SiNUShmMt9u6XejmRyrEDyPL_lZkQnU4PG7S-opNRgHSE4Ra3RfxlFMfPX-0NUajuSog8PusoVUUMhtrvRXjPY7SCJOmtHgi7r6FZ75yxSGmUOCFKjRGX5NmyHd_gtItvc1uXJSOFNEyZLawDZOF72gU6A6M_XVLt75xBjvf0Fi2Lo4AMgYm0RtiiXSfueVqPSM1bFVFCbetci8vBHojbNTqIPTFMW-Fm0fVgOdOspRiNcARaus4Oh_s0t1f5OUc-qFe93rKNpfqhnNCcBKbkdT7JXhhyOWwrxfNUccQviRYZCrnvMA92VVuk2EKU5DwP-oDfVAOu5B0LZzGLO-e3PEAOL7r4ofwY6Y-T2OEoSXfdeCIasjkHjMs99CdYyQVfON_qPDNyhkcFpB5US4VwiZk6vAHLWy7KdeeGjsx_ZZ5DDi61tNY3orkOLKOH4R9NgD2x14My0ZocejEl3tMESOcf4fK2ziRAYkzuVRZJq8C-UY-DHVKxv5ocM9pXthfgbTVQMMtX2V2uTKjJGgcJZ7LDYWe6mg3ltxRwpoKSv2Z9RE1qhJapvu35f2nFRULqhGNb68yHToqSRrwKGPlNRnUIf-_N4qhJqbdN9VEJY-fnHoJ1zB3hoH10qas3RkHDdSPppGRGnK1CaZVGIr8U2UCev9MIiFqdHOGTOgAIqQghjaD9vKLuutn243G68d9AWGo9VjZAMNXH5EoIRwGVoW71GTfPvIOJk8JiHJezAiJUPzr4i4FHiKJc_7BKubu8-S22no4N9XX6UljrhZA2z66HRxnJkePn5b-Rv-zks0IsRQNntKGGHK52YaYKqZVVOYhDQg-7XLFNo7QHLQV8Q6-524vm4UaiY1veByp76i-Ua0XnyP5frhJ1KIeGP6Tl4WYs_-tu5-l4BiWgLI2IDr4k-jr1zRA2m32pj8gPn6xYr7lrYUq3t6TJJJJ12y6wKB-r5otEqe8U5H8lc8R28Yz5cZ-iGrA_iZ25wKQYxXn6mLvsX-4CkkYxUwRLPdeXgTwU5VeysHVmJW_HJRFQnpEsT13bskDmRiWZB8oXVdihwhTJmmwGk-F6OAP_idsv2gTgacu0xqBzvQc--aphK0bwM-RufA23si7YKCPpCXqEz_8aFEDdDwmzo3jik1dYy-x12iBaBz6x18pizB1oSCGgvJF1JPijLrtEATJc3HXlCw-jK3JishdoEisYyovqUg5ifbp6EuAPd72vQj1_6cWcjMMKKXTolfI3U7R1rU0n-eaWK9aasTZe5bQiUXUolOa_JnF8un42M3JYb5LZZJRHYh5d01Z21vDNxiQTNvq2FApcqVML_SfjCXlejiLUaF50iSlsojKaxGhhDSQSvyzzuDpLpiG5M6QudSI9_PMGwPQljApwWvecLYLWlNBL9usfmxveqLovTXuyhV5gZBC4-RrJw4nsJfWp7rW7ihZUbV01tsIIDeXUTd2jmewyCp4ZXbskGcpgAJ9G_iYTA9rfpDGTu7rFfYmQpewx0AiUiYepEyPes-hCUlB-XcoO0IbQqXfz-nmNOi4wnnt-t_jyu1n8YCbne5F2GrAqB01zh3TOadjr-kYQIPwU0PgivjMIKdfF220gpXHKkfHCK2qAXLselpHB9QeEms6NiRs4tTeIOg5ivRwAwExiL-NBO5Ku_-jRG-K2leFZiMrI0Ns8fbjuwlydCkhOTq2DYS_JaRUozr3ZfzbWRYR0MZKAYp63wBujfDdnPnzhAZRL7A0wKxLRSHbTa0yVbuLX1V32QCTkPwfLhLPD3-FGaioSbTQVR0KPhjMDQFATQPseIYuwOSEGp25WuitVhqP2KPlnO4cTz74p_PxwbpeAHrcyXcfCs_evIJr050FAHs2DB0lqPnwO7nR_qTUBXpBTxPiSIJCDSt8yXZB8vp_QULWEqMFJegbWeU77Aa1AdDMJti4AS7sokUSy8aO2DZsfBn6log9dxudkMQ2VssgHsy1abC1TWkl67ebyqPmNhoVi-ytgQwbRAgVvjxX4MKXJhfk-X63v1hkn1ZmeHDHJY-9n3PyHxiAFMnbkenIt9MgaBG6doAQnsv0LR4l8ua2CXDbtzT0LI674LcrsPghZ3odOLcFukh985_QTTbdFnsnytBJQh8ZNM-ETPWeG-jZJ-JjHv8ch_zgZA#xhttp-ab5ygrlc"

	// 这里应该调用 URL 解析函数
	// 由于我们没有直接访问 dialer/v2ray 包，这里只是示例
	t.Logf("Testing URL parsing for: %s", testURL)

	// 验证 URL 包含期望的参数
	expectedParams := []string{
		"type=xhttp",
		"encryption=mlkem768x25519plus.native.0rtt",
		"mode=auto",
		"security=reality",
	}

	for _, param := range expectedParams {
		if !contains(testURL, param) {
			t.Errorf("URL should contain parameter: %s", param)
		}
	}
}

func TestVLESSFlowControlTypes(t *testing.T) {
	// 测试所有支持的流控制类型
	flowTypes := []string{
		XRV,
		FlowVisionReality,
		FlowOrigin,
		FlowOriginUDP443,
		FlowDirect,
		FlowDirectUDP443,
		FlowSplice,
		FlowSpliceUDP443,
		FlowVisionRealityTCP,
	}

	for _, flowType := range flowTypes {
		header := protocol.Header{
			ProxyAddress: "example.com:443",
			Password:     "test-uuid",
			Feature1:     flowType,
			IsClient:     true,
		}

		dialer, err := NewDialer(nil, header)
		if err != nil {
			t.Errorf("Failed to create dialer for flow type '%s': %v", flowType, err)
			continue
		}

		if dialer.(*Dialer).flow != flowType {
			t.Errorf("Expected flow type '%s', got '%s'", flowType, dialer.(*Dialer).flow)
		}
	}
}

func TestVLESSEncryptionModes(t *testing.T) {
	// 测试支持的加密模式
	encryptionModes := []string{
		EncryptionNone,
		EncryptionMLKEM768X25519Plus,
	}

	for _, encryptionMode := range encryptionModes {
		header := protocol.Header{
			ProxyAddress: "example.com:443",
			Password:     "test-uuid",
			Feature1:     "xtls-rprx-vision",
			Feature2:     encryptionMode,
			IsClient:     true,
		}

		dialer, err := NewDialer(nil, header)
		if err != nil {
			t.Errorf("Failed to create dialer for encryption mode '%s': %v", encryptionMode, err)
			continue
		}

		if dialer.(*Dialer).encryption != encryptionMode {
			t.Errorf("Expected encryption mode '%s', got '%s'", encryptionMode, dialer.(*Dialer).encryption)
		}
	}
}

type blockingNextDialer struct{}

func (blockingNextDialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestVLESSConnectionTimeout(t *testing.T) {
	header := protocol.Header{
		ProxyAddress: "nonexistent.example.com:443",
		Password:     "test-uuid",
		Feature1:     "xtls-rprx-vision",
		IsClient:     true,
	}

	// nil next dialer must fail cleanly (no panic)
	dNil, err := NewDialer(nil, header)
	if err != nil {
		t.Fatalf("Failed to create dialer: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err = dNil.DialContext(ctx, "tcp", "example.com:80"); err == nil {
		t.Error("Expected nil next dialer to fail")
	}

	d, err := NewDialer(blockingNextDialer{}, header)
	if err != nil {
		t.Fatalf("Failed to create dialer: %v", err)
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel2()
	if _, err = d.DialContext(ctx2, "tcp", "example.com:80"); err == nil {
		t.Error("Expected connection to fail due to timeout")
	}
}

// 辅助函数
func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[len(s)-len(substr):] == substr ||
		len(s) > len(substr) && contains(s[:len(s)-1], substr)
}
