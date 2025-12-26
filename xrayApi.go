package main

import (
	"context"
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/app/proxyman/command"
	statsService "github.com/xtls/xray-core/app/stats/command"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vmess"
	vmessInbound "github.com/xtls/xray-core/proxy/vmess/inbound"
	"github.com/xtls/xray-core/transport/internet"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport/internet/httpupgrade"
	"github.com/xtls/xray-core/transport/internet/kcp"
	"github.com/xtls/xray-core/transport/internet/tcp"
	"github.com/xtls/xray-core/transport/internet/tls"
	"github.com/xtls/xray-core/transport/internet/websocket"
	"google.golang.org/grpc"
)

type XrayController struct {
	HsClient *command.HandlerServiceClient
	SsClient *statsService.StatsServiceClient
	CmdConn  *grpc.ClientConn
}

func (x *XrayController) Init(cfg *BaseConfig) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.New(fmt.Sprintf("init apt of XRAY error - %s", r))
		}
	}()
	x.CmdConn, err = grpc.Dial(fmt.Sprintf("%s:%d", cfg.Proxy.APIAddress, cfg.Proxy.APIPort), grpc.WithInsecure())
	if err != nil {
		return err
	}
	hsClient := command.NewHandlerServiceClient(x.CmdConn)
	ssClient := statsService.NewStatsServiceClient(x.CmdConn)

	x.HsClient = &hsClient
	x.SsClient = &ssClient

	return
}

func (x *XrayController) AddUsers(users *[]UserInfo) (err error) {
	for _, u := range *users {
		switch u.Protocol {
		case "vmess":
			err = addVmessUser(*x.HsClient, &u)
		case "trojan":
			err = addTrojanUser(*x.HsClient, &u)
		case "ss":
			err = addSSUser(*x.HsClient, &u)
		case "vless":
			err = addVlessUser(*x.HsClient, &u)
		}

		if err != nil {
			return err
		}
	}
	return
}

func addVmessUser(client command.HandlerServiceClient, user *UserInfo) error {
	_, err := client.AlterInbound(context.Background(), &command.AlterInboundRequest{
		Tag: user.InTag,
		Operation: serial.ToTypedMessage(&command.AddUserOperation{
			User: &protocol.User{
				Level: user.Level,
				Email: user.Tag,
				Account: serial.ToTypedMessage(&vmess.Account{
					Id: user.Uuid,
					// AlterId: user.AlterId,
				}),
			},
		}),
	})
	return err
}

func addVlessUser(client command.HandlerServiceClient, user *UserInfo) error {
	_, err := client.AlterInbound(context.Background(), &command.AlterInboundRequest{
		Tag: user.InTag,
		Operation: serial.ToTypedMessage(&command.AddUserOperation{
			User: &protocol.User{
				Level: user.Level,
				Email: user.Tag,
				Account: serial.ToTypedMessage(&vless.Account{
					Id:   user.Uuid,
					Flow: "xtls-rprx-direct",
				}),
			},
		}),
	})
	return err
}

func addSSUser(client command.HandlerServiceClient, user *UserInfo) error {
	var ssCipherType shadowsocks.CipherType
	switch user.CipherType {
	case "aes-128-gcm":
		ssCipherType = shadowsocks.CipherType_AES_128_GCM
	case "aes-256-gcm":
		ssCipherType = shadowsocks.CipherType_AES_256_GCM
	case "chacha20-ietf-poly1305":
		ssCipherType = shadowsocks.CipherType_CHACHA20_POLY1305
	}

	_, err := client.AlterInbound(context.Background(), &command.AlterInboundRequest{
		Tag: user.InTag,
		Operation: serial.ToTypedMessage(&command.AddUserOperation{
			User: &protocol.User{
				Level: user.Level,
				Email: user.Tag,
				Account: serial.ToTypedMessage(&shadowsocks.Account{
					Password:   user.Password,
					CipherType: ssCipherType,
				}),
			},
		}),
	})
	return err
}

func addTrojanUser(client command.HandlerServiceClient, user *UserInfo) error {
	_, err := client.AlterInbound(context.Background(), &command.AlterInboundRequest{
		Tag: user.InTag,
		Operation: serial.ToTypedMessage(&command.AddUserOperation{
			User: &protocol.User{
				Level: user.Level,
				Email: user.Tag,
				Account: serial.ToTypedMessage(&trojan.Account{
					Password: user.Uuid,
				}),
			},
		}),
	})
	return err
}

func removeUser(client command.HandlerServiceClient, user *UserInfo) error {
	_, err := client.AlterInbound(context.Background(), &command.AlterInboundRequest{
		Tag: user.InTag,
		Operation: serial.ToTypedMessage(&command.RemoveUserOperation{
			Email: user.Tag,
		}),
	})
	return err
}

func (x *XrayController) RemoveUsers(users *[]UserInfo) (err error) {
	for _, u := range *users {
		err = removeUser(*x.HsClient, &u)
		if err != nil {
			return err
		}
	}

	return
}

func (x *XrayController) QueryUsersTraffic(users *[]UserInfo) (usersTraffic *[]UserTraffic, err error) {
	usersTraffic = new([]UserTraffic)
	var ut UserTraffic

	for _, u := range *users {
		ut.Id = u.Id
		ut.Up, err = queryUserTraffic(*x.SsClient, u.Tag, "up")
		ut.Down, err = queryUserTraffic(*x.SsClient, u.Tag, "down")
		// when a user used this node, post traffic data
		if ut.Up+ut.Down > 0 {
			*usersTraffic = append(*usersTraffic, ut)
		}
		if err != nil {
			return
		}
	}

	return
}

func queryUserTraffic(c statsService.StatsServiceClient, userId, direction string) (traffic int64, err error) {
	// var userTraffic *string
	traffic = 0
	ptn := fmt.Sprintf("user>>>%s>>>traffic>>>%slink", userId, direction)
	resp, err := c.QueryStats(context.Background(), &statsService.QueryStatsRequest{
		Pattern: ptn,
		Reset_:  true, // reset traffic data everytime
	})
	if err != nil {
		return
	}
	// Get traffic data
	stat := resp.GetStat()

	if len(stat) != 0 {
		traffic = stat[0].Value
	} else {
		traffic = 0
	}
	return
}

func (x *XrayController) AddInbound(node *NodeInfo) (err error) {
	return addInbound(*x.HsClient, node)
}

func (x *XrayController) RemoveInbound(node *NodeInfo) (err error) {
	return removeInbound(*x.HsClient, node)
}

func addInbound(client command.HandlerServiceClient, node *NodeInfo) (err error) {
	var (
		protocolName      string
		transportSettings []*internet.TransportConfig
		securityType      string
		securitySettings  []*serial.TypedMessage
		proxySetting      *serial.TypedMessage
	)

	switch node.Protocol {
	case "vmess":
		proxySetting = serial.ToTypedMessage(&vmessInbound.Config{})
	case "trojan":
		proxySetting = serial.ToTypedMessage(&trojan.ServerConfig{})
	case "ss":
		proxySetting = serial.ToTypedMessage(&shadowsocks.ServerConfig{
			Network: []net.Network{2, 3},
		})
	case "vless":
		err = errors.New("unsupported to auto create VLESS inbounds")
		return err
	}

	switch node.TransportMode {
	case "ws":
		protocolName = "websocket"
		if node.Path == "" {
			node.Path = "/"
		}

		header := map[string]string{
			"Host": node.Host,
		}

		transportSettings = []*internet.TransportConfig{
			{
				ProtocolName: protocolName,
				Settings: serial.ToTypedMessage(&websocket.Config{
					Path:                node.Path,
					Header:              header,
					AcceptProxyProtocol: node.EnableProxyProtocol,
				},
				),
			},
		}

	case "tcp":
		protocolName = "tcp"
		transportSettings = []*internet.TransportConfig{
			{
				ProtocolName: protocolName,
				Settings: serial.ToTypedMessage(&tcp.Config{
					AcceptProxyProtocol: node.EnableProxyProtocol,
				}),
			},
		}
	case "kcp":
		protocolName = "mkcp"
		transportSettings = []*internet.TransportConfig{
			{
				ProtocolName: protocolName,
				Settings:     serial.ToTypedMessage(&kcp.Config{}),
			},
		}
	case "http":
		protocolName = "http"
		transportSettings = []*internet.TransportConfig{
			{
				ProtocolName: protocolName,
				Settings: serial.ToTypedMessage(&httpupgrade.Config{
					Host: node.Host,
					Path: node.Path,
				}),
			},
		}

	}

	if node.EnableTLS == true && node.Cert.CertPath != "" && node.Cert.KeyPath != "" {
		// Use custom cert file
		certConfig := &conf.TLSCertConfig{
			CertFile: node.Cert.CertPath,
			KeyFile:  node.Cert.KeyPath,
		}
		builtCert, err := certConfig.Build()
		if err != nil {
			return err
		}
		securityType = serial.GetMessageType(&tls.Config{})
		securitySettings = []*serial.TypedMessage{
			serial.ToTypedMessage(&tls.Config{
				Certificate: []*tls.Certificate{builtCert},
			}),
		}
	} else if node.EnableTLS == true {
		// Auto build cert
		securityType = serial.GetMessageType(&tls.Config{})
		securitySettings = []*serial.TypedMessage{
			serial.ToTypedMessage(&tls.Config{
				Certificate: []*tls.Certificate{tls.ParseCertificate(cert.MustGenerate(nil))},
			}),
		}
	} else {
		// Disable TLS
		securityType = ""
		securitySettings = nil
	}

	_, err = client.AddInbound(context.Background(), &command.AddInboundRequest{
		Inbound: &core.InboundHandlerConfig{
			Tag: node.Tag,
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
				//PortList: &net.PortList{
				//	Range: []*net.PortRange{net.SinglePortRange(net.Port(node.ListenPort))},
				//},
				PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(net.Port(node.ListenPort))}},
				Listen:   net.NewIPOrDomain(net.AnyIP),
				SniffingSettings: &proxyman.SniffingConfig{
					Enabled:             node.EnableSniffing,
					DestinationOverride: []string{"http", "tls"},
				},
				StreamSettings: &internet.StreamConfig{
					ProtocolName:      protocolName,
					TransportSettings: transportSettings,
					SecurityType:      securityType,
					SecuritySettings:  securitySettings,
				},
			}),
			ProxySettings: proxySetting,
		},
	})

	return err
}

func removeInbound(client command.HandlerServiceClient, node *NodeInfo) error {
	_, err := client.RemoveInbound(context.Background(), &command.RemoveInboundRequest{
		Tag: node.Tag,
	})
	return err
}

func initProxyCore() (apiClient ProxyCommand, err error) {
	switch baseCfg.Proxy.Type {
	case "xray":
		apiClient = new(XrayController)
		for {
			err = apiClient.Init(baseCfg)
			if err != nil {
				log.Error(err)
			} else {
				break
			}
		}
		return
	default:
		err = errors.New("unsupported proxy core")
		return
	}
}
