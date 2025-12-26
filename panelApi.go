package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bitly/go-simplejson"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func initPanel(idIndex uint32) (node PanelCommand, err error) {
	switch baseCfg.Panel.Type {
	//case "sspanel":
	//	node = new(SspController)
	//	err = node.Init(baseCfg, idIndex)
	//	if err != nil {
	//		log.Error(err)
	//	}
	//	return
	case "v2board":
		node = new(V2bController)
		err = node.Init(baseCfg, idIndex)
		if err != nil {
			log.Error(err)
		}
		return
	//case "django-sspanel":
	//	node = new(DjSspController)
	//	err = node.Init(baseCfg, idIndex)
	//	if err != nil {
	//		log.Error(err)
	//	}
	//	return
	default:
		err = errors.New("unsupported panel type")
		return nil, err
	}
}

// V2boardAPI
type V2bController struct {
	URL      string
	Key      string
	NodeInfo *NodeInfo
}

func (v2bCtl *V2bController) GetNodeInfo(closeTLS bool) (err error) {
	return getNodeInfo(v2bCtl, closeTLS)
}

func (v2bCtl *V2bController) GetUser() (userList *[]UserInfo, err error) {
	return getUser(v2bCtl)
}

func (v2bCtl *V2bController) PostTraffic(trafficData *[]UserTraffic) (err error) {
	return postTraffic(v2bCtl, trafficData)
}

func (v2bCtl *V2bController) PostSysLoad(load *SysLoad) (err error) {
	return errors.New("unsupported method")
}

func (v2bCtl *V2bController) PostAliveIP(baseCfg *BaseConfig, userIP *[]UserIP) (err error) {
	return errors.New("unsupported method")
}

func (v2bCtl *V2bController) GetNowInfo() (nodeInfo *NodeInfo) {
	return v2bCtl.NodeInfo
}

func (v2bCtl *V2bController) Init(cfg *BaseConfig, idIndex uint32) (err error) {
	v2bCtl.NodeInfo = new(NodeInfo)
	v2bCtl.URL = cfg.Panel.URL
	v2bCtl.Key = cfg.Panel.Key
	v2bCtl.NodeInfo.Id = cfg.Panel.NodeIDs[idIndex]
	v2bCtl.NodeInfo.IdIndex = idIndex
	// 预先写入，如果没有获取到节点配置则使用配置文件的alterID
	v2bCtl.NodeInfo.AlterID = cfg.Proxy.AlterID
	v2bCtl.NodeInfo.Tag = cfg.Proxy.InTags[idIndex]
	v2bCtl.NodeInfo.Cert = cfg.Proxy.Cert
	v2bCtl.NodeInfo.EnableSniffing = cfg.Proxy.EnableSniffing
	// Not force
	if len(cfg.Panel.NodesProxyProtocol) > int(idIndex) {
		v2bCtl.NodeInfo.EnableProxyProtocol = cfg.Panel.NodesProxyProtocol[idIndex]
	} else {
		v2bCtl.NodeInfo.EnableProxyProtocol = false
	}

	switch strings.ToLower(cfg.Panel.NodesType[idIndex]) {
	case "v2ray":
		v2bCtl.NodeInfo.Protocol = "vmess"
	case "vmess":
		v2bCtl.NodeInfo.Protocol = "vmess"
	case "trojan":
		v2bCtl.NodeInfo.Protocol = "trojan"
	case "ss":
		v2bCtl.NodeInfo.Protocol = "ss"
	default:
		err = errors.New("unsupported protocol")
	}

	return err
}

/**
 *
 * node func
 */
func getNodeInfo(node *V2bController, closeTLS bool) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.New(fmt.Sprintf("get nodeInfo from v2board failed %s", r))
		}
	}()

	client := &http.Client{Timeout: 40 * time.Second}
	defer client.CloseIdleConnections()
	apiURL := ""
	switch node.NodeInfo.Protocol {
	case "vmess":
		apiURL = "api/v1/server/Deepbwork/config"
	case "trojan":
		apiURL = "api/v1/server/TrojanTidalab/config"
	case "ss":
		node.NodeInfo.TransportMode = "tcp"
		node.NodeInfo.EnableTLS = false
		return err
	}

	req, err := http.NewRequest("GET", fmt.Sprintf("%s/%s?node_id=%v&token=%s&local_port=1", node.URL, apiURL, node.NodeInfo.Id, node.Key), nil)
	if err != nil {
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		return
	}

	bodyText, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}

	rtn, err := simplejson.NewJson(bodyText)
	if err != nil {
		return
	}

	if rtn.Get("message").MustString() != "" {
		return errors.New(fmt.Sprintf("Server error - %s", rtn.Get("message").MustString()))
	}

	switch node.NodeInfo.Protocol {
	case "vmess":
		err = parseVmessRawInfo(rtn, node.NodeInfo, closeTLS)
	case "trojan":
		err = parseTrojanRawInfo(rtn, node.NodeInfo, closeTLS)
	}

	if err != nil {
		return
	}

	return nil
}

func parseVmessRawInfo(rtnJson *simplejson.Json, node *NodeInfo, closeTLS bool) (err error) {
	// Thanks XrayR
	inboundInfo := simplejson.New()
	if tmpInboundInfo, ok := rtnJson.CheckGet("inbound"); ok {
		inboundInfo = tmpInboundInfo
		// Compatible with v2board 1.5.5-dev
	} else if tmpInboundInfo, ok = rtnJson.CheckGet("inbounds"); ok {
		tmpInboundInfo := tmpInboundInfo.MustArray()
		marshalByte, _ := json.Marshal(tmpInboundInfo[0].(map[string]interface{}))
		inboundInfo, _ = simplejson.NewJson(marshalByte)
	} else {
		return fmt.Errorf("Unable to find inbound(s) in the nodeInfo.")
	}
	node.ListenPort = uint32(inboundInfo.Get("port").MustInt())
	node.TransportMode = inboundInfo.Get("streamSettings").Get("network").MustString()

	switch node.TransportMode {
	case "ws":
		node.Path = inboundInfo.Get("streamSettings").Get("wsSettings").Get("path").MustString()
		node.Host = inboundInfo.Get("streamSettings").Get("wsSettings").Get("headers").Get("Host").MustString()
	}

	if inboundInfo.Get("streamSettings").Get("security").MustString() == "tls" && closeTLS == false {
		node.EnableTLS = true
	} else {
		node.EnableTLS = false
	}

	return err
}

func parseTrojanRawInfo(rtnJson *simplejson.Json, node *NodeInfo, closeTLS bool) (err error) {
	node.ListenPort = uint32(rtnJson.Get("local_port").MustInt())
	node.Host = rtnJson.Get("ssl").Get("sni").MustString()
	node.TransportMode = "tcp"
	if closeTLS == false {
		node.EnableTLS = true
	} else {
		node.EnableTLS = false
	}

	return err
}

/**
 *
 * node func end
 */

func postTraffic(node *V2bController, trafficData *[]UserTraffic) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.New("unplanned outages when post traffic data")
		}
	}()

	bodyJson, err := json.Marshal(*trafficData)
	if err != nil {
		return
	}
	client := &http.Client{Timeout: 40 * time.Second}
	defer client.CloseIdleConnections()
	apiURL := ""
	switch node.NodeInfo.Protocol {
	case "vmess":
		apiURL = "api/v1/server/Deepbwork/submit"
	case "trojan":
		apiURL = "api/v1/server/TrojanTidalab/submit"
	case "ss":
		apiURL = "api/v1/server/ShadowsocksTidalab/submit"
	}
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/%s?node_id=%v&token=%s", node.URL, apiURL, node.NodeInfo.Id, node.Key), bytes.NewBuffer(bodyJson))
	if err != nil {
		return
	}
	// Use json type
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	bodyText, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	rtn, err := simplejson.NewJson(bodyText)
	if err != nil {
		return
	}
	if rtn.Get("ret").MustInt() != 1 {
		return errors.New("server error or node not found")
	}

	return
}

func getUser(node *V2bController) (userList *[]UserInfo, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.New(fmt.Sprintf("get users from v2board failed %s", r))
		}
	}()

	userList = new([]UserInfo)
	user := UserInfo{}

	client := &http.Client{Timeout: 40 * time.Second}
	defer client.CloseIdleConnections()
	apiURL := ""
	switch node.NodeInfo.Protocol {
	case "vmess":
		apiURL = "api/v1/server/Deepbwork/user"
	case "trojan":
		apiURL = "api/v1/server/TrojanTidalab/user"
	case "ss":
		apiURL = "api/v1/server/ShadowsocksTidalab/user"
	}
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/%s?node_id=%v&token=%s&local_port=1", node.URL, apiURL, node.NodeInfo.Id, node.Key), nil)
	if err != nil {
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	bodyText, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	rtn, err := simplejson.NewJson(bodyText)
	if err != nil {
		return
	}

	numOfUsers := len(rtn.Get("data").MustArray())

	for u := 0; u < numOfUsers; u++ {
		user.Id = uint32(rtn.Get("data").GetIndex(u).Get("id").MustInt())
		user.Level = 0
		user.InTag = node.NodeInfo.Tag
		user.Tag = fmt.Sprintf("%s-%s", strconv.FormatUint(uint64(user.Id), 10), user.InTag)
		user.Protocol = node.NodeInfo.Protocol
		switch node.NodeInfo.Protocol {
		case "ss":
			user.Password = rtn.Get("data").GetIndex(u).Get("secret").MustString()
			user.CipherType = rtn.Get("data").GetIndex(u).Get("cipher").MustString()
			//set ss port
			if u == 0 && node.NodeInfo.Protocol == "ss" {
				node.NodeInfo.ListenPort = uint32(rtn.Get("data").GetIndex(u).Get("port").MustInt())
			}
		case "trojan":
			user.Uuid = rtn.Get("data").GetIndex(u).Get("trojan_user").Get("password").MustString()
		case "vmess":
			user.Uuid = rtn.Get("data").GetIndex(u).Get("v2ray_user").Get("uuid").MustString()
			user.AlterId = uint32(rtn.Get("data").GetIndex(u).Get("v2ray_user").Get("alter_id").MustInt())
		}

		*userList = append(*userList, user)
	}

	return
}

/***
 *
 *
 *
 */

// SSPanelAPI
type SspController struct {
	URL      string
	Key      string
	NodeInfo *NodeInfo
}

func (sspCtl *SspController) Init(cfg *BaseConfig, idIndex uint32) (err error) {
	sspCtl.NodeInfo = new(NodeInfo)
	sspCtl.URL = cfg.Panel.URL
	sspCtl.Key = cfg.Panel.Key
	sspCtl.NodeInfo.Id = cfg.Panel.NodeIDs[idIndex]
	sspCtl.NodeInfo.IdIndex = idIndex
	// 预先写入，如果没有获取到节点配置则使用配置文件的alterID
	sspCtl.NodeInfo.AlterID = cfg.Proxy.AlterID
	sspCtl.NodeInfo.Tag = cfg.Proxy.InTags[idIndex]
	sspCtl.NodeInfo.Cert = cfg.Proxy.Cert
	sspCtl.NodeInfo.EnableSniffing = cfg.Proxy.EnableSniffing

	return err
}

// DjangoSSPanelAPI
type DjSspController struct {
	URL      string
	Key      string
	NodeInfo *NodeInfo
}

func (djsspCtl *DjSspController) Init(cfg *BaseConfig, idIndex uint32) (err error) {
	djsspCtl.NodeInfo = new(NodeInfo)
	djsspCtl.URL = cfg.Panel.URL
	djsspCtl.Key = cfg.Panel.Key
	djsspCtl.NodeInfo.Id = cfg.Panel.NodeIDs[idIndex]
	djsspCtl.NodeInfo.IdIndex = idIndex
	// 预先写入，如果没有获取到节点配置则使用配置文件的alterID
	djsspCtl.NodeInfo.AlterID = cfg.Proxy.AlterID
	djsspCtl.NodeInfo.Tag = cfg.Proxy.InTags[idIndex]
	djsspCtl.NodeInfo.Cert = cfg.Proxy.Cert
	djsspCtl.NodeInfo.EnableSniffing = cfg.Proxy.EnableSniffing

	switch strings.ToLower(cfg.Panel.NodesType[idIndex]) {
	case "v2ray":
		djsspCtl.NodeInfo.Protocol = "vmess"
	case "vmess":
		djsspCtl.NodeInfo.Protocol = "vmess"
	case "trojan":
		djsspCtl.NodeInfo.Protocol = "trojan"
	case "ss":
		djsspCtl.NodeInfo.Protocol = "ss"
	default:
		err = errors.New("unsupported protocol")
	}

	return err
}
