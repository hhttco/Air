package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/shirou/gopsutil/host"
	"github.com/shirou/gopsutil/load"
	log "github.com/sirupsen/logrus"
	"os"
	"reflect"
)

var (
	baseCfg = &BaseConfig{
		Log: Log{
			LogLevel: "info",
			Access:   "",
		},
		Panel: Panel{
			Type: "sspanel",
		},
		Proxy: Proxy{
			Type:           "xray",
			AlterID:        1,
			AutoGenerate:   true,
			InTags:         []string{},
			APIAddress:     "127.0.0.1",
			APIPort:        10085,
			LogPath:        "/var/log/au/xr.log",
			ForceCloseTLS:  false,
			EnableSniffing: true,
			Cert: Cert{
				CertPath: "/usr/local/share/au/server.crt",
				KeyPath:  "/usr/local/share/au/server.key",
			},
		},
		Sync: Sync{
			Interval:       60,
			FailDelay:      5,
			Timeout:        5,
			PostIPInterval: 90,
		},
	}
)

// 基础配置
func ParseBaseConfig(configPath *string) (*BaseConfig, error) {
	file, err := os.Open(*configPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	if err := json.NewDecoder(file).Decode(baseCfg); err != nil {
		return nil, err
	}

	if baseCfg.Proxy.AutoGenerate == true {
		if len(baseCfg.Proxy.InTags) < len(baseCfg.Panel.NodeIDs) {
			log.Debugf("InTags length isn't equal to nodeID length, adding inTags")
			for n := len(baseCfg.Proxy.InTags); n < len(baseCfg.Panel.NodeIDs); n++ {
				baseCfg.Proxy.InTags = append(baseCfg.Proxy.InTags, fmt.Sprintf("p%v", n))
			}
		}
	}

	return baseCfg, nil
}

// 检查配置
func checkCfg() (err error) {
	switch baseCfg.Panel.Type {
	case "sspanel":
		break
	case "v2board":
		break
	case "django-sspanel":
		break
	default:
		err = errors.New("unsupported panel type")
		return
	}

	switch baseCfg.Proxy.Type {
	case "v2ray":
		break
	case "xray":
		break
	default:
		err = errors.New("unsupported proxy type")
		return
	}

	if len(baseCfg.Panel.NodeIDs) != len(baseCfg.Proxy.InTags) {
		err = errors.New("node_ids length isn't equal to in_tags length")
	}

	if len(baseCfg.Panel.NodeIDs) != len(baseCfg.Panel.NodesType) && baseCfg.Panel.Type == "v2board" {
		err = errors.New("node_ids length isn't equal to nodes_type length")
	}

	return
}

// command 对接API使用
type ProxyCommand interface {
	Init(cfg *BaseConfig) error
	AddUsers(user *[]UserInfo) error
	RemoveUsers(user *[]UserInfo) error
	QueryUsersTraffic(user *[]UserInfo) (*[]UserTraffic, error)
	AddInbound(node *NodeInfo) (err error)
	RemoveInbound(node *NodeInfo) (err error)
}

type PanelCommand interface {
	Init(cfg *BaseConfig, idIndex uint32) error
	GetNodeInfo(closeTLS bool) (err error)
	GetUser() (userList *[]UserInfo, err error)
	PostTraffic(trafficData *[]UserTraffic) (err error)
	PostSysLoad(load *SysLoad) (err error)
	PostAliveIP(baseCfg *BaseConfig, userIP *[]UserIP) (err error)
	GetNowInfo() (nodeInfo *NodeInfo)
}

/**
 *
 *
 * 向上匹配限速策略，即如果策略限制只有 1Mbps, 10Mbps 用户限速5Mbps 最终会匹配到 10Mbps
 */
func AddLevel(users *[]UserInfo, sl []float32) (err error) {
	var speedIndex uint32
	// 不限速策略，默认使用level0
	for userIndex := 0; userIndex < len(*users); userIndex++ {
		userSpeedLimit := float32((*users)[userIndex].SpeedLimit)

		if userSpeedLimit == 0 || userSpeedLimit > sl[len(sl)-1] {
			(*users)[userIndex].Level = 0
			continue
		}

		for speedIndex = 1; int(speedIndex) < len(sl); speedIndex++ {
			if userSpeedLimit > sl[speedIndex] {
				continue
			} else if userSpeedLimit <= sl[speedIndex] {
				(*users)[userIndex].Level = speedIndex
				break
			}
		}
	}

	return err
}

func FindUserDiffer(before, now *[]UserInfo) (remove, add *[]UserInfo, err error) {
	defer func() {
		if r := recover(); r != nil {
			remove = new([]UserInfo)
			add = new([]UserInfo)
			err = errors.New(fmt.Sprintf("model FindUserDiffer cause error - %s", r))
		}
	}()

	remove = new([]UserInfo)
	add = new([]UserInfo)
	// 对于空的对象要处理下，因为会死循环
	if len(*before) == 0 {
		return remove, now, err
	} else if len(*now) == 0 {
		return before, add, err
	}

	n := 0
	b := 0
	//nLastAppear := false
	//bLastAppear := false
	for true {
		if (*before)[b] == (*now)[n] {
			n++
			b++
		} else if (*before)[b].Id < (*now)[n].Id {
			// (*before)[b] has been removed
			*remove = append(*remove, (*before)[b])
			b++
		} else if (*before)[b].Id > (*now)[n].Id {
			// (*now)[n] has been inserted
			*add = append(*add, (*now)[n])
			n++
		} else if (*before)[b].Id == (*now)[n].Id && reflect.DeepEqual((*before)[b], (*now)[n]) == false {
			//user (*before)[b] changed uuid
			*remove = append(*remove, (*before)[b])
			*add = append(*add, (*now)[n])
			n++
			b++
			// Last one will tagged
			//continue
		}
		// any userList finished, break and add remainder users to remove or add
		if n == len(*now) || b == len(*before) {
			break
		}
	}

	// left users will add or remove
	if b != len(*before) {
		for u := b; u < len(*before); u++ {
			*remove = append(*remove, (*before)[u])
		}
	} else if n != len(*now) {
		for u := n; u < len(*now); u++ {
			*add = append(*add, (*now)[u])
		}
	}

	return
}

func GetSysLoad() (sysLoad *SysLoad, err error) {
	sysLoad = new(SysLoad)
	sLoad, err := load.Avg()
	if err != nil {
		return nil, err
	}
	sysLoad.Load1 = sLoad.Load1
	sysLoad.Load5 = sLoad.Load5
	sysLoad.Load15 = sLoad.Load15

	sysLoad.Uptime, err = host.Uptime()
	if err != nil {
		return nil, err
	}

	return
}
