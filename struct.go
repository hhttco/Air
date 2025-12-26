package main

type BaseConfig struct {
	Log   Log   `json:"log"`
	Panel Panel `json:"panel"`
	Proxy Proxy `json:"proxy"`
	Sync  Sync  `json:"sync"`
}

type Log struct {
	LogLevel string `json:"log_level"`
	Access   string `json:"access"`
}

type Panel struct {
	Type               string   `json:"type"`
	URL                string   `json:"url"`
	Key                string   `json:"key"`
	NodeIDs            []uint32 `json:"node_ids"`
	NodesType          []string `json:"nodes_type"`
	NodesProxyProtocol []bool   `json:"nodes_proxy_protocol"`
}

type Proxy struct {
	Type            string    `json:"type"`
	AlterID         uint32    `json:"alter_id"`
	AutoGenerate    bool      `json:"auto_generate"`
	InTags          []string  `json:"in_tags"`
	APIAddress      string    `json:"api_address"`
	APIPort         uint32    `json:"api_port"`
	ConfigPath      string    `json:"config_path"`
	LogPath         string    `json:"log_path"`
	ForceCloseTLS   bool      `json:"force_close_tls"`
	EnableSniffing  bool      `json:"enable_sniffing"`
	Cert            Cert      `json:"cert"`
	SpeedLimitLevel []float32 `json:"speed_limit_level"`
}

type Sync struct {
	Interval       uint32 `json:"interval"`
	FailDelay      uint32 `json:"fail_delay"`
	Timeout        uint32 `json:"timeout"`
	PostIPInterval uint32 `json:"post_ip_interval"`
}

type Cert struct {
	CertPath string `json:"cert_path"`
	KeyPath  string `json:"key_path"`
}

// node
type NodeInfo struct {
	Id                  uint32
	IdIndex             uint32
	Tag                 string
	SpeedLimit          uint32 `json:"node_speedlimit"`
	Sort                uint32 `json:"sort"`
	RawInfo             string `json:"server"`
	Url                 string
	Protocol            string
	CipherType          string
	ListenPort          uint32
	AlterID             uint32
	EnableSniffing      bool
	EnableTLS           bool
	EnableProxyProtocol bool
	TransportMode       string
	Path                string
	Host                string
	Cert                Cert
}

type SysLoad struct {
	Uptime uint64
	Load1  float64
	Load5  float64
	Load15 float64
}

type UserIP struct {
	Id      uint32
	InTag   string
	AliveIP []string
}

// ===
type UserInfo struct {
	Id      uint32
	Uuid    string
	AlterId uint32
	// Level will use for speed limit
	Level uint32
	InTag string
	// Tag = Id + “-” + InTag
	Tag string
	// Protocol Vmess, trojan..
	Protocol   string
	CipherType string
	Password   string
	SpeedLimit uint32
	MaxClients uint32
	// 单端口承载用户标识，true代表该用户为单端口承载用户
	SSConfig bool
}

type UserTraffic struct {
	Id   uint32 `json:"user_id"`
	Up   int64  `json:"u"`
	Down int64  `json:"d"`
}
