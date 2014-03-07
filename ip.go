package ip

import "fmt"

type IPAnalyzer interface {
	//Init adapter via dbFile
	Init(dbFile string) error
	//Analyze ip string, return location and isp
	Analyze(ip string) (string, string, error)
}

var adapters = make(map[string]IPAnalyzer)

//Adapter register
func Register(name string, adapter IPAnalyzer) {
	if _, dup := adapters[name]; dup {
		panic("IPAnalyzer: name conflict: " + name)
	}
	adapters[name] = adapter
}

//Create a IP analyzer, according to adapterName, initialized via dbFile 
func NewIPAnalyzer(adapterName, dbFile string) (IPAnalyzer, error) {
	adapter, ok := adapters[adapterName]
	if !ok {
		return nil, fmt.Errorf("IPAnalyzer: unknown adapter %q", adapterName)
	}

	e := adapter.Init(dbFile)
	if e != nil {
		return nil, e
	}

	return adapter, nil
}

//BigEndian to native host int
func ntohl(b []byte) uint32 {
	var n uint32
	cnt := len(b) - 1
	for i := 0; i <= cnt; i++ {
		n |= uint32(b[i]) << (uint(cnt-i) * 8)
	}
	return n
}

//LittleEndian to native host int
func ltohl(b []byte) uint32 {
	var n uint32
	cnt := len(b) - 1
	for i := cnt; i >= 0; i-- {
		n |= uint32(b[i]) << (uint(i) * 8)
	}
	return n
}
