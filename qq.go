package ip

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/qiniu/iconv"
	"net"
	"os"
)

//IPAnalyzer adapter
type QQIPAnalyzer struct {
	img      []byte
	firstIdx int
	lastIdx  int
}

//Register a new adapter
func init() {
	Register("qq", &QQIPAnalyzer{})
}

//Initialize
func (a *QQIPAnalyzer) Init(dbFile string) error {
	file, e := os.Open(dbFile)
	if e != nil {
		return e
	}
	defer file.Close()

	info, e := file.Stat()
	if e != nil {
		return e
	}

	a.img = make([]byte, info.Size())

	nr, e := file.Read(a.img)
	if e != nil {
		return e
	}

	if nr != int(info.Size()) {
		return fmt.Errorf("Read interrupted")
	}

	var idx struct {
		First int32
		Last  int32
	}
	e = binary.Read(bytes.NewReader(a.img[:8]), binary.LittleEndian, &idx)
	if e != nil {
		return e
	}

	a.firstIdx = int(idx.First)
	a.lastIdx = int(idx.Last)

	return nil
}

//binary search
func (a *QQIPAnalyzer) find(nip int64, l, r int) int {
	if r-l <= 1 {
		return l
	}

	m := (l + r) / 2
	off := a.firstIdx + m*7

	idxIP := int64(ltohl(a.img[off : off+4]))
	if nip <= idxIP {
		return a.find(nip, l, m)
	}

	return a.find(nip, m, r)
}

//Get location and isp string 
func (a *QQIPAnalyzer) getAddress(off int) (string, string, error) {
	var e error
	var location, isp string
	mod := int(a.img[off])
	var nr int

	if mod == 1 {
		return a.getAddress(int(ltohl(a.img[off+1 : off+4])))
	} else if mod == 2 {
		cOff := int(ltohl(a.img[off+1 : off+4]))
		if location, _, e = a.readString(cOff); e != nil {
			goto out
		}
		isp, e = a.readArea(off + 4)
	} else {
		if location, nr, e = a.readString(off); e != nil {
			goto out
		}
		isp, e = a.readArea(off + nr)
	}
out:
	return location, isp, e
}

//Get GBK string, encoding into UTF-8
func (a *QQIPAnalyzer) readString(off int) (string, int, error) {
	i := off
	for ; a.img[i] != byte(0); i++ {
	}

	cd, e := iconv.Open("utf-8", "gbk")
	if e != nil {
		return "", 0, e
	}
	defer cd.Close()

	utf8 := cd.ConvString(string(a.img[off:i]))

	return utf8, i - off + 1, nil
}

//Read ISP string
func (a *QQIPAnalyzer) readArea(off int) (string, error) {
	o := off
	mod := int(a.img[off])
	if mod == 1 || mod == 2 {
		aOff := int(ltohl(a.img[off+1 : off+4]))
		if aOff == 0 {
			return "未知", nil
		}

		o = aOff
	}

	isp, _, e := a.readString(o)
	return isp, e
}

//Analyze ip string
func (a *QQIPAnalyzer) Analyze(ip string) (string, string, error) {
	nip := int64(ntohl(net.ParseIP(ip)))
	if 0 == nip {
		return "", "", fmt.Errorf("Illeagal ip")
	}

	idx := a.find(nip, 0, (a.lastIdx-a.firstIdx)/7)
	off := a.firstIdx + idx*7

	rOff := ltohl(a.img[off+4 : off+7])
	return a.getAddress(int(rOff) + 4)
}
