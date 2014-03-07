e it?# ip

a ip lookup adapter. It can use many ip databases. It only support QQ ip database now. 

## How to install?

    go get github.com/ianzeng/ip

## How to use it?

Use it like this:

    import (
        "github.com/ianzeng/ip"
    )
    
    func main() {
        ip := "192.168.60.66"
        //Init a ip analyzer
        an, e := ip.NewIPAnalyzer("qq", "./QQWry.DAT")
        if e != nil {
            fmt.Println("Create ip analyzer error, desc:", e)
            return
        }

        location, isp, e := an.Analyze(ip)
        if e != nil {
            fmt.Println("Analyze ip error, desc:", e)
            return
        }

        fmt.Println("location:",location,", isp:",isp)
    }
