package main;

import "os/exec"
import "fmt"
// import "os"

func try_ping_host(host string) bool{
    cmd:=exec.Command("ping", "-c", "1", host)
    err:=cmd.Run()
    return err==nil
}

func main() {
    for i:=1;i<65;i++{
        host:=fmt.Sprintf("c%03d", i)
        if try_ping_host(host){
            fmt.Printf("%s: ping \033[92mSUCCESS\033[0m\n", host)
        } else{
            fmt.Printf("%s: ping \033[91mFAILURE\033[0m\n", host)
        }
    }
    fmt.Println("Done !!!")
}