package main;

import "net/http"
import "time"
import "sync"
import "fmt"
import "os"


func main() {
    client:=&http.Client{
        Timeout: 5*time.Second,
    }

    var wait_group sync.WaitGroup

    for i:=1;i<65;i++{
        wait_group.Add(1)
        go func(i int){
            defer wait_group.Done()
            host:=fmt.Sprintf("c%03d", i)
            _, err:=client.Head(fmt.Sprintf("http://%s:4753/api/is_busy", host))
            if err==nil{
                fmt.Println(host)
            }
        }(i)
    }

    wait_group.Wait()
    fmt.Fprintln(os.Stderr, "Done !!!")
}