package main;

import "encoding/json"
import "crypto/ecdsa"
import "crypto/x509"
import "io/ioutil"
import "net/http"
import "os"
import "fmt"
import "time"

func load_private_key() (*ecdsa.PrivateKey, error){
    key_in_bytes, err:=ioutil.ReadFile("private.key")
    if err!=nil{
        return nil, err
    }

    return x509.ParseECPrivateKey(key_in_bytes)
}

type Work struct{
    Hosts []string `json:"hosts"`
    Work []struct{
        Dir string `json:"dir"`
        Command string `json:"command"`
    } `json:"work"`
}

type InvalidJsonContent struct{}

func (InvalidJsonContent) Error() string{
    return "InvalidJsonContent"
}

func load_work() (Work, error){
    var work Work
    f,err:=os.Open("work.json")
    defer f.Close()
    if err!=nil{
        return work, err
    }

    err=json.NewDecoder(f).Decode(&work)
    if err!=nil{
        return work, err
    }

    if len(work.Hosts)==0 || len(work.Work)==0{
        return work, InvalidJsonContent{}
    }

    for _,inner_work := range work.Work{
        if len(inner_work.Dir)==0 || len(inner_work.Command)==0{
            return work, InvalidJsonContent{}
        }
    }

    return work, nil
}


type MyClient struct{
    client *http.Client
}

func (c MyClient) is_host_busy(host string) (bool, error){
    response, err:=c.client.Get(fmt.Sprintf("http://%s:4753/api/is_busy", host))
    if err!=nil{
        return false, err
    }

    var busy_struct struct{
        Busy bool `json:"busy"`
    }
    err=json.NewDecoder(response.Body).Decode(&busy_struct)
    return busy_struct.Busy, err
}


func main() {
    private_key,err:=load_private_key()
    if err!=nil{
        fmt.Fprintln(os.Stderr, "Error loading key:", err)
    }

    work,err:=load_work()
    if err!=nil{
        fmt.Fprintln(os.Stderr, "Error loading work:", err)
    }

    inner_client:=&http.Client{
        Timeout: 5*time.Second,
    }
    client:=MyClient{client: inner_client}

    hosts:=work.Hosts
    works:=work.Work

    outer: for _,work:=range works{
        for{
            for _,host:=range hosts{
                    fmt.Println(work, host)
                    busy,err:=client.is_host_busy(host)
                    fmt.Println(busy, err)
                    fmt.Println("")
                if busy==true{
                    continue outer
                }
            }
        }
    }

    fmt.Println("")
    fmt.Println(private_key, work)
}