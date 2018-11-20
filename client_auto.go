package main;

import "encoding/json"
import "crypto/sha256"
import "crypto/ecdsa"
import "crypto/x509"
import "crypto/rand"
import "io/ioutil"
import "net/http"
import "strings"
import "bytes"
import "time"
import "sort"
import "sync"
import "fmt"
import "os"

func load_private_key() (*ecdsa.PrivateKey, error){
    key_in_bytes, err:=ioutil.ReadFile("private.key")
    if err!=nil{
        return nil, err
    }

    return x509.ParseECPrivateKey(key_in_bytes)
}

func read_list_file(filename string) ([]string, error){
    content, err:=ioutil.ReadFile(filename)
    if err!=nil{
        return nil, err
    }

    lines:=strings.Split(string(content), "\n")
    return_strings:=make([]string, 0, len(lines))
    for _,line :=range lines{
        trimmed_line:=strings.TrimSpace(line)
        if len(trimmed_line)==0{
            continue
        }

        return_strings=append(return_strings, trimmed_line)
    }

    return return_strings, nil
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

type StatusCodeIsNotOk struct{
    content string
    host string
    code int
}

func (s StatusCodeIsNotOk) Error() string{
    content:=""
    host:=""
    code:=""

    if len(s.content)!=0{
        content=fmt.Sprintf("(content=%s)", s.content)
    }

    if len(s.host)!=0{
        host=fmt.Sprintf("(host=%s)", s.host)
    }

    if s.code!=0{
        code=fmt.Sprintf("(code=%d)", s.code)
    }

    return fmt.Sprintf("StatusCodeIsNotOk%s%s%s", host, content, code)
}

func (c MyClient) is_host_busy(host string) (bool, error){
    response, err:=c.client.Get(fmt.Sprintf("http://%s:4753/api/is_busy", host))
    if err!=nil{
        return false, err
    }

    if response.StatusCode!=200{
        return false, StatusCodeIsNotOk{host: host, code: response.StatusCode}
    }

    var busy_message BusyMessage
    err=json.NewDecoder(response.Body).Decode(&busy_message)
    return busy_message.Busy, err
}

func (c MyClient) get_nonce(host string) (uint64, error){
    response, err:=c.client.Get(fmt.Sprintf("http://%s:4753/api/get_nonce", host))
    if err!=nil{
        return 0, err
    }

    if response.StatusCode!=200{
        return 0, StatusCodeIsNotOk{host: host, code: response.StatusCode}
    }

    var nonce_message NonceMessage
    err=json.NewDecoder(response.Body).Decode(&nonce_message)
    return nonce_message.Nonce, err
}

func (c MyClient) send_work(host string, work_path string, signature_r string, signature_s string) error{
    command_message:=Command{
        Work_path: work_path,
        Signature_r: signature_r,
        Signature_s: signature_s,
    }

    var buffer bytes.Buffer
    err:=json.NewEncoder(&buffer).Encode(&command_message)
    if err!=nil{
        return err
    }

    response, err:=c.client.Post(fmt.Sprintf("http://%s:4753/api/work", host), "application/json", &buffer)
    if err!=nil{
        return err
    }

    if response.StatusCode!=200{
        content, err:=ioutil.ReadAll(response.Body)
        if err!=nil{
            return StatusCodeIsNotOk{host: host, code: response.StatusCode, content: "Could not read: "+err.Error()}
        }
        response.Body.Close()

        return StatusCodeIsNotOk{host: host, code: response.StatusCode, content: string(content)}
    }

    return nil
}

// func find_servers() []string{
//     const PC_RANGE = 65
//     client:=&http.Client{
//         Timeout: 5*time.Second,
//     }

//     var wait_group sync.WaitGroup
//     returns:=make([]string,PC_RANGE)

//     for i:=1;i<PC_RANGE;i++{
//         wait_group.Add(1)
//         go func(i int, returns []string){
//             defer wait_group.Done()
//             host:=fmt.Sprintf("c%03d", i)
//             _, err:=client.Head(fmt.Sprintf("http://%s:4753/api/is_busy", host))
//             if err==nil{
//                 returns[i]=host
//             }
//         }(i, returns)
//     }
//     wait_group.Wait()

//     hosts:=make([]string, 0, 64)
//     for _,host:=range returns{
//         if len(host)!=0{
//             hosts=append(hosts, host)
//         }
//     }

//     return hosts
// }

func try_access_host(client *http.Client, host_num int, wait_group *sync.WaitGroup, return_chan chan string){
    defer wait_group.Done()

    host:=fmt.Sprintf("c%03d", host_num)
    _, err:=client.Head(fmt.Sprintf("http://%s:4753/api/is_busy", host))
    if err==nil{
        return_chan<-host
    }
}

func find_servers() []string{
    const PC_RANGE = 65

    wait_group:=sync.WaitGroup{}
    return_chan:=make(chan string)
    client:=&http.Client{
        Timeout: 5*time.Second,
    }

    for i:=1;i<PC_RANGE;i++{
        wait_group.Add(1)
        go try_access_host(client, i, &wait_group, return_chan)
    }

    go func(){
        wait_group.Wait()
        close(return_chan)
    }()

    hosts:=make([]string, 0, 64)
    for host:=range return_chan{
        hosts=append(hosts, host)
    }

    sort.Strings(hosts)
    return hosts
}


func main() {
    private_key,err:=load_private_key()
    if err!=nil{
        fmt.Fprintln(os.Stderr, "Error loading key:", err)
        return
    }

    work_paths, err:=read_list_file("work_paths.list")
    if err!=nil{
        fmt.Fprintln(os.Stderr, "Error reading work paths:", err)
        return
    }

    hosts:=find_servers()
    last_host_update_time:=time.Now()
    fmt.Println("Found hosts:", hosts)

    inner_client:=&http.Client{
        Timeout: 5*time.Second,
    }
    client:=MyClient{client: inner_client}

    outer: for _,work_path:=range work_paths{
        fmt.Println("Next to send:", work_path)
        for{
            if len(hosts)==0 || time.Now().After(last_host_update_time.Add(5*time.Minute)){
                hosts=find_servers()
                last_host_update_time=time.Now()
                fmt.Println("Found hosts:", hosts)
            }
            for _,host:=range hosts{
                busy,err:=client.is_host_busy(host)
                if err!=nil{
                    fmt.Fprintln(os.Stderr, "Error checking if host is busy:", err)
                    continue
                }

                if busy{
                    continue
                }

                nonce,err:=client.get_nonce(host)
                if err!=nil{
                    fmt.Fprintln(os.Stderr, "Error getting nonce:", err)
                    continue
                }

                if nonce==0{
                    fmt.Fprintln(os.Stderr, "Error: nonce is zero")
                    continue
                }

                string_to_sign:=fmt.Sprintf("$$%s$$%x$$", work_path, nonce)
                hash_to_sign:=sha256.Sum256([]byte(string_to_sign))
                r,s,err:=ecdsa.Sign(rand.Reader, private_key, hash_to_sign[:])
                if err!=nil{
                    fmt.Fprintln(os.Stderr, "Error signing:", err)
                    continue
                }

                signature_r:=r.String()
                signature_s:=s.String()

                err=client.send_work(host, work_path, signature_r, signature_s)
                if err!=nil{
                    fmt.Fprintln(os.Stderr, "Error sending work:", err)
                    continue
                }

                fmt.Println("Host", host, "accetpted")

                continue outer
            }

            time.Sleep(10*time.Second)
        }
    }
}