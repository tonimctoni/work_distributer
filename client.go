package main;

import "encoding/base64"
import "encoding/json"
import "crypto/ecdsa"
import "crypto/x509"
import "crypto/sha256"
import "crypto/rand"
import "crypto"
import "io/ioutil"
import "net/http"
import "os"
import "fmt"
import "time"
import "bytes"

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

type StatusCodeIsNotOk struct{
    content string
}

func (s StatusCodeIsNotOk) Error() string{
    if len(s.content)==0{
        return "StatusCodeIsNotOk"
    }

    return fmt.Sprintf("StatusCodeIsNotOk(%s)", s.content)
}

func (c MyClient) is_host_busy(host string) (bool, error){
    response, err:=c.client.Get(fmt.Sprintf("http://%s:4753/api/is_busy", host))
    if err!=nil{
        return false, err
    }

    if response.StatusCode!=200{
        return false, StatusCodeIsNotOk{}
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
        return 0, StatusCodeIsNotOk{}
    }

    var nonce_message NonceMessage
    err=json.NewDecoder(response.Body).Decode(&nonce_message)
    return nonce_message.Nonce, err
}

func (c MyClient) send_work(host string, dir string, command string, signature string) error{
    command_message:=Command{
        Dir: dir,
        Command: command,
        Signature: signature,
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
            return StatusCodeIsNotOk{content: "Could not read: "+err.Error()}
        }
        response.Body.Close()

        return StatusCodeIsNotOk{content: string(content)}
    }

    return nil
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
        // Print what is going to be sent next here
        for{
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

                dir:=work.Dir
                command:=work.Command
                string_to_sign:=fmt.Sprintf("$$%s$$%s$$%x$$")
                hash_to_sign:=sha256.Sum256([]byte(string_to_sign))
                signature_bytes, err:=private_key.Sign(rand.Reader, hash_to_sign[:], crypto.SHA256)
                if err!=nil{
                    fmt.Fprintln(os.Stderr, "Error signing:", err)
                    continue
                }
                signature_base64:=base64.StdEncoding.EncodeToString(signature_bytes)

                err=client.send_work(host, dir, command, signature_base64)
                if err!=nil{
                    fmt.Fprintln(os.Stderr, "Error sending work:", err)
                    continue
                }

                continue outer
            }
        }
    }
}