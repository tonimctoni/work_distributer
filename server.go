package main;

import "encoding/json"
import "crypto/sha256"
import "crypto/ecdsa"
import "crypto/x509"
import "crypto/rand"
import "sync/atomic"
import "io/ioutil"
import "net/http"
import "math/big"
import "os/exec"
import "time"
import "fmt"
import "os"

func load_public_key() (*ecdsa.PublicKey, error){
    key_in_bytes, err:=ioutil.ReadFile("private.key")
    if err!=nil{
        return nil, err
    }

    private_key, err:=x509.ParseECPrivateKey(key_in_bytes)
    if err!=nil{
        return nil, err
    }

    return &private_key.PublicKey, nil
}

type IncompleteRead struct{}

func (IncompleteRead) Error() string{
    return "IncompleteRead"
}

type NonceInErrorState struct{}

func (NonceInErrorState) Error() string{
    return "NonceInErrorState"
}

func get_random_u64() (uint64, error){
    bytes:=make([]byte, 8, 8)
    n,err:=rand.Read(bytes)
    if err!=nil{
        return 0,err
    }
    if n!=8{
        return 0,IncompleteRead{}
    }

    return_value:=uint64(0)
    return_value|=uint64(bytes[0])<<(8*0)
    return_value|=uint64(bytes[1])<<(8*1)
    return_value|=uint64(bytes[2])<<(8*2)
    return_value|=uint64(bytes[3])<<(8*3)
    return_value|=uint64(bytes[4])<<(8*4)
    return_value|=uint64(bytes[5])<<(8*5)
    return_value|=uint64(bytes[6])<<(8*6)
    return_value|=uint64(bytes[7])<<(8*7)

    return return_value,nil
}






type Nonce struct{
    nonce *uint64
}

func (n Nonce) reset() (uint64,error){
    new_nonce, err:=get_random_u64()
    if err!=nil{
        atomic.StoreUint64(n.nonce, 0)
        return 0, err
    }

    if new_nonce==0{
        atomic.StoreUint64(n.nonce, 0)
        return 0, NonceInErrorState{}
    }

    atomic.StoreUint64(n.nonce, new_nonce)
    return new_nonce, nil
}

func (n Nonce) get() (uint64,error){
    nonce:=atomic.LoadUint64(n.nonce)
    if nonce==0{
        return 0, NonceInErrorState{}
    }

    return nonce, nil
}

func (n Nonce) ServeHTTP(w http.ResponseWriter,r *http.Request){
    w.Header().Set("Content-Type", "application/json")
    nonce, err:=n.reset()
    if err!=nil{
        fmt.Fprintln(os.Stderr, "Error resetting nonce:", err)
        w.WriteHeader(http.StatusInternalServerError)
    } else{
        if nonce==0{
            w.WriteHeader(http.StatusInternalServerError)
        } else{
            w.WriteHeader(http.StatusOK)
        }
    }

    nonce_message:=NonceMessage{Nonce: nonce}
    err=json.NewEncoder(w).Encode(&nonce_message)
    if err!=nil{
        fmt.Fprintln(os.Stderr, "Error encoding nonce:", err)
    }
    return
}






type Busy struct{
    busy *int64
}

func (b Busy) is_busy() bool{
    return atomic.LoadInt64(b.busy)!=0
}

func (b Busy) make_busy() bool{ // retruns true if made busy, false if it already was busy
    old:=atomic.SwapInt64(b.busy, 1)
    return old==0
}

func (b Busy) make_free() bool{ // retruns true if made free, false if it already was free
    old:=atomic.SwapInt64(b.busy, 0)
    return old!=0
}

func (b Busy) ServeHTTP(w http.ResponseWriter,r *http.Request){
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)

    busy_message:=BusyMessage{Busy: b.is_busy()}
    err:=json.NewEncoder(w).Encode(&busy_message)
    if err!=nil{
        fmt.Fprintln(os.Stderr, "Error encoding busy:", err)
    }
    return
}




type Worker struct{
    nonce Nonce
    busy Busy
    public_key *ecdsa.PublicKey
}

func (o Worker) ServeHTTP(w http.ResponseWriter,r *http.Request){
    w.Header().Set("Content-Type", "text/plain")

    command_message:=Command{}
    err:=json.NewDecoder(r.Body).Decode(&command_message)
    if err!=nil{
        w.WriteHeader(http.StatusBadRequest)
        w.Write([]byte("error"))
        fmt.Fprintln(os.Stderr, "Error decoding command:", err)
        return
    }

    work_path:=command_message.Work_path
    signature_r:=command_message.Signature_r
    signature_s:=command_message.Signature_s

    signature_r_bigint:=new(big.Int)
    signature_s_bigint:=new(big.Int)

    _, err_r := fmt.Sscan(signature_r, signature_r_bigint)
    _, err_s := fmt.Sscan(signature_s, signature_s_bigint)

    if err_r!=nil || err_s!=nil{
        w.WriteHeader(http.StatusBadRequest)
        w.Write([]byte("error"))
        fmt.Fprintln(os.Stderr, "Error decoding signature", err_r, err_s)
        return
    }

    nonce, err:=o.nonce.get()
    if err!=nil{
        w.WriteHeader(http.StatusInternalServerError)
        w.Write([]byte("error"))
        fmt.Fprintln(os.Stderr, "Error getting nonce:", err)
        return
    }

    string_to_check:=fmt.Sprintf("$$%s$$%x$$", work_path, nonce)
    hash_to_check:=sha256.Sum256([]byte(string_to_check))

    checks_out:=ecdsa.Verify(o.public_key, hash_to_check[:], signature_r_bigint, signature_s_bigint)
    if !checks_out{
        w.WriteHeader(http.StatusBadRequest)
        w.Write([]byte("signature_error"))
        fmt.Fprintln(os.Stderr, "Error verifying signature")
        return
    }

    if !o.busy.make_busy(){
        w.WriteHeader(http.StatusPreconditionFailed)
        w.Write([]byte("busy"))
        fmt.Fprintln(os.Stderr, "Error: could not make busy")
        return
    }

    go func(work_path string, busy Busy){
        cmd:=exec.Command("make")
        cmd.Stdout=os.Stdout
        cmd.Stderr=os.Stderr
        cmd.Dir=work_path
        fmt.Println("Executing:", work_path)
        err:=cmd.Run()
        if !busy.make_free(){
            fmt.Fprintln(os.Stderr, "Error: attempted to make busy free while it was already free")
            return
        }
        if err!=nil{
            fmt.Fprintln(os.Stderr, "Error while running command", err)
            return
        }
        fmt.Println("Command was executed successfully:", work_path)
    }(work_path, o.busy)

    w.WriteHeader(http.StatusOK)
    w.Write([]byte("ok"))
    return
}





func main() {
    public_key,err:=load_public_key()
    if err!=nil{
        fmt.Fprintln(os.Stderr, "Error loading key:", err)
        return
    }

    mux:=http.NewServeMux()
    server:=&http.Server{
        Addr: ":4753",
        ReadTimeout: 5*time.Second,
        WriteTimeout: 5*time.Second,
        IdleTimeout: 5*time.Second,
        Handler: mux,
    }

    inner_nonce:=new(uint64)
    nonce:=Nonce{nonce:inner_nonce}
    mux.Handle("/api/get_nonce", nonce)

    inner_busy:=new(int64)
    busy:=Busy{busy:inner_busy}
    mux.Handle("/api/is_busy", busy)

    worker:=Worker{nonce: nonce, busy: busy, public_key: public_key}
    mux.Handle("/api/work", worker)

    err=server.ListenAndServe()
    if err!=nil{
        fmt.Fprintln(os.Stderr, "Error:", err)
    }
    fmt.Println("end")
}
