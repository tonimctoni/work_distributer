package main;

import "net/http"
import "time"
import "fmt"
import "crypto/rand"
import "os"
import "sync/atomic"
import "encoding/json"
import "crypto/ecdsa"
import "crypto/x509"
import "io/ioutil"

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




// type Worker struct{
//     nonce Nonce
//     busy Busy
// }

// func (o Worker) ServeHTTP(w http.ResponseWriter,r *http.Request){
//     w.Header().Set("Content-Type", "application/json")
//     w.WriteHeader(http.StatusOK)
//     return
// }





func main() {
    fmt.Println("end")
    return
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

    err:=server.ListenAndServe()
    // err:=error(nil)
    // _=server
    if err!=nil{
        fmt.Fprintln(os.Stderr, "Error:", err)
        // fmt.Println("Error:", err)
    }
    fmt.Println("end")
}
