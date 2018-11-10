package main;

import "crypto/rand"
import "crypto/ecdsa"
import "crypto/elliptic"
import "fmt"
import "crypto/x509"
import "io/ioutil"
import "os"


func main() {
    key, err:=ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
    if err!=nil{
        fmt.Fprintln(os.Stderr, "Could not generate key:", err)
        return
    }
    key_in_bytes,err:=x509.MarshalECPrivateKey(key)
    if err!=nil{
        fmt.Fprintln(os.Stderr, "Could not marshall key:", err)
        return
    }
    err=ioutil.WriteFile("private.key", key_in_bytes, 0600)
    if err!=nil{
        fmt.Fprintln(os.Stderr, "Could not write key to file:", err)
        return
    }
}