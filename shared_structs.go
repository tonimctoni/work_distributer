package main;



type NonceMessage struct{
    Nonce uint64 `json:"nonce"`
}


type BusyMessage struct{
    Busy bool `json:"busy"`
}

type Command struct{
    Dir string `json:"dir"`
    Command string `json:"command"`
    Signature_r string `json:"signature_r"`
    Signature_s string `json:"signature_s"`
}