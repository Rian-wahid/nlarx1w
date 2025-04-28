package main

import (
	"fmt"
	"crypto/rand"
	"github.com/Rian-wahid/nlarx1w"
)
func exampleXorKeyStream(){
	key:=make([]byte,nlarx1w.KeySize)
	nonce:=make([]byte,nlarx1w.NonceSize)
	rand.Read(key)
	rand.Read(nonce)
	msg:=[]byte("a secret message")
	ciphertext:=make([]byte,len(msg))
	c,err:=nlarx1w.NewCipher(key,nonce)
	if err!=nil {
		panic(err)
	}
	c.XORKeyStream(ciphertext,msg)
	fmt.Printf("msg (hex):\n%x\n",msg)
	fmt.Printf("ciphertext (hex):\n%x\n",ciphertext)
	//decrypt
	c,_=nlarx1w.NewCipher(key,nonce)
	plaintext:=make([]byte,len(msg))
	c.XORKeyStream(plaintext,ciphertext)
	fmt.Printf("plaintext (hex):\n%x\n",plaintext)

}

func exampleAuthenticated(){
	key:=make([]byte,nlarx1w.KeySize)
	nonce:=make([]byte,nlarx1w.NonceSize)
	rand.Read(key)
	rand.Read(nonce)
	msg:=[]byte("a secret message")
	fmt.Printf("msg (hex):\n%x\n",msg)
	aead,err:=nlarx1w.NewAuthenticatedCipher(key)
	if err!=nil {
		panic(err)
	}
	ciphertext:=make([]byte,nlarx1w.NonceSize+len(msg)+nlarx1w.Overhead)
	copy(ciphertext,nonce)
	encrypted:=aead.Seal(ciphertext[nlarx1w.NonceSize:],nonce,msg,nil)
	fmt.Printf("ciphertext (hex):\n%x\n",ciphertext)
	fmt.Printf("encrypted (hex):\n%x\n",encrypted)
	//decrypt
	plaintext,err:=aead.Open(nil,ciphertext[:nlarx1w.NonceSize],ciphertext[nlarx1w.NonceSize:],nil)
	if err!=nil {
		panic(err)
	}
	fmt.Printf("plaintext (hex):\n%x\n",plaintext)
}

func main(){
	exampleXorKeyStream()
	fmt.Println("--------")
	exampleAuthenticated()

}
