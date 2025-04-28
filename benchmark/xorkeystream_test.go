package benchmark


import (

	"testing"
	"fmt"
	"crypto/rand"
	"github.com/Rian-wahid/nlarx1w"
)


func BenchmarkXORKeyStream(b *testing.B){
	key:=make([]byte,nlarx1w.KeySize)
	nonce:=make([]byte,nlarx1w.NonceSize)
	rand.Read(key)
	rand.Read(nonce)
	block:=make([]byte,nlarx1w.BlockSize*8)
	zerobytes:=make([]byte,nlarx1w.BlockSize*8)
	total:=0
	tincr:=len(block)
	c,err:=nlarx1w.NewCipher(key,nonce)
	if err!=nil {
		panic(err)
	}
	for b.Loop() {

		c.XORKeyStream(block,zerobytes)
		total+=tincr
	}
	fmt.Println("total encrypted message (bytes):",total,"byte")
	fmt.Println("total encrypted message (MB):",total/1_000_000,"MB")
	fmt.Printf("last key stream block:\n%x\n",block[len(block)-nlarx1w.BlockSize:])
}
