package nlarx1w



import (
	"crypto/cipher"
	"bytes"
	"errors"
	"golang.org/x/crypto/poly1305"
)

const (
	Overhead int=16
)

type AuthenticatedCipher struct {
	k []byte
}

func NewAuthenticatedCipher(key []byte)(cipher.AEAD,error){

	if len(key)!=KeySize{
		return nil,errors.New("nlarx1w: wrong key size")
	}
	k:=make([]byte,KeySize)
	copy(k,key)
	return &AuthenticatedCipher{k:k},nil
}

func (ac *AuthenticatedCipher) NonceSize()int {
	return NonceSize
}

func (ac *AuthenticatedCipher) Overhead()int {
	return Overhead
}

func (ac *AuthenticatedCipher) Seal(dst,nonce,plaintext,additionalData []byte)[]byte{
	ret,out := sliceForAppend(dst,len(plaintext)+Overhead)
	ciphertext,tag:=out[:len(plaintext)],out[len(plaintext):]
	if inexactOverlap(out,plaintext) {
		panic("nlarx1w: invalid buffer overlap")
	}
	var buf bytes.Buffer
	c,err:=NewCipher(ac.k,nonce,&buf)
	if err!=nil {
		panic(err)
	}
	var mk [32]byte
	c.Write(mk[:])
	buf.Read(mk[:])
	m:=poly1305.New(&mk)
	
	m.Write(additionalData)
	c.Write(plaintext)
	b:=buf.Bytes()
	m.Write(b)
	copy(ciphertext,b)
	copy(tag,m.Sum(nil))
	return ret


}

func (ac *AuthenticatedCipher) Open(dst,nonce,ciphertext,additionalData []byte)([]byte,error){
	if dst!=nil && len(dst)<len(ciphertext)-Overhead{
		return nil,errors.New("nlarx1w: bad dst length")
	}
	if len(ciphertext)-Overhead<=0 {
		return nil,errors.New("nlarx1w: bad ciphertext length")
	}

	var mk [32]byte
	var buf bytes.Buffer
	tag:=ciphertext[len(ciphertext)-Overhead:]
	ct:=ciphertext[:len(ciphertext)-Overhead]

	c,err:=NewCipher(ac.k,nonce,&buf)
	if err!=nil {
		return nil,err
	}
	c.Write(mk[:])
	buf.Read(mk[:])
	m:=poly1305.New(&mk)
	m.Write(additionalData)
	m.Write(ct)
	ret,out := sliceForAppend(dst,len(ct))
	if inexactOverlap(out,ct) {
		return nil,errors.New("nlarx1w: invalid buffer overlap")
	}
	if !m.Verify(tag) {
		for i:= range out{
			out[i]=0
		}
		return nil,errors.New("nlarx1w: message authentication failed")
	}

	c.Write(ct)
	buf.Read(out)
	return ret,nil
}


