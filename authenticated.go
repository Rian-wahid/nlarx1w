package nlarx1w



import (
	"crypto/cipher"
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
	if dst==nil {
		dst=make([]byte,len(plaintext)+Overhead)
	}
	if len(dst)<len(plaintext)+Overhead {
		panic("nlarx1w: invalid dst length")
	}
	ciphertext,tag:=dst[:len(plaintext)],dst[len(plaintext):]
	if invalidOverlap(dst,plaintext) {
		panic("nlarx1w: invalid buffer overlap")
	}
	
	c,err:=NewCipher(ac.k,nonce)
	if err!=nil {
		panic(err)
	}
	var mk [32]byte
	c.XORKeyStream(mk[:],mk[:])
	m:=poly1305.New(&mk)
	
	m.Write(additionalData)
	c.XORKeyStream(ciphertext,plaintext)
	m.Write(ciphertext)
	copy(tag,m.Sum(nil))
	return dst


}

func (ac *AuthenticatedCipher) Open(dst,nonce,ciphertext,additionalData []byte)([]byte,error){

	if len(ciphertext)-Overhead<=0 {
		return nil,errors.New("nlarx1w: invalid ciphertext length")
	}
	if dst==nil {
		dst=make([]byte,len(ciphertext)-Overhead)
	}
	if len(dst)<len(ciphertext)-Overhead{
		return nil,errors.New("nlarx1w: invalid dst length")
	}
	
	var mk [32]byte
	tag:=ciphertext[len(ciphertext)-Overhead:]
	ct:=ciphertext[:len(ciphertext)-Overhead]

	c,err:=NewCipher(ac.k,nonce)
	if err!=nil {
		return nil,err
	}
	c.XORKeyStream(mk[:],mk[:])
	m:=poly1305.New(&mk)
	m.Write(additionalData)
	m.Write(ct)
	
	if invalidOverlap(dst,ct) {
		return nil,errors.New("nlarx1w: invalid buffer overlap")
	}
	if !m.Verify(tag) {
		return nil,errors.New("nlarx1w: message authentication failed")
	}
	c.XORKeyStream(dst,ct)
	return dst,nil
}


