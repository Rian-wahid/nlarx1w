package nlarx1w


import "io"

type Cipher struct{

	k *blockKey
	counter uint64
	lastKSIndex int
	ks []byte
	w io.Writer
	buf []byte
	nli uint64
}

const (

	c0 uint32=0xabcdef89
)



func NewCipher(key,nonce []byte,w io.Writer)(*Cipher,error){

	bk,err:=newBlockKey(key,nonce)
	if err!=nil {
		return nil,err
	}
	c:=&Cipher{}
	c.k=bk
	c.counter=bk.counter
	bk.counter=0
	c.nli=(c.counter>>4)+uint64(c0)
	c.lastKSIndex=0
	c.ks=make([]byte,BlockSize)
	c.buf=make([]byte,BlockSize)
	c.w=w

	return c,nil
}

func (c *Cipher) genKs(){
	c.nli+=1
	a:=uint16(c.nli)
	b:=uint16(c.nli>>16)
	cc:=uint16(c.nli>>32)
	d:=uint16(c.nli>>48)
	a,_,_,_=arx16(a,b,cc,d)
	c.counter+=uint64(((a>>1)|1))
	c.k.nextKeyStream(c.counter,c.ks)
	
}

func (c *Cipher) Write(b []byte)(int,error){
	if b==nil || len(b)<1 {
		return 0,nil
	}
	if c.lastKSIndex == 0 {
		c.genKs()
	}
	j:=c.lastKSIndex
	i:=0
	wc:=0
	for {
		l:=0
		m:=BlockSize
		if len(b)-i<m {
			m=len(b)-i
		}
		s:=b[i:i+m]

		for ;l<len(s); {
			if j>=BlockSize{
				j=0
				c.genKs()
			}
			c.buf[l]=s[l]^c.ks[j]
			j+=1
			l+=1
			i+=1
		}
		nn,err:=c.w.Write(c.buf[:len(s)])
		if err!=nil {
			return wc+nn,err
		}else{
			wc+=nn		
		}
		if i>=len(b) {
			break
		}
	}
	if j>=BlockSize {
		j=0
	}
	c.lastKSIndex=j
	return wc,nil
}
