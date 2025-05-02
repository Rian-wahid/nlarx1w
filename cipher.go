package nlarx1w


import ( 
	"unsafe"
)

type Cipher struct{

	k *blockKey
	counter uint64
	lastKSIndex int
	ks []byte
	nli uint64
}


func NewCipher(key,nonce []byte)(*Cipher,error){

	bk,err:=newBlockKey(key,nonce)
	if err!=nil {
		return nil,err
	}
	c:=&Cipher{}
	c.k=bk
	c.counter=bk.counter
	bk.counter=0
	c.nli=c.counter>>4
	c.lastKSIndex=0
	c.ks=make([]byte,BlockSize)

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


func (c *Cipher) xorKeyStreamBig(dst,src []byte){
	ds:=(*[128]uint64)(unsafe.Pointer(&dst[0]))[:]
	sc:=(*[128]uint64)(unsafe.Pointer(&src[0]))[:]
	ks:=(*[16]uint64)(unsafe.Pointer(&(c.ks[0])))[:]
	var sds []uint64
	var ssc []uint64
	for i:=0; i<128; i+=16{
		sds=ds[i:]
		ssc=sc[i:]
		c.genKs()

		sds[0]=ssc[0]^ks[0]
		sds[1]=ssc[1]^ks[1]
		sds[2]=ssc[2]^ks[2]
		sds[3]=ssc[3]^ks[3]

		sds[4]=ssc[4]^ks[4]
		sds[5]=ssc[5]^ks[5]
		sds[6]=ssc[6]^ks[6]
		sds[7]=ssc[7]^ks[7]

		sds[8]=ssc[8]^ks[8]
		sds[9]=ssc[9]^ks[9]
		sds[10]=ssc[10]^ks[10]
		sds[11]=ssc[11]^ks[11]

		sds[12]=ssc[12]^ks[12]
		sds[13]=ssc[13]^ks[13]
		sds[14]=ssc[14]^ks[14]
		sds[15]=ssc[15]^ks[15]


	}

}


func (c *Cipher) XORKeyStream(dst,src []byte){

	if len(dst)<len(src) {
		panic("nlarx1w: output smaller than input")
	}
	if invalidOverlap(dst,src) {
		panic("nlarx1w: invalid buffer overlap")
	}

	if c.lastKSIndex==0 {
		srclen:=len(src)
		bsx8:=BlockSize*8
		if srclen>=bsx8 {
			i:=0
			for ; i<srclen; i+=bsx8 {
				if i+bsx8>srclen {
					i+=bsx8
					break
				}
				c.xorKeyStreamBig(dst[i:],src[i:])
			}
			if i==srclen {
				return
			}
			i-=bsx8
			src=src[i:]
			dst=dst[i:]

		}

		c.genKs()
	}
	j:=c.lastKSIndex
	i:=0
	var ks []uint64
	var sc []uint64
	var ds []uint64
	for i<len(src) {
		if j>=BlockSize {
			j=0
			c.genKs()
		}
		l:=0
		if len(src[i:])>len(c.ks[j:]) {
			l=len(c.ks[j:])
		}else{
			l=len(src[i:])
		}
		if l%8>0 && l>8 {
			l=l-(l%8)
		}
		
		if l<8 {
			for n:=0; n<l; n++{
				dst[i+n]=src[i+n]^c.ks[j+n]	
			}
		}else{
			switch(l/8){

			case 1:
				ks=(*[1]uint64)(unsafe.Pointer(&(c.ks[j])))[:]
				sc=(*[1]uint64)(unsafe.Pointer(&src[i]))[:]
				ds=(*[1]uint64)(unsafe.Pointer(&dst[i]))[:]
				ds[0]=sc[0]^ks[0]
				break
			case 2:
				ks=(*[2]uint64)(unsafe.Pointer(&(c.ks[j])))[:]
				sc=(*[2]uint64)(unsafe.Pointer(&src[i]))[:]
				ds=(*[2]uint64)(unsafe.Pointer(&dst[i]))[:]
				ds[0]=sc[0]^ks[0]
				ds[1]=sc[1]^ks[1]
				break
			case 3:
				ks=(*[3]uint64)(unsafe.Pointer(&(c.ks[j])))[:]
				sc=(*[3]uint64)(unsafe.Pointer(&src[i]))[:]
				ds=(*[3]uint64)(unsafe.Pointer(&dst[i]))[:]
				ds[0]=sc[0]^ks[0]
				ds[1]=sc[1]^ks[1]
				ds[2]=sc[2]^ks[2]
				break
			case 4:
				ks=(*[4]uint64)(unsafe.Pointer(&(c.ks[j])))[:]
				sc=(*[4]uint64)(unsafe.Pointer(&src[i]))[:]
				ds=(*[4]uint64)(unsafe.Pointer(&dst[i]))[:]
				ds[0]=sc[0]^ks[0]
				ds[1]=sc[1]^ks[1]
				ds[2]=sc[2]^ks[2]
				ds[3]=sc[3]^ks[3]
				break
			case 5:
				ks=(*[5]uint64)(unsafe.Pointer(&(c.ks[j])))[:]
				sc=(*[5]uint64)(unsafe.Pointer(&src[i]))[:]
				ds=(*[5]uint64)(unsafe.Pointer(&dst[i]))[:]
				ds[0]=sc[0]^ks[0]
				ds[1]=sc[1]^ks[1]
				ds[2]=sc[2]^ks[2]
				ds[3]=sc[3]^ks[3]
				ds[4]=sc[4]^ks[4]
				break
			case 6:
				ks=(*[6]uint64)(unsafe.Pointer(&(c.ks[j])))[:]
				sc=(*[6]uint64)(unsafe.Pointer(&src[i]))[:]
				ds=(*[6]uint64)(unsafe.Pointer(&dst[i]))[:]
				ds[0]=sc[0]^ks[0]
				ds[1]=sc[1]^ks[1]
				ds[2]=sc[2]^ks[2]
				ds[3]=sc[3]^ks[3]
				ds[4]=sc[4]^ks[4]
				ds[5]=sc[5]^ks[5]
				break
			case 7:
				ks=(*[7]uint64)(unsafe.Pointer(&(c.ks[j])))[:]
				sc=(*[7]uint64)(unsafe.Pointer(&src[i]))[:]
				ds=(*[7]uint64)(unsafe.Pointer(&dst[i]))[:]
				ds[0]=sc[0]^ks[0]
				ds[1]=sc[1]^ks[1]
				ds[2]=sc[2]^ks[2]
				ds[3]=sc[3]^ks[3]

				ds[4]=sc[4]^ks[4]
				ds[5]=sc[5]^ks[5]
				ds[6]=sc[6]^ks[6]
				break
			case 8:
				ks=(*[8]uint64)(unsafe.Pointer(&(c.ks[j])))[:]
				sc=(*[8]uint64)(unsafe.Pointer(&src[i]))[:]
				ds=(*[8]uint64)(unsafe.Pointer(&dst[i]))[:]
				ds[0]=sc[0]^ks[0]
				ds[1]=sc[1]^ks[1]
				ds[2]=sc[2]^ks[2]
				ds[3]=sc[3]^ks[3]

				ds[4]=sc[4]^ks[4]
				ds[5]=sc[5]^ks[5]
				ds[6]=sc[6]^ks[6]
				ds[7]=sc[7]^ks[7]
				break
			case 9:
				ks=(*[9]uint64)(unsafe.Pointer(&(c.ks[j])))[:]
				sc=(*[9]uint64)(unsafe.Pointer(&src[i]))[:]
				ds=(*[9]uint64)(unsafe.Pointer(&dst[i]))[:]
				ds[0]=sc[0]^ks[0]
				ds[1]=sc[1]^ks[1]
				ds[2]=sc[2]^ks[2]
				ds[3]=sc[3]^ks[3]

				ds[4]=sc[4]^ks[4]
				ds[5]=sc[5]^ks[5]
				ds[6]=sc[6]^ks[6]
				ds[7]=sc[7]^ks[7]

				ds[8]=sc[8]^ks[8]
				break
			case 10:
				ks=(*[10]uint64)(unsafe.Pointer(&(c.ks[j])))[:]
				sc=(*[10]uint64)(unsafe.Pointer(&src[i]))[:]
				ds=(*[10]uint64)(unsafe.Pointer(&dst[i]))[:]
				ds[0]=sc[0]^ks[0]
				ds[1]=sc[1]^ks[1]
				ds[2]=sc[2]^ks[2]
				ds[3]=sc[3]^ks[3]

				ds[4]=sc[4]^ks[4]
				ds[5]=sc[5]^ks[5]
				ds[6]=sc[6]^ks[6]
				ds[7]=sc[7]^ks[7]

				ds[8]=sc[8]^ks[8]
				ds[9]=sc[9]^ks[9]
				break
			case 11:
				ks=(*[11]uint64)(unsafe.Pointer(&(c.ks[j])))[:]
				sc=(*[11]uint64)(unsafe.Pointer(&src[i]))[:]
				ds=(*[11]uint64)(unsafe.Pointer(&dst[i]))[:]
				ds[0]=sc[0]^ks[0]
				ds[1]=sc[1]^ks[1]
				ds[2]=sc[2]^ks[2]
				ds[3]=sc[3]^ks[3]

				ds[4]=sc[4]^ks[4]
				ds[5]=sc[5]^ks[5]
				ds[6]=sc[6]^ks[6]
				ds[7]=sc[7]^ks[7]

				ds[8]=sc[8]^ks[8]
				ds[9]=sc[9]^ks[9]
				ds[10]=sc[10]^ks[10]
				break
			case 12:
				ks=(*[12]uint64)(unsafe.Pointer(&(c.ks[j])))[:]
				sc=(*[12]uint64)(unsafe.Pointer(&src[i]))[:]
				ds=(*[12]uint64)(unsafe.Pointer(&dst[i]))[:]
				ds[0]=sc[0]^ks[0]
				ds[1]=sc[1]^ks[1]
				ds[2]=sc[2]^ks[2]
				ds[3]=sc[3]^ks[3]

				ds[4]=sc[4]^ks[4]
				ds[5]=sc[5]^ks[5]
				ds[6]=sc[6]^ks[6]
				ds[7]=sc[7]^ks[7]

				ds[8]=sc[8]^ks[8]
				ds[9]=sc[9]^ks[9]
				ds[10]=sc[10]^ks[10]
				ds[11]=sc[11]^ks[11]
				break
			case 13:
				ks=(*[13]uint64)(unsafe.Pointer(&(c.ks[j])))[:]
				sc=(*[13]uint64)(unsafe.Pointer(&src[i]))[:]
				ds=(*[13]uint64)(unsafe.Pointer(&dst[i]))[:]
				ds[0]=sc[0]^ks[0]
				ds[1]=sc[1]^ks[1]
				ds[2]=sc[2]^ks[2]
				ds[3]=sc[3]^ks[3]

				ds[4]=sc[4]^ks[4]
				ds[5]=sc[5]^ks[5]
				ds[6]=sc[6]^ks[6]
				ds[7]=sc[7]^ks[7]

				ds[8]=sc[8]^ks[8]
				ds[9]=sc[9]^ks[9]
				ds[10]=sc[10]^ks[10]
				ds[11]=sc[11]^ks[11]

				ds[12]=sc[12]^ks[12]
				break
			case 14:
				ks=(*[14]uint64)(unsafe.Pointer(&(c.ks[j])))[:]
				sc=(*[14]uint64)(unsafe.Pointer(&src[i]))[:]
				ds=(*[14]uint64)(unsafe.Pointer(&dst[i]))[:]
				ds[0]=sc[0]^ks[0]
				ds[1]=sc[1]^ks[1]
				ds[2]=sc[2]^ks[2]
				ds[3]=sc[3]^ks[3]

				ds[4]=sc[4]^ks[4]
				ds[5]=sc[5]^ks[5]
				ds[6]=sc[6]^ks[6]
				ds[7]=sc[7]^ks[7]

				ds[8]=sc[8]^ks[8]
				ds[9]=sc[9]^ks[9]
				ds[10]=sc[10]^ks[10]
				ds[11]=sc[11]^ks[11]

				ds[12]=sc[12]^ks[12]
				ds[13]=sc[13]^ks[13]
				break
			case 15:
				ks=(*[15]uint64)(unsafe.Pointer(&(c.ks[j])))[:]
				sc=(*[15]uint64)(unsafe.Pointer(&src[i]))[:]
				ds=(*[15]uint64)(unsafe.Pointer(&dst[i]))[:]
				ds[0]=sc[0]^ks[0]
				ds[1]=sc[1]^ks[1]
				ds[2]=sc[2]^ks[2]
				ds[3]=sc[3]^ks[3]

				ds[4]=sc[4]^ks[4]
				ds[5]=sc[5]^ks[5]
				ds[6]=sc[6]^ks[6]
				ds[7]=sc[7]^ks[7]

				ds[8]=sc[8]^ks[8]
				ds[9]=sc[9]^ks[9]
				ds[10]=sc[10]^ks[10]
				ds[11]=sc[11]^ks[11]

				ds[12]=sc[12]^ks[12]
				ds[13]=sc[13]^ks[13]
				ds[14]=sc[14]^ks[14]
				break
			default:
				ks=(*[16]uint64)(unsafe.Pointer(&(c.ks[j])))[:]
				sc=(*[16]uint64)(unsafe.Pointer(&src[i]))[:]
				ds=(*[16]uint64)(unsafe.Pointer(&dst[i]))[:]
				ds[0]=sc[0]^ks[0]
				ds[1]=sc[1]^ks[1]
				ds[2]=sc[2]^ks[2]
				ds[3]=sc[3]^ks[3]

				ds[4]=sc[4]^ks[4]
				ds[5]=sc[5]^ks[5]
				ds[6]=sc[6]^ks[6]
				ds[7]=sc[7]^ks[7]

				ds[8]=sc[8]^ks[8]
				ds[9]=sc[9]^ks[9]
				ds[10]=sc[10]^ks[10]
				ds[11]=sc[11]^ks[11]

				ds[12]=sc[12]^ks[12]
				ds[13]=sc[13]^ks[13]
				ds[14]=sc[14]^ks[14]
				ds[15]=sc[15]^ks[15]
				
			}
			
		}
		i+=l
		j+=l
		
	}
	if j>=BlockSize {
		j=0
	}
	c.lastKSIndex=j
}




