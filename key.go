package nlarx1w

import (
	"encoding/binary"
	"errors"
	"unsafe"
)
type ptUint64 func (b []byte,n uint64);
type blockKey struct{

	   k1,k2,k3 uint64
	k4,k5,k6,k7 uint64
	k8,k9,ka,kb uint64
	kc,kd,ke,kf uint64

	counter uint64
	isLe bool
}


const (

	KeySize int=32
	NonceSize int=24
	BlockSize int=128

	w0 uint64 =0x7468654265737450 
	w1 uint64 =0x726f74656374696f 
	w2 uint64 =0x6e49734f6e6c7946 
	w3 uint64 =0x726f6d416c6c6168
)

func newBlockKey(key,nonce []byte) (*blockKey,error){
	if key==nil || len(key)!=KeySize{

		return nil,errors.New("nlarx1w: wrong key size")
	}
	if nonce==nil || len(nonce)!=NonceSize{

		return nil,errors.New("nlarx1w: wrong nonce size")
	}
	k:=&blockKey{}
	k.k5=binary.LittleEndian.Uint64(key[:8])
	k.k6=binary.LittleEndian.Uint64(key[8:16])
	k.k7=binary.LittleEndian.Uint64(key[16:24])
	k.k8=binary.LittleEndian.Uint64(key[24:32])

	k.kd=binary.LittleEndian.Uint64(nonce[:8])
	k.ke=binary.LittleEndian.Uint64(nonce[8:16])
	k.kf=binary.LittleEndian.Uint64(nonce[16:24])


	k.k1=w0
	k.k2=w1
	k.k3=w2
	k.k4=w3

	//precompute

	//expand key
	k.k9,k.ka,k.kb,k.kc=oneWay(k.k4,k.k5,k.k6,k.k7)


	buf:=make([]byte,BlockSize)
	k.nextKeyStream(0,buf)
	k.counter=(binary.LittleEndian.Uint64(buf[:8])>>16)
	k.k1=binary.LittleEndian.Uint64(buf[8:16])
	k.k2=binary.LittleEndian.Uint64(buf[16:24])
	k.k3=binary.LittleEndian.Uint64(buf[24:32])
	k.k4=binary.LittleEndian.Uint64(buf[32:40])
	k.k5=binary.LittleEndian.Uint64(buf[40:48])
	k.k6=binary.LittleEndian.Uint64(buf[48:56])
	k.k7=binary.LittleEndian.Uint64(buf[56:64])
	k.k8=binary.LittleEndian.Uint64(buf[64:72])
	k.k9=binary.LittleEndian.Uint64(buf[72:80])
	k.ka=binary.LittleEndian.Uint64(buf[80:88])
	k.kb=binary.LittleEndian.Uint64(buf[88:96])
	k.kc=binary.LittleEndian.Uint64(buf[96:104])
	k.kd=binary.LittleEndian.Uint64(buf[104:112])
	k.ke=binary.LittleEndian.Uint64(buf[112:120])
	k.kf=binary.LittleEndian.Uint64(buf[120:128])

	//check system endian
	var n uint16=0x00ff
	b:=(*byte)(unsafe.Pointer(&n))
	k.isLe=*b==0xff
	return k,nil
}

func (k *blockKey) nextKeyStream(counter uint64,dst []byte)error{
	if len(dst)<BlockSize {
		return errors.New("nlarx1w: wrong dst size")
	}
	ds:=(*[16]uint64)(unsafe.Pointer(&dst[0]))[:]
	
	   k1,k2,k3:=k.k1,k.k2,k.k3
	k4,k5,k6,k7:=k.k4,k.k5,k.k6,k.k7
	k8,k9,ka,kb:=k.k8,k.k9,k.ka,k.kb
	kc,kd,ke,kf:=k.kc,k.kd,k.ke,k.kf

	
	//first round
	counter,k3,k4,k7=oneWay(counter,k3,k4,k7)

	//first column and last column round
	counter,k4,k8,kc=mix(counter,k4,k8,kc)
	k3,k7,kb,kf=mix(k3,k7,kb,kf)
	
	//diagonal round
	counter,k5,ka,kf=mix(counter,k5,ka,kf)
	k3,k6,k9,kc=mix(k3,k6,k9,kc)

	//ring round
	k1,k7,ke,k8=mix(k1,k7,ke,k8)
	k2,kb,kd,k4=mix(k2,kb,kd,k4)

	counter=(counter<<31)|(counter>>33)
	k3=(k3<<27)|(k3>>37)
	kc=(kc<<23)|(kc>>41)
	kf=(kf<<19)|(kf>>45)
	k5=(k5<<15)|(k5>>49)
	k6=(k6<<11)|(k6>>53)
	k9=(k9<<7)|(k9>>57)
	ka=(ka<<5)|(ka>>59)

	k1=(k1<<31)|(k1>>33)
	k2=(k2<<27)|(k2>>37)
	k7=(k7<<23)|(k7>>41)
	kb=(kb<<19)|(kb>>45)
	ke=(ke<<15)|(ke>>49)
	kd=(kd<<11)|(kd>>53)
	k8=(k8<<7)|(k8>>57)
	k4=(k4<<5)|(k4>>59)

	//diagonal round 2
	k1,k6,kb,kc=mix(k1,k6,kb,kc)
	k2,k5,k8,kf=mix(k2,k5,k8,kf)
	kd,ka,k7,counter=mix(kd,ka,k7,counter)
	ke,k9,k4,k3=mix(ke,k9,k4,k3)

	counter=(counter<<31)|(counter>>33)
	k3=(k3<<27)|(k3>>37)
	kc=(kc<<23)|(kc>>41)
	kf=(kf<<19)|(kf>>45)
	k5=(k5<<15)|(k5>>49)
	k6=(k6<<11)|(k6>>53)
	k9=(k9<<7)|(k9>>57)
	ka=(ka<<5)|(ka>>59)

	k1=(k1<<31)|(k1>>33)
	k2=(k2<<27)|(k2>>37)
	k7=(k7<<23)|(k7>>41)
	kb=(kb<<19)|(kb>>45)
	ke=(ke<<15)|(ke>>49)
	kd=(kd<<11)|(kd>>53)
	k8=(k8<<7)|(k8>>57)
	k4=(k4<<5)|(k4>>59)

	//column round
	counter,k4,k8,kc=mix(counter,k4,k8,kc)
	k1,k5,k9,kd=mix(k1,k5,k9,kd)
	k2,k6,ka,ke=mix(k2,k6,ka,ke)
	k3,k7,kb,kf=mix(k3,k7,kb,kf)

	counter=(counter<<31)|(counter>>33)
	k3=(k3<<27)|(k3>>37)
	kc=(kc<<23)|(kc>>41)
	kf=(kf<<19)|(kf>>45)
	k5=(k5<<15)|(k5>>49)
	k6=(k6<<11)|(k6>>53)
	k9=(k9<<7)|(k9>>57)
	ka=(ka<<5)|(ka>>59)

	k1=(k1<<31)|(k1>>33)
	k2=(k2<<27)|(k2>>37)
	k7=(k7<<23)|(k7>>41)
	kb=(kb<<19)|(kb>>45)
	ke=(ke<<15)|(ke>>49)
	kd=(kd<<11)|(kd>>53)
	k8=(k8<<7)|(k8>>57)
	k4=(k4<<5)|(k4>>59)



	//diagonal round
	counter,k5,ka,kf=mix(counter,k5,ka,kf)
	k3,k6,k9,kc=mix(k3,k6,k9,kc)

	//ring round
	k1,k7,ke,k8=mix(k1,k7,ke,k8)
	k2,kb,kd,k4=mix(k2,kb,kd,k4)

	counter=(counter<<31)|(counter>>33)
	k3=(k3<<27)|(k3>>37)
	kc=(kc<<23)|(kc>>41)
	kf=(kf<<19)|(kf>>45)
	k5=(k5<<15)|(k5>>49)
	k6=(k6<<11)|(k6>>53)
	k9=(k9<<7)|(k9>>57)
	ka=(ka<<5)|(ka>>59)

	k1=(k1<<31)|(k1>>33)
	k2=(k2<<27)|(k2>>37)
	k7=(k7<<23)|(k7>>41)
	kb=(kb<<19)|(kb>>45)
	ke=(ke<<15)|(ke>>49)
	kd=(kd<<11)|(kd>>53)
	k8=(k8<<7)|(k8>>57)
	k4=(k4<<5)|(k4>>59)

	//diagonal round 2
	k1,k6,kb,kc=mix(k1,k6,kb,kc)
	k2,k5,k8,kf=mix(k2,k5,k8,kf)
	kd,ka,k7,counter=mix(kd,ka,k7,counter)
	ke,k9,k4,k3=mix(ke,k9,k4,k3)

	//column round
	counter,k4,k8,kc=mix(counter,k4,k8,kc)
	k1,k5,k9,kd=mix(k1,k5,k9,kd)
	k2,k6,ka,ke=mix(k2,k6,ka,ke)
	k3,k7,kb,kf=mix(k3,k7,kb,kf)




	if k.isLe {
		ds[0]=counter
		ds[1]=k1
		ds[2]=k2
		ds[3]=k3
		ds[4]=k4
		ds[5]=k5
		ds[6]=k6
		ds[7]=k7
		ds[8]=k8
		ds[9]=k9
		ds[10]=ka
		ds[11]=kb
		ds[12]=kc
		ds[13]=kd
		ds[14]=ke
		ds[15]=kf
		return nil

	}
	
	binary.LittleEndian.PutUint64(dst[:8],counter)
	binary.LittleEndian.PutUint64(dst[8:16],k1)
	binary.LittleEndian.PutUint64(dst[16:24],k2)
	binary.LittleEndian.PutUint64(dst[24:32],k3)
	binary.LittleEndian.PutUint64(dst[32:40],k4)
	binary.LittleEndian.PutUint64(dst[40:48],k5)
	binary.LittleEndian.PutUint64(dst[48:56],k6)
	binary.LittleEndian.PutUint64(dst[56:64],k7)
	binary.LittleEndian.PutUint64(dst[64:72],k8)
	binary.LittleEndian.PutUint64(dst[72:80],k9)
	binary.LittleEndian.PutUint64(dst[80:88],ka)
	binary.LittleEndian.PutUint64(dst[88:96],kb)
	binary.LittleEndian.PutUint64(dst[96:104],kc)
	binary.LittleEndian.PutUint64(dst[104:112],kd)
	binary.LittleEndian.PutUint64(dst[112:120],ke)
	binary.LittleEndian.PutUint64(dst[120:128],kf)
	
	return nil

}



