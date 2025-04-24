package nlarx1w

func oneWay(a,b,c,d uint64)(uint64,uint64,uint64,uint64){
	t:=a+b+c+d
	a^=t
	b^=t
	c^=t
	d^=t

	a=(a<<31)|(a>>33)
	b=(b<<27)|(b>>37)
	t=a+b+c+d
	a^=t
	b^=t
	c^=t
	d^=t

	c=(c<<23)|(c>>41)
	d=(d<<19)|(d>>45)
	t=a+b+c+d
	a^=t
	b^=t
	c^=t
	d^=t

	a=(a<<15)|(a>>49)
	b=(b<<11)|(b>>53)
	t=a+b+c+d
	a^=t
	b^=t
	c^=t
	d^=t

	c=(c<<7)|(c>>57)
	d=(d<<5)|(d>>59)
	t=a+b+c+d
	a^=t
	b^=t
	c^=t
	d^=t
	
	return a,b,c,d

}

func mix(a,b,c,d uint64)(uint64, uint64, uint64, uint64){
	t:=a+b+c+d
	return a^t,b^t,c^t,d^t
}



func arx16(a,b,c,d uint16)(uint16,uint16,uint16,uint16){

	t:=a+b+c+d
	a^=t
	b^=t
	c^=t
	d^=t
	a=(a<<7)|(a>>9)
	b=(b<<3)|(b>>13)
	t=a+b+c+d
	a^=t
	b^=t
	c^=t
	d^=t
	c=(c<<7)|(c>>9)
	d=(d<<3)|(d>>13)
	t=a+b+c+d
	a^=t
	b^=t
	c^=t
	d^=t

	return a,b,c,d
}


