package nlarx1w

import "reflect"

func inexactOverlap(a,b []byte)bool {

	if len(a)==0 || len(b)==0 || &a[0]==&b[0] {
		return false
	}
	return reflect.ValueOf(&a[0]).Pointer() <= reflect.ValueOf(&b[len(b)-1]).Pointer() &&
		reflect.ValueOf(&b[0]).Pointer() <= reflect.ValueOf(&a[len(a)-1]).Pointer()
}
	
func sliceForAppend(inp []byte, n int) (h, t []byte) {
	if total := len(inp) + n; cap(inp) < total {
		h = make([]byte, total)
		copy(h,inp)
	} else {
		h = inp[:total]
	}
	t = h[len(inp):]
	return
}

