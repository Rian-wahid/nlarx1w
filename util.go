package nlarx1w

import "reflect"

func invalidOverlap(a,b []byte)bool {

	if len(a)==0 || len(b)==0 || &a[0]==&b[0] {
		return false
	}
	return reflect.ValueOf(&a[0]).Pointer() <= reflect.ValueOf(&b[len(b)-1]).Pointer() &&
		reflect.ValueOf(&b[0]).Pointer() <= reflect.ValueOf(&a[len(a)-1]).Pointer()
}
	
