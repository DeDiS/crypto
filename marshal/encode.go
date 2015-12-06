package marshal

import (
	"encoding/binary"
	"golang.org/x/net/context"
	"io"
	"reflect"
)

type encoder struct {
	c context.Context
	w io.Writer
}

// Write a data structure containing cryptographic objects,
// using their built-in binary serialization, to an io.Writer.
// Supports writing of Points, Secrets,
// basic fixed-length data types supported by encoding/binary/Write(),
// and structs, arrays, and slices containing all of these types.
//
func Write(c context.Context, w io.Writer, objs ...interface{}) error {
	en := encoder{c, w}
	for i := 0; i < len(objs); i++ {
		if err := en.value(objs[i], 0); err != nil {
			return err
		}
	}
	return nil
}

func (en *encoder) value(obj interface{}, depth int) error {

	// Does the object support our self-decoding interface?
	if e, ok := obj.(Marshaler); ok {
		//prindent(depth, "encode: %s\n", e.String())
		_, err := e.Marshal(en.c, en.w)
		return err
	}

	// Otherwise, reflectively handle composite types.
	v := reflect.ValueOf(obj)
	//prindent(depth, "%s: %s\n", v.Kind().String(), v.Type().String())
	switch v.Kind() {

	case reflect.Interface:
	case reflect.Ptr:
		return en.value(v.Elem().Interface(), depth+1)

	case reflect.Struct:
		l := v.NumField()
		for i := 0; i < l; i++ {
			if err := en.value(v.Field(i).Interface(), depth+1); err != nil {
				return err
			}
		}

	case reflect.Slice, reflect.Array:
		l := v.Len()
		for i := 0; i < l; i++ {
			if err := en.value(v.Index(i).Interface(), depth+1); err != nil {
				return err
			}
		}

	case reflect.Int:
		i64 := v.Int()
		i32 := int32(i64)
		if int64(i32) != i64 {
			panic("int too large to encode in 32-bit wire format")
		}
		return binary.Write(en.w, binary.BigEndian, i32)

	case reflect.Bool:
		b := uint8(0)
		if v.Bool() {
			b = 1
		}
		return binary.Write(en.w, binary.BigEndian, b)

	default:
		// Fall back to big-endian binary encoding
		return binary.Write(en.w, binary.BigEndian, obj)
	}
	return nil
}
