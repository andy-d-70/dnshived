// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package config

import "reflect"

// Clone returns a deep copy of c: no map, slice or pointer is shared with it.
// It walks the type with reflection, so a field added later is copied too.
// Fields that are not exported are copied by value as they are.
func (c Cluster) Clone() Cluster {
	out := c
	deepen(reflect.ValueOf(&out).Elem())
	return out
}

func deepen(v reflect.Value) {
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() || !v.CanSet() {
			return
		}
		n := reflect.New(v.Type().Elem())
		n.Elem().Set(v.Elem())
		deepen(n.Elem())
		v.Set(n)
	case reflect.Interface:
		if v.IsNil() || !v.CanSet() {
			return
		}
		inner := reflect.New(v.Elem().Type()).Elem()
		inner.Set(v.Elem())
		deepen(inner)
		v.Set(inner)
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Field(i).CanSet() {
				deepen(v.Field(i))
			}
		}
	case reflect.Slice:
		if v.IsNil() || !v.CanSet() {
			return
		}
		n := reflect.MakeSlice(v.Type(), v.Len(), v.Len())
		reflect.Copy(n, v)
		if hasRefs(v.Type().Elem()) {
			for i := 0; i < n.Len(); i++ {
				deepen(n.Index(i))
			}
		}
		v.Set(n)
	case reflect.Map:
		if v.IsNil() || !v.CanSet() {
			return
		}
		n := reflect.MakeMapWithSize(v.Type(), v.Len())
		refs := hasRefs(v.Type().Elem())
		for _, k := range v.MapKeys() {
			e := reflect.New(v.Type().Elem()).Elem()
			e.Set(v.MapIndex(k))
			if refs {
				deepen(e)
			}
			n.SetMapIndex(k, e)
		}
		v.Set(n)
	}
}

// hasRefs reports whether a value of type t can hold a pointer, map, slice or
// interface, that is, whether copying it by value shares anything.
func hasRefs(t reflect.Type) bool {
	switch t.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Interface:
		return true
	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			if hasRefs(t.Field(i).Type) {
				return true
			}
		}
	case reflect.Array:
		return hasRefs(t.Elem())
	}
	return false
}
