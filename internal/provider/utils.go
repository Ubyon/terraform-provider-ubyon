/*
 *  Copyright © 2021-2024 All rights reserved
 *  Maintainer: Ubyon
 */

package provider

import (
	"net"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

func IsTypesStringEmpty(ts types.String) bool {
	return ts.IsNull() || ts.IsUnknown() || ts.ValueString() == ""
}

func ConvTypesString(ts types.String) string {
	if !ts.IsNull() && !ts.IsUnknown() {
		return ts.ValueString()
	}

	return ""
}

func ConvTypesBool(tb types.Bool) bool {
	if !tb.IsNull() && !tb.IsUnknown() {
		return tb.ValueBool()
	}

	return false
}

func ConvTypesInt64(ti types.Int64) int64 {
	if !ti.IsNull() && !ti.IsUnknown() {
		return ti.ValueInt64()
	}

	return 0
}

func ConvTypesArrayString(ta []types.String) []string {
	if len(ta) <= 0 {
		return nil
	}

	s := make([]string, len(ta))
	for i, v := range ta {
		s[i] = ConvTypesString(v)
	}

	return s
}

func ConvStringTypesArray(sa []string) []types.String {
	if len(sa) <= 0 {
		return nil
	}

	ts := make([]types.String, len(sa))
	for i, v := range sa {
		ts[i] = types.StringValue(v)
	}

	return ts
}

func ConvTypesMapStringArray(im map[types.String][]types.String) map[string][]string {
	if len(im) <= 0 {
		return nil
	}

	m := make(map[string][]string)
	for k, v := range im {
		m[ConvTypesString(k)] = ConvTypesArrayString(v)
	}

	return nil
}

func ConvMapStringArrayTypes(m map[string][]string) map[types.String][]types.String {
	if len(m) <= 0 {
		return nil
	}

	im := make(map[types.String][]types.String)
	for k, v := range m {
		im[types.StringValue(k)] = ConvStringTypesArray(v)
	}

	return nil
}

func ConvMapStringToArr(m map[string]struct{}) []string {
	if len(m) <= 0 {
		return nil
	}

	s := make([]string, len(m))
	i := 0
	for k := range m {
		s[i] = k
		i++
	}

	return s
}

func IsIpStr(s string) bool {
	return net.ParseIP(s) != nil
}
