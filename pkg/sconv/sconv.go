package sconv

import (
	"fmt"
	"strconv"
	"strings"
)

// ConverterWithErrors struct
type ConverterWithErrors struct {
	input string
}

// StringWithError input to convert
func StringWithError(input string) *ConverterWithErrors {
	return &ConverterWithErrors{input: input}
}

func (cwe *ConverterWithErrors) String() (r string, e error) {
	r = cwe.input
	return
}

func (cwe *ConverterWithErrors) Bytes() (r []byte, e error) {
	r = []byte(cwe.input)
	return
}

// Int from string
func (cwe *ConverterWithErrors) Int() (r int, e error) {
	return strconv.Atoi(cwe.input)
}

// UInt from string
func (cwe *ConverterWithErrors) UInt() (r uint, e error) {
	_, e = fmt.Sscan(cwe.input, &r)
	return
}

// Int8 from string
func (cwe *ConverterWithErrors) Int8() (r int8, e error) {
	_, e = fmt.Sscan(cwe.input, &r)
	return
}

// Int16 from string
func (cwe *ConverterWithErrors) Int16() (r int16, e error) {
	_, e = fmt.Sscan(cwe.input, &r)
	return
}

// Int32 from string
func (cwe *ConverterWithErrors) Int32() (r int32, e error) {
	_, e = fmt.Sscan(cwe.input, &r)
	return
}

// Int64 from string
func (cwe *ConverterWithErrors) Int64() (r int64, e error) {
	return strconv.ParseInt(cwe.input, 10, 64)

}

// UInt8 from string
func (cwe *ConverterWithErrors) UInt8() (r uint8, e error) {
	_, e = fmt.Sscan(cwe.input, &r)
	return
}

// UInt16 from string
func (cwe *ConverterWithErrors) UInt16() (r uint16, e error) {
	_, e = fmt.Sscan(cwe.input, &r)
	return
}

// UInt32 from string
func (cwe *ConverterWithErrors) UInt32() (r uint32, e error) {
	_, e = fmt.Sscan(cwe.input, &r)
	return
}

// UInt64 from string
func (cwe *ConverterWithErrors) UInt64() (r uint64, e error) {
	return strconv.ParseUint(cwe.input, 10, 64)
}

// Float32 from string
func (cwe *ConverterWithErrors) Float32() (r float32, e error) {
	_, e = fmt.Sscan(cwe.input, &r)
	return
}

// Float64 from string
func (cwe *ConverterWithErrors) Float64() (r float64, e error) {
	return strconv.ParseFloat(cwe.input, 64)
}

// Bool from string
func (cwe *ConverterWithErrors) Bool() (r bool, e error) {
	input := strings.ToLower(strings.Trim(cwe.input, " \t\r\n"))
	if input == "" {
		r = false
	}
	if input == "false" {
		r = false
	}
	if input == "true" {
		r = true
	}
	if input == "0" {
		r = false
	}
	if input == "1" {
		r = true
	}
	if input == "no" {
		r = false
	}
	if input == "yes" {
		r = true
	}
	return
}

// ConverterWithoutErrors struct
type ConverterWithoutErrors struct {
	cwe *ConverterWithErrors
}

// String to numeric type
func String(input string) *ConverterWithoutErrors {
	return &ConverterWithoutErrors{
		StringWithError(input),
	}
}

func (cwe *ConverterWithoutErrors) String() (r string) {
	r, _ = cwe.cwe.String()
	return
}

func (cwe *ConverterWithoutErrors) Bytes() (r []byte) {
	r, _ = cwe.cwe.Bytes()
	return
}

// Int from string
func (cwe *ConverterWithoutErrors) Int() (r int) {
	r, _ = cwe.cwe.Int()
	return
}

// UInt from string
func (cwe *ConverterWithoutErrors) UInt() (r uint) {
	r, _ = cwe.cwe.UInt()
	return
}

// Int8 from string
func (cwe *ConverterWithoutErrors) Int8() (r int8) {
	r, _ = cwe.cwe.Int8()
	return
}

// Int16 from string
func (cwe *ConverterWithoutErrors) Int16() (r int16) {
	r, _ = cwe.cwe.Int16()
	return
}

// Int32 from string
func (cwe *ConverterWithoutErrors) Int32() (r int32) {
	r, _ = cwe.cwe.Int32()
	return
}

// Int64 from string
func (cwe *ConverterWithoutErrors) Int64() (r int64) {
	r, _ = cwe.cwe.Int64()
	return

}

// UInt8 from string
func (cwe *ConverterWithoutErrors) UInt8() (r uint8) {
	r, _ = cwe.cwe.UInt8()
	return
}

// UInt16 from string
func (cwe *ConverterWithoutErrors) UInt16() (r uint16) {
	r, _ = cwe.cwe.UInt16()
	return
}

// UInt32 from string
func (cwe *ConverterWithoutErrors) UInt32() (r uint32) {
	r, _ = cwe.cwe.UInt32()
	return
}

// UInt64 from string
func (cwe *ConverterWithoutErrors) UInt64() (r uint64) {
	r, _ = cwe.cwe.UInt64()
	return
}

// Float32 from string
func (cwe *ConverterWithoutErrors) Float32() (r float32) {
	r, _ = cwe.cwe.Float32()
	return
}

// Float64 from string
func (cwe *ConverterWithoutErrors) Float64() (r float64) {
	r, _ = cwe.cwe.Float64()
	return
}

// Bool from string
func (cwe *ConverterWithoutErrors) Bool() (r bool) {
	r, _ = cwe.cwe.Bool()
	return
}
