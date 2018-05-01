package util

import insecureRand "math/rand"
import "encoding/binary"
import "reflect"
import "bytes"
import "sort"
import "io"

func SortByteSlices(source [][]byte) {
	sort.Slice(source, func(i, j int) bool {
		return bytes.Compare(source[i], source[j]) < 0
	})
}

func SortedByteSlices(source [][]byte) (result [][]byte) {
	result = make([][]byte, len(source), len(source))
	copy(result, source)
	sort.Slice(result, func(i, j int) bool {
		return bytes.Compare(result[i], result[j]) < 0
	})
	return
}

func WriteByteSlices(writer io.Writer, slices [][]byte) (n int, err error) {
	for _, slice := range slices {
		m, err := writer.Write(slice)
		n += m
		if err != nil {
			return n, err
		}
	}
	return
}

func FlattenByteSlices(slices [][]byte) (result []byte) {
	for _, slice := range slices {
		result = append(result, slice...)
	}
	return
}

func WriteShort(writer io.Writer, value uint16) error {
	return binary.Write(writer, binary.BigEndian, value)
}

func InsecureShuffle(slice interface{}) {
	swap := reflect.Swapper(slice)
	n := reflect.ValueOf(slice).Len()
	for i := n - 1; i > 0; i-- {
		j := insecureRand.Intn(i + 1)
		swap(i, j)
	}
}
