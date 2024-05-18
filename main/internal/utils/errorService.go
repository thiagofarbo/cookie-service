package utils

import "fmt"

func isNil[T any](value T, err error) ([]T, error) {
	if err != nil {
		fmt.Println("Error:", err)
		panic(err)
	}
	return []T{value}, nil
}
