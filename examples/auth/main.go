package main

import (
	"fmt"

	"github.com/softyesti/softutils_golang/pkg/auth"
)

func main() {
	fmt.Println("--SoftUtils Auth Examples--")

	apiKey()
}

func apiKey() {
	authApiKey := auth.AuthApiKey{}

	value := "hello world"
	key, err := authApiKey.Generate(value)
	if err != nil {
		panic(err)
	}

	fmt.Println("api key:", key)

	isValid := authApiKey.Verify(value, key)
	if isValid {
		fmt.Println("api key: is valid")
	} else {
		fmt.Println("api key: is invalid")
	}
}
