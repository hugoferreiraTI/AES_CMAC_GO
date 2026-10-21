// Command cmac demonstrates AES-128 CMAC generation and verification.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/hugoferreiraTI/AES_CMAC_Go/cmac"
	"github.com/joho/godotenv"
)

// main loads the local example configuration and prints the MAC and its
// verification result. The library itself receives only the key and message.
func main() {
	message := flag.String("message", "Payment 2590|sale=42", "Message to authenticate")
	flag.Parse()

	if err := godotenv.Load("config/.env"); err != nil {
		fmt.Fprintln(os.Stderr, "config: could not load config/.env")
		os.Exit(1)
	}

	keyHex := os.Getenv("AES_CMAC_KEY")
	if keyHex == "" {
		fmt.Fprintln(os.Stderr, "config: AES_CMAC_KEY is not set")
		os.Exit(1)
	}

	tagHex, err := cmac.Generate(keyHex, *message)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	verify, err := cmac.Verify(keyHex, *message, tagHex)
	if err != nil {
		fmt.Print(err)
		os.Exit(1)
	}
	if !verify {
		fmt.Print(verify)
		os.Exit(1)
	}

	fmt.Println(tagHex)
	fmt.Println(verify)
}
