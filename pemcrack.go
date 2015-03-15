package main

import (
	"bufio"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"sync"
)

var numRoutines int = 5

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func printUsage() {
	fmt.Println("Usage: pemcrack PEM_FILE DICT_FILE")
}

func checkPassword(pem *pem.Block, passwords []string, wg *sync.WaitGroup) {
	for _, password := range passwords {
		key, err := x509.DecryptPEMBlock(pem, []byte(password))
		if err == nil {
			validKey := false
			_, err = x509.ParsePKCS8PrivateKey(key)
			if err == nil {
				validKey = true
			}

			_, err = x509.ParsePKCS1PrivateKey(key)
			if err == nil {
				validKey = true
			}

			if validKey == true {
				fmt.Println("Password found: " + password)
				wg.Done()
			}
		}
	}
	wg.Done()
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func main() {

	// Check for the right command-line arguments
	if len(os.Args) != 3 {
		printUsage()
		os.Exit(1)
	}

	// Second argument should be the path to the private-key file
	privateKeyFile := os.Args[1]
	fmt.Println("Loading Private Key: " + privateKeyFile)

	// Load the private key as a byte []
	privateKey, err := ioutil.ReadFile(privateKeyFile)
	check(err)

	// Third argument should be the path to the dictionary file
	// Dictionaries are expected to be files with one password per line
	dictionaryFile := os.Args[2]
	fmt.Println("Loading dictionary: " + privateKeyFile)

	// Load all the passwords to memory. This is obviously a bad idea for
	// large dictionaries
	passwordList, err := readLines(dictionaryFile)
	check(err)

	dictLen := len(passwordList)
	fmt.Println(strconv.Itoa(dictLen) + " passwords loaded.")
	// Try to decode the data inside the file as a PEM
	decodedPEM, _ := pem.Decode(privateKey)

	// Error if we can't decode
	if decodedPEM == nil {
		fmt.Println("Error while loading Private key from: " + privateKeyFile)
		os.Exit(1)
	}

	// Print the details of the private key
	fmt.Printf("PEM Type :\n%s\n", decodedPEM.Type)
	fmt.Printf("PEM Headers :\n%s\n", decodedPEM.Headers)
	// fmt.Printf("PEM Bytes :\n%x\n", string(decodedPEM.Bytes))

	var wg sync.WaitGroup
	wg.Add(numRoutines)

	// Start the routines
	sliceSize := dictLen / numRoutines
	for i := 0; i < numRoutines; i++ {
		go checkPassword(decodedPEM, passwordList[i*(sliceSize):(i+1)*sliceSize], &wg)
	}
	fmt.Println("Cracking password...")
	// Wait for all the routines
	wg.Wait()
}
