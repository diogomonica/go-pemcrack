package main

import (
  "fmt"
  "crypto/x509"
  "io/ioutil"
  "bufio"
  "os"
  "encoding/pem"
  "strconv"
)

func check(e error) {
    if e != nil {
        panic(e)
    }
}

func printUsage(){
  fmt.Println("Usage: pemcrack PEM_FILE DICT_FILE")
}

func checkPassword(pem *pem.Block, passwords []string, done chan string) {
  for _, password := range passwords {
    _, err := x509.DecryptPEMBlock(pem, []byte(password))

    if err == nil {
      done <- password
    }
  }
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
  fmt.Println( strconv.Itoa(dictLen) + " passwords loaded.")
  // Try to decode the data inside the file as a PEM
  decodedPEM, _ := pem.Decode(privateKey)
  // XXX: Should check for errors.

  // Print the details of the private key
  fmt.Printf("PEM Type :\n%s\n", decodedPEM.Type)
  fmt.Printf("PEM Headers :\n%s\n", decodedPEM.Headers)
  fmt.Printf("PEM Bytes :\n%x\n", string(decodedPEM.Bytes))

  // Create the channel and start the threads
  done := make(chan string, 1)
  go checkPassword(decodedPEM, passwordList[0:dictLen/2], done)
  go checkPassword(decodedPEM, passwordList[dictLen/2:], done)

  // Wait for a password to match and print it out
  correctPassword := <-done
  fmt.Println("Password found: " + correctPassword)
}
