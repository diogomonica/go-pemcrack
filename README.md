# go-pemcrack
go-pemcrack is a simple encrypted PEM password cracker written in go. You can clone the repo and test it out by running:

    # go run pemcrack.go fixtures/private.pem test.dict

While go-pemcrack does find the right password, it currently has a lot of false-positives. The reason for this seems to be `x509.DecryptPEMBloc`'s implementation (https://golang.org/src/crypto/x509/pem_decrypt.go).

```go
   148   // Blocks are padded using a scheme where the last n bytes of padding are all
   149		// equal to n. It can pad from 1 to blocksize bytes inclusive. See RFC 1423.
   150		// For example:
   151		//	[x y z 2 2]
   152		//	[x y 7 7 7 7 7 7 7]
   153		// If we detect a bad padding, we assume it is an invalid password.
   154		dlen := len(data)
   155		if dlen == 0 || dlen%ciph.blockSize != 0 {
   156			return nil, errors.New("x509: invalid padding")
   157		}
   158		last := int(data[dlen-1])
   159		if dlen < last {
   160			return nil, IncorrectPasswordError
   161		}
   162		if last == 0 || last > ciph.blockSize {
   163			return nil, IncorrectPasswordError
   164		}
   165		for _, val := range data[dlen-last:] {
   166			if int(val) != last {
   167				return nil, IncorrectPasswordError
   168			}
   169		}
```
This validation seems to be insuficient and any password that makes the padding match up these three conditions makes `x509.DecryptPEMBloc` provide an non-error return.

You can generate your own private key using the following command line command:
```bash
openssl genrsa -des3 -out private.pem 2048
```
To validate if you have the right password you can run this command:

```bash
openssl rsa -in private.pem -outform PEM -pubout -out public.pem
```

The password that was used for private.pem is `omgomgponies`
