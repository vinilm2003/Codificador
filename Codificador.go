package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"golang.org/x/crypto/scrypt"
)

func main() {
	var resposta string

	fmt.Printf("Bem vindo!\n\tGostaria de utilizar o codificador?\n")
	fmt.Scanln(&resposta)
	respVerif := simOuNao(resposta)

	if respVerif {
		fmt.Print("\n")
		inicialização()
	} else {
		fmt.Println("Obrigado e até a próxima!")
	}
}

func simOuNao(resp string) (sim bool) {
	respLower := strings.ToLower(resp)
	switch respLower {
	case "sim", "s":
		sim = true
	case "não", "nao", "n":
		sim = false
	default:
		os.Exit(0)
	}
	return
}

func inicialização() {
	var texto, chave string
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("O que gostaria de codificar?")
	texto, _ = reader.ReadString('\n')
	fmt.Print("\n")

	fmt.Println("Qual chave gostaria de usar para acessar?")
	chave, _ = reader.ReadString('\n')
	fmt.Print("\n")

	fmt.Printf("\tTexto: %v\tChave: %v\n", texto, chave)

	salt := []byte{0xc6, 0x30, 0xf0, 0x60, 0xa5, 0x8a, 0xab, 0x9b}

	chaveCifrada, err := scrypt.Key([]byte(chave), salt, 1<<15, 8, 1, 32)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("chave criptografada: " + base64.StdEncoding.EncodeToString(chaveCifrada) + "\n")

	key := []byte(chaveCifrada)
	plaintext := []byte(texto)
	textoCifrado, err := encrypt(key, plaintext)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Texto criptografado: %0x\n", textoCifrado)
	result, err := decrypt(key, textoCifrado)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Texto descriptografado: %s\n", result)
}

func encrypt(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	b := base64.StdEncoding.EncodeToString(text)
	textoCifrado := make([]byte, aes.BlockSize+len(b))
	iv := textoCifrado[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(textoCifrado[aes.BlockSize:], []byte(b))
	return textoCifrado, nil
}

func decrypt(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(text) < aes.BlockSize {
		return nil, errors.New("textoCifrado too short")
	}
	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(text, text)
	data, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return nil, err
	}
	return data, nil
}
