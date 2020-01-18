package aes_cbc

import (
	"crypto/cipher"
	"crypto/aes"
	"bytes"
	"encoding/base64"
)

func PKCS5Padding(plaintext []byte, blockSize int) []byte {
	padding := blockSize-len(plaintext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)},padding)
	return append(plaintext,padtext...)
}

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func AesEncrypt(origData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	//AES分组长度为 128 位，所以 blockSize=16 字节
	blockSize := block.BlockSize()
	origData = PKCS5Padding(origData,blockSize)
	blockMode := cipher.NewCBCEncrypter(block,key[:blockSize])	//初始向量的长度必须等于块block的长度16字节
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted,origData)
	return crypted, nil
}

func AesDecrypt(crypted, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// AES分组长度为 128 位，所以 blockSize=16 字节
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])	//初始向量的长度必须等于块block的长度16字节
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS5UnPadding(origData)
	return origData, nil
}

func EncryptBase64(data, key []byte)(string, error){
	aesData,err:=AesEncrypt(data,key)
	if err!=nil{
		return "",err
	}
	return base64.RawURLEncoding.EncodeToString(aesData),nil
}

func DecryptBase64(data string, key []byte)([]byte, error){
	aesData,err:=base64.RawURLEncoding.DecodeString(data)
	if err!=nil{
		return nil, err
	}
	return AesDecrypt(aesData,key)
}

