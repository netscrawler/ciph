package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"

	"github.com/schollz/progressbar/v3"
)

const bufferSize = 1024 * 1024 // 1MB

type KeyInfo struct {
	KeySize   int // размер ключа в битах
	BlockSize int // максимальный размер блока для шифрования
}

type cryptTask struct {
	data   []byte
	index  int
	result []byte
	err    error
}

func calculateBlockSize(keySize int) int {
	keyBytes := keySize / 8
	return keyBytes - 2*32 - 2
}

func generateAndSaveKeys(keySize int, privateKeyPath string, publicKeyPath string) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	if keySize < 1024 {
		return nil, nil, fmt.Errorf("размер ключа должен быть не менее 1024 бит")
	}

	fmt.Println("Генерация ключей RSA...")
	bar := progressbar.Default(-1, "Генерация")

	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, nil, fmt.Errorf("ошибка генерации ключей: %v", err)
	}
	bar.Finish()

	publicKey := &privateKey.PublicKey
	keyInfo := KeyInfo{
		KeySize:   keySize,
		BlockSize: calculateBlockSize(keySize),
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
		Headers: map[string]string{
			"KeySize":   fmt.Sprintf("%d", keyInfo.KeySize),
			"BlockSize": fmt.Sprintf("%d", keyInfo.BlockSize),
		},
	})

	err = os.WriteFile(privateKeyPath, privateKeyPEM, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("ошибка сохранения приватного ключа: %v", err)
	}

	publicKeyBytes := x509.MarshalPKCS1PublicKey(publicKey)
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
		Headers: map[string]string{
			"KeySize":   fmt.Sprintf("%d", keyInfo.KeySize),
			"BlockSize": fmt.Sprintf("%d", keyInfo.BlockSize),
		},
	})

	err = os.WriteFile(publicKeyPath, publicKeyPEM, 0o644)
	if err != nil {
		return nil, nil, fmt.Errorf("ошибка сохранения публичного ключа: %v", err)
	}

	return privateKey, publicKey, nil
}

func getKeyInfoFromPEM(pemBlock *pem.Block) (KeyInfo, error) {
	keySize := 0
	blockSize := 0

	if sizeStr, ok := pemBlock.Headers["KeySize"]; ok {
		fmt.Sscanf(sizeStr, "%d", &keySize)
	}
	if blockSizeStr, ok := pemBlock.Headers["BlockSize"]; ok {
		fmt.Sscanf(blockSizeStr, "%d", &blockSize)
	}

	if keySize == 0 || blockSize == 0 {
		key, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
		if err == nil {
			keySize = key.Size() * 8
			blockSize = calculateBlockSize(keySize)
		} else {
			pubKey, err := x509.ParsePKCS1PublicKey(pemBlock.Bytes)
			if err != nil {
				return KeyInfo{}, fmt.Errorf("невозможно определить размер ключа")
			}
			keySize = pubKey.Size() * 8
			blockSize = calculateBlockSize(keySize)
		}
	}

	return KeyInfo{KeySize: keySize, BlockSize: blockSize}, nil
}

func loadPrivateKey(path string) (*rsa.PrivateKey, KeyInfo, error) {
	privateKeyData, err := os.ReadFile(path)
	if err != nil {
		return nil, KeyInfo{}, fmt.Errorf("ошибка чтения файла приватного ключа: %v", err)
	}

	block, _ := pem.Decode(privateKeyData)
	if block == nil {
		return nil, KeyInfo{}, fmt.Errorf("ошибка декодирования PEM блока")
	}

	keyInfo, err := getKeyInfoFromPEM(block)
	if err != nil {
		return nil, KeyInfo{}, err
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, KeyInfo{}, fmt.Errorf("ошибка парсинга приватного ключа: %v", err)
	}

	return privateKey, keyInfo, nil
}

func loadPublicKey(path string) (*rsa.PublicKey, KeyInfo, error) {
	publicKeyData, err := os.ReadFile(path)
	if err != nil {
		return nil, KeyInfo{}, fmt.Errorf("ошибка чтения файла публичного ключа: %v", err)
	}

	block, _ := pem.Decode(publicKeyData)
	if block == nil {
		return nil, KeyInfo{}, fmt.Errorf("ошибка декодирования PEM блока")
	}

	keyInfo, err := getKeyInfoFromPEM(block)
	if err != nil {
		return nil, KeyInfo{}, err
	}

	publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, KeyInfo{}, fmt.Errorf("ошибка парсинга публичного ключа: %v", err)
	}

	return publicKey, keyInfo, nil
}

func encryptFileParallel(inputPath string, outputPath string, publicKey *rsa.PublicKey, blockSize int) error {
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("ошибка открытия входного файла: %v", err)
	}
	defer inputFile.Close()

	outputFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("ошибка создания выходного файла: %v", err)
	}
	defer outputFile.Close()

	bufferedInput := bufio.NewReaderSize(inputFile, bufferSize)
	bufferedOutput := bufio.NewWriterSize(outputFile, bufferSize)
	defer bufferedOutput.Flush()

	fileInfo, err := inputFile.Stat()
	if err != nil {
		return fmt.Errorf("ошибка получения информации о файле: %v", err)
	}

	bar := progressbar.DefaultBytes(
		fileInfo.Size(),
		"Шифрование",
	)

	numWorkers := runtime.NumCPU()
	tasks := make(chan cryptTask, numWorkers)
	results := make(chan cryptTask, numWorkers)

	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for task := range tasks {
				encryptedBlock, err := rsa.EncryptOAEP(
					sha256.New(),
					rand.Reader,
					publicKey,
					task.data,
					nil,
				)
				task.result = encryptedBlock
				task.err = err
				results <- task
			}
		}()
	}

	go func() {
		defer close(results)
		wg.Wait()
	}()

	go func() {
		defer close(tasks)
		buffer := make([]byte, blockSize)
		index := 0
		for {
			n, err := bufferedInput.Read(buffer)
			if err != nil && err != io.EOF {
				tasks <- cryptTask{err: err}
				return
			}
			if n == 0 {
				break
			}

			dataCopy := make([]byte, n)
			copy(dataCopy, buffer[:n])
			tasks <- cryptTask{
				data:  dataCopy,
				index: index,
			}
			index++
		}
	}()

	resultBuffer := make(map[int][]byte)
	nextIndex := 0

	for task := range results {
		if task.err != nil {
			return fmt.Errorf("ошибка шифрования блока: %v", task.err)
		}

		resultBuffer[task.index] = task.result

		for {
			if data, ok := resultBuffer[nextIndex]; ok {
				err := binary.Write(bufferedOutput, binary.LittleEndian, uint32(len(data)))
				if err != nil {
					return fmt.Errorf("ошибка записи размера блока: %v", err)
				}

				_, err = bufferedOutput.Write(data)
				if err != nil {
					return fmt.Errorf("ошибка записи зашифрованного блока: %v", err)
				}

				bar.Add(len(task.data))
				delete(resultBuffer, nextIndex)
				nextIndex++
			} else {
				break
			}
		}
	}

	return nil
}

func decryptFileParallel(inputPath string, outputPath string, privateKey *rsa.PrivateKey) error {
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("ошибка открытия входного файла: %v", err)
	}
	defer inputFile.Close()

	outputFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("ошибка создания выходного файла: %v", err)
	}
	defer outputFile.Close()

	bufferedInput := bufio.NewReaderSize(inputFile, bufferSize)
	bufferedOutput := bufio.NewWriterSize(outputFile, bufferSize)
	defer bufferedOutput.Flush()

	fileInfo, err := inputFile.Stat()
	if err != nil {
		return fmt.Errorf("ошибка получения информации о файле: %v", err)
	}

	bar := progressbar.DefaultBytes(
		fileInfo.Size(),
		"Расшифровка",
	)

	numWorkers := runtime.NumCPU()
	tasks := make(chan cryptTask, numWorkers)
	results := make(chan cryptTask, numWorkers)

	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for task := range tasks {
				decryptedBlock, err := rsa.DecryptOAEP(
					sha256.New(),
					rand.Reader,
					privateKey,
					task.data,
					nil,
				)
				task.result = decryptedBlock
				task.err = err
				results <- task
			}
		}()
	}

	go func() {
		defer close(results)
		wg.Wait()
	}()

	go func() {
		defer close(tasks)
		index := 0
		for {
			var blockSize uint32
			err := binary.Read(bufferedInput, binary.LittleEndian, &blockSize)
			if err == io.EOF {
				break
			}
			if err != nil {
				tasks <- cryptTask{err: fmt.Errorf("ошибка чтения размера блока: %v", err)}
				return
			}

			encryptedBlock := make([]byte, blockSize)
			_, err = io.ReadFull(bufferedInput, encryptedBlock)
			if err != nil {
				tasks <- cryptTask{err: fmt.Errorf("ошибка чтения зашифрованного блока: %v", err)}
				return
			}

			tasks <- cryptTask{
				data:  encryptedBlock,
				index: index,
			}
			index++
			bar.Add(int(blockSize))
		}
	}()

	resultBuffer := make(map[int][]byte)
	nextIndex := 0

	for task := range results {
		if task.err != nil {
			return fmt.Errorf("ошибка расшифровки блока: %v", task.err)
		}

		resultBuffer[task.index] = task.result

		for {
			if data, ok := resultBuffer[nextIndex]; ok {
				_, err := bufferedOutput.Write(data)
				if err != nil {
					return fmt.Errorf("ошибка записи расшифрованного блока: %v", err)
				}
				delete(resultBuffer, nextIndex)
				nextIndex++
			} else {
				break
			}
		}
	}

	return nil
}

func main() {
	encrypt := flag.Bool("e", false, "Режим шифрования")
	decrypt := flag.Bool("d", false, "Режим расшифровки")
	inputFile := flag.String("in", "", "Путь к входному файлу")
	outputFile := flag.String("out", "", "Путь к выходному файлу")
	genKeys := flag.Bool("g", false, "Сгенерировать новую пару ключей")
	keySize := flag.Int("size", 2048, "Размер ключа в битах (минимум 1024)")
	workers := flag.Int("workers", runtime.NumCPU(), "Количество параллельных обработчиков")
	privateKeyFile := flag.String("private", "private.pem", "Путь к файлу приватного ключа")
	publicKeyFile := flag.String("public", "public.pem", "Путь к файлу публичного ключа")
	flag.Parse()
	runtime.GOMAXPROCS(*workers)
	if *genKeys {
		fmt.Printf("Генерация новой пары ключей размером %d бит...\n", *keySize)
		_, _, err := generateAndSaveKeys(*keySize, *privateKeyFile, *publicKeyFile)
		if err != nil {
			fmt.Printf("Ошибка генерации ключей: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Ключи успешно сгенерированы и сохранены в файлы:\n")
		fmt.Printf("- Приватный ключ: %s\n", *privateKeyFile)
		fmt.Printf("- Публичный ключ: %s\n", *publicKeyFile)
		os.Exit(0)
	}
	if *inputFile == "" || *outputFile == "" {
		fmt.Println("Использование:")
		fmt.Println("  Генерация ключей: program -g [-size размер_ключа] [-private путь_к_приватному_ключу] [-public путь_к_публичному_ключу]")
		fmt.Println("  Шифрование:       program -e -in входной_файл -out выходной_файл [-public путь_к_публичному_ключу] [-workers количество_процессов]")
		fmt.Println("  Расшифровка:      program -d -in входной_файл -out выходной_файл [-private путь_к_приватному_ключу] [-workers количество_процессов]")
		os.Exit(1)
	}

	// Проверяем существование входного файла
	if _, err := os.Stat(*inputFile); os.IsNotExist(err) {
		fmt.Printf("Ошибка: входной файл '%s' не существует\n", *inputFile)
		os.Exit(1)
	}

	if *encrypt {
		publicKey, keyInfo, err := loadPublicKey(*publicKeyFile)
		if err != nil {
			fmt.Printf("Ошибка загрузки публичного ключа: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Используется ключ размером %d бит (размер блока: %d байт)\n",
			keyInfo.KeySize, keyInfo.BlockSize)
		fmt.Printf("Количество рабочих процессов: %d\n", *workers)

		err = encryptFileParallel(*inputFile, *outputFile, publicKey, keyInfo.BlockSize)
		if err != nil {
			fmt.Printf("Ошибка шифрования: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("\nФайл успешно зашифрован")
	} else if *decrypt {
		privateKey, keyInfo, err := loadPrivateKey(*privateKeyFile)
		if err != nil {
			fmt.Printf("Ошибка загрузки приватного ключа: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Используется ключ размером %d бит (размер блока: %d байт)\n",
			keyInfo.KeySize, keyInfo.BlockSize)
		fmt.Printf("Количество рабочих процессов: %d\n", *workers)

		err = decryptFileParallel(*inputFile, *outputFile, privateKey)
		if err != nil {
			fmt.Printf("Ошибка расшифровки: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("\nФайл успешно расшифрован")
	} else {
		fmt.Println("Необходимо указать режим (-e для шифрования или -d для расшифровки)")
		os.Exit(1)
	}
}
