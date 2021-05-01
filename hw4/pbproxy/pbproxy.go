package main

import (
    "fmt"
    "flag"
    "log"
    "os"
    "bufio"
//    "io"
    "net"
    "golang.org/x/crypto/pbkdf2"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
)

var (
    destination string
    port string
    passwd string
    saltLength int = 8
)

func check(e error) {
    if e != nil {
        log.Fatal(e)
    }
}

func encrypt(plaintext []byte) []byte {
    salt := make([]byte, saltLength)
    rand.Read(salt)
//    log.Println("esalt", len(salt), hex.Dump(salt))
    aesKey := pbkdf2.Key([]byte(passwd), salt, 4096, 32, sha256.New)

    block, err := aes.NewCipher(aesKey)
    check(err)

    aesgcm, err := cipher.NewGCM(block)
    check(err)

    nonce := make([]byte, aesgcm.NonceSize())
    rand.Read(nonce)
//    log.Println("enonce", len(nonce), hex.Dump(nonce))

    data := append(salt, nonce...)
//    log.Println("eplaintext", len(plaintext), hex.Dump(plaintext))
    encryptedData := aesgcm.Seal(data, nonce, plaintext, nil)
//    log.Println("eencryptedData", len(encryptedData), hex.Dump(encryptedData))
    return encryptedData
}

func decrypt(data []byte) []byte {

    salt := data[:saltLength]
    log.Println("dsalt", len(salt), hex.Dump(salt))

    aesKey := pbkdf2.Key([]byte(passwd), salt, 4096, 32, sha256.New)

    block, err := aes.NewCipher(aesKey)
    check(err)

    aesgcm, err := cipher.NewGCM(block)
    check(err)

    nonceSize := aesgcm.NonceSize()
    nonce := data[saltLength : nonceSize + saltLength]
    log.Println("dnonce", len(nonce))
    encryptedData := data[nonceSize + saltLength : ]
    log.Println("dencryptedData", len(encryptedData), hex.Dump(encryptedData))

    plaintext, err := aesgcm.Open(nil, nonce, encryptedData, nil)
    log.Println("dplaintext", len(plaintext))
    check(err)

    return plaintext
}

func handleConnection (clientConn *net.TCPConn) {
    serviceConn, err := net.Dial("tcp", destination + ":" + port)
    if err != nil {
        log.Println("Error connecting to the service", err)
        return
    }
    serviceData := make([]byte, 4096)
    go func() {
        for {
            //log.Println("READING FROM SERVICE")
            if nr2, err := serviceConn.Read(serviceData); err == nil {
//                log.Println("Before Encrypt", nr2)
                encryptedServiceData := encrypt(serviceData[:nr2])
//                log.Println("After Encrypt", len(encryptedServiceData))
                _, err := clientConn.Write(encryptedServiceData)
                check(err)
                //log.Println("WRITE TO CLIENT DONE", nw2, hex.Dump(serviceData[:nw2]))
            } else {
                //log.Println("BROKE 1", err)
                break
            }
        }
    }()
    clientData := make([]byte, 4132)
    for {
        //log.Println("READING FROM CLIENT")
        if nr1, err := clientConn.Read(clientData); err == nil {
//            log.Println("Before Decrypt", nr1, hex.Dump(clientData[:nr1]))
            decryptedClientData := decrypt(clientData[:nr1])
//            log.Println("After Decrypt", len(decryptedClientData), hex.Dump(decryptedClientData))
            _, err := serviceConn.Write(decryptedClientData)
            check(err)
            //log.Println("WRITE TO SERVICE DONE", nw1, hex.Dump(clientData[:nw1]))
        } else {
            //log.Println("BROKE", err)
            break
        }
    }

//    log.Println("Closing...")
    serviceConn.Close()
    clientConn.Close()
}

func listen(port string) {
    addr, err := net.ResolveTCPAddr("tcp", ":" + port)
    check(err)

    ln, err := net.ListenTCP("tcp", addr)
    check(err)

    for {
        conn, err := ln.AcceptTCP()
        check(err)

        conn.SetReadBuffer(4132)
        conn.SetWriteBuffer(4132)
        go handleConnection(conn)
    }
}

func readAndSend() {
    reader := bufio.NewReader(os.Stdin)

    addr, err := net.ResolveTCPAddr("tcp", destination + ":" + port)
    check(err)

    conn, err := net.DialTCP("tcp", nil, addr)
    check(err)
    conn.SetReadBuffer(4132)
    conn.SetWriteBuffer(4132)

    serverData := make([]byte, 4132)
    go func() {
        for {
            //log.Println("READING FROM SERVER")
            if n, err := conn.Read(serverData); err == nil {
//                log.Println("Before decrypt", n)
                decryptedData := decrypt(serverData[:n])
//                log.Println("After decrypt", len(decryptedData))
                os.Stdout.Write(decryptedData)
                //log.Println("WRITE TO STDOUT DONE")
            } else {
                //log.Println("BROKE")
                break
            }
        }
    }()

    stdinData := make([]byte, 4096)

    for {
        //log.Println("READING FROM STDIN")
        if n, err := reader.Read(stdinData); err == nil {
            //stdinData = append(stdinData, data)
        //} else if err == io.EOF {
//            log.Println("Before encrypt", len(stdinData))
encryptedData := encrypt(stdinData[:n])
//            log.Println("After encrypt", len(encryptedData))
            _, err := conn.Write(encryptedData)
            check(err)
          //  stdinData = make([]byte, 0)
            //log.Println("WRITE TO SERVER DONE")
        } else {
            //log.Println("BROKE 1")
            break
        }
    }
    conn.Close()
}

func main() {

    listenPort := flag.String("l", "", "listenport")
    pwdFile := flag.String("p", "", "path to password file")

    flag.Parse()

    if *pwdFile == "" {
        log.Fatal("Please provide a file containing the password text with option -p\n")
    }
    file, err := os.Open(*pwdFile)
    check(err)
    defer file.Close()

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        passwd = scanner.Text()
        break;
    }

    var args = flag.Args()

    if len(args) != 2 {
        log.Fatal("Args expected: 'destination port'\n")
    }

    destination = args[0]
    port = args[1]

    if *listenPort != "" {
        fmt.Println("Listening on port", *listenPort)
        listen(*listenPort)
    } else {
        readAndSend()
    }

}
