package main

import (
    "fmt"
    "flag"
    "log"
    "os"
    "bufio"
    "net"
    "encoding/hex"
    //"bytes"
//    "io"
)

var (
    destination string
    port string
    passwd string
)

func check(e error) {
    if e != nil {
        log.Fatal(e)
    }
}

func handleConnection (clientConn net.Conn) {
    serviceConn, err := net.Dial("tcp", destination + ":" + port)
    if err != nil {
        log.Println("Error connecting to the service", err)
        return
    }
    serviceData := make([]byte, 1600)
    go func() {
        for {
            log.Println("READING FROM SERVICE")
            if nr2, err := serviceConn.Read(serviceData); err == nil {
                log.Println("READ FROM SERVICE DONE", nr2, hex.Dump(serviceData[:nr2]))
                nw2, err := clientConn.Write(serviceData[:nr2])
                check(err)
                log.Println("WRITE TO CLIENT DONE", nw2, hex.Dump(serviceData[:nw2]))
            } else {
                log.Println("BROKE 1", err)
                break
            }
        }
    }()
    clientData := make([]byte, 1600)
    for {
        log.Println("READING FROM CLIENT")
        if nr1, err := clientConn.Read(clientData); err == nil {
            log.Println("READ FROM CLIENT DONE", nr1, hex.Dump(clientData[:nr1]))
            nw1, err := serviceConn.Write(clientData[:nr1])
            check(err)
            log.Println("WRITE TO SERVICE DONE", nw1, hex.Dump(clientData[:nw1]))
        } else {
            log.Println("BROKE", err)
            break
        }
    }

    log.Println("Closing...")
    serviceConn.Close()
    clientConn.Close()
}

func listen(port string) {
    ln, err := net.Listen("tcp", ":" + port)
    check(err)

    for {
        conn, err := ln.Accept()
        check(err)

        go handleConnection(conn)
    }
}

func readAndSend() {
    reader := bufio.NewReader(os.Stdin)

    conn, err := net.Dial("tcp", destination + ":" + port)
    check(err)

    serverData := make([]byte, 1600)
    stdinData := make([]byte, 1)
    go func() {
        for {
            log.Println("READING FROM SERVER")
            if n, err := conn.Read(serverData); err == nil {
                log.Println("READ FROM SERVER", n, hex.Dump(serverData[:n]))
                os.Stdout.Write(serverData[:n])
                log.Println("WRITE TO STDOUT DONE")
            } else {
                log.Println("BROKE")
                break
            }
        }
    }()

    for {
        log.Println("READING FROM STDIN")
        if data, err := reader.ReadByte(); err == nil {
            stdinData[0] = data
            log.Println("READ FROM STDIN DONE", hex.Dump(stdinData))
            _, err := conn.Write(stdinData)
            check(err)
            log.Println("WRITE TO SERVER DONE")
        } else {
            log.Println("BROKE 1")
            break
        }
    }
    log.Println("Closing...")
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
