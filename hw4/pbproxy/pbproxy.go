package main

import (
    "fmt"
    "flag"
    "log"
    "os"
    "bufio"
    "net"
)

func check(e error) {
    if e != nil {
        log.Fatal(e)
    }
}

func handleConnection (conn net.Conn) {
    fmt.Println(conn)
    conn.Close()
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

    var passwd = ""
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        passwd = scanner.Text()
        break;
    }

    var args = flag.Args()

    if len(args) != 2 {
        log.Fatal("Args expected: 'destination port'\n")
    }

    var destination = args[0]
    var port = args[1]

    if *listenPort != "" {
        fmt.Println("Listening on port", *listenPort)
        listen(*listenPort)
    } else {
    }

}
