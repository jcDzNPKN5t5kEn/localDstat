package main

import (

	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"sync"
	"time"
)

var (
	rps float64
	counter   int
	mutex     sync.Mutex
	startTime time.Time
	maxRps    int
	https     = flag.Bool("https", false, "https")
)

func main() {
	flag.Parse()
	startTime = time.Now()
	go printStats()

	if *https {
		cert, _ := GenerateSelfSignedCert()
		// 设置HTTP路由
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			// 记录连接数
			mutex.Lock()
			counter++
			mutex.Unlock()
			w.Write([]byte (fmt.Sprintf("%.2f conn/s",rps)))
		})

		// 创建TLS配置
		config := &tls.Config{
			Certificates: []tls.Certificate{*cert},
		}

		// 创建TLS listener
		listener, err := net.Listen("tcp", ":8080")
		if err != nil {
			panic(err)
		}

		// 监听HTTPS请求
		tlsListener := tls.NewListener(listener, config)
		err = http.Serve(tlsListener, nil)
		if err != nil {
			panic(err)
		}
	} else {
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			// 记录连接数
			mutex.Lock()
			counter++
			mutex.Unlock()

			w.Write([]byte (fmt.Sprintf("%.2f conn/s",rps)))
		})

		http.ListenAndServe(":8080", nil)
	}
}

func printStats() {
	//fmt.Printf("init")
	//time.Sleep(1 * time.Second)
	for {
		time.Sleep(1 * time.Second)
		duration := time.Since(startTime)
		if counter > maxRps {
			maxRps = counter
		}
		fmt.Printf("Received %d connections in %s (max=%d)\n", counter, duration.String(), maxRps)
		mutex.Lock()
		counter = 0
		startTime = time.Now()
		mutex.Unlock()
	}
}

func GenerateSelfSignedCert() (*tls.Certificate, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privKey)})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	return &cert, nil
}
