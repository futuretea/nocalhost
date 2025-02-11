/*
* Copyright (C) 2021 THL A29 Limited, a Tencent company.  All rights reserved.
* This source code is licensed under the Apache License Version 2.0.
 */

package daemon_client

import (
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func TestTimeout(t *testing.T) {
	addr, _ := net.ResolveTCPAddr("tcp4", "127.0.0.1:48888")

	tcp, _ := net.ListenTCP("tcp", addr)
	go func() {
		for {
			accept, _ := tcp.Accept()
			go func() {
				defer accept.Close()
				time.Sleep(time.Second * 10)
				_, err := accept.Write([]byte("timeout"))
				if err != nil {
					fmt.Println(err)
				}
			}()
		}
	}()
	for i := 0; i < 10; i++ {
		now := time.Now()
		timeout, err := net.DialTimeout("tcp", "127.0.0.1:48888", time.Second*30)
		if err != nil {
			fmt.Println(err)
		}
		if err = timeout.SetReadDeadline(time.Now().Add(time.Second * 5)); err != nil {
			fmt.Println(err)
		}
		_, err = io.ReadAll(timeout)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Printf("cost: %fs\n", time.Now().Sub(now).Seconds())
	}
}
