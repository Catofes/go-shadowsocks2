#!/bin/bash
mkdir -p build
env CGO_ENABLED=0 go build -o build/mysqld github.com/Catofes/go-shadowsocks2
    
