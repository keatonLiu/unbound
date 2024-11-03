#!/usr/local/bin/bash
# This script is used to test the dig command
unbound-control flush www.baidu.com && unbound-control flush baidu.com
dig @127.0.0.1 www.baidu.com 
