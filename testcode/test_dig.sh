#!/bin/env bash
# This script is used to test the dig command

zone=pn.pinning.dns4test.com.

unbound-control flush "$zone" && unbound-control flush "$zone"
dig @127.0.0.1 "$zone" NS
