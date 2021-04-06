#!/usr/bin/env python

import requests
import argparse

parser = argparse.ArgumentParser(description='Send a command to the strongforth server and receive a response.')
parser.add_argument('ip', type=str,
                    help='ip address of the server')
parser.add_argument('command', type=str,
                    help='command to send')

args = parser.parse_args()

resp = requests.post(args.url, args.command)

print(resp)
