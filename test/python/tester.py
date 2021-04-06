#!/usr/bin/env python

import requests
import argparse
import stf

parser = argparse.ArgumentParser(description='Send a command to the strongforth server and receive a response.')
parser.add_argument('ip', type=str,
                    help='ip address of the server')
args = parser.parse_args()
url = "http://" + args.ip


stf.stf_init("../../forth/strongforth.zf")

#resp = requests.post(url, "pri pub genkey pub 32> pri 32>")
#print(resp.text)

resp = stf.stf_eval([b"pub< CEBPO3SUJXGTJVASK4XLQH2O24N2QYD2MX26UCYVTZUUTKTZHMLU3M6QAZGGFIOVVIJAEE73YAGQDSMG2JNUMTBAJN65N2NQU4CJPNA 14 pub setpub"])
print(str(resp[0][1]) +  " : " + resp[0][2])
# AT2CI2VIKS5FT5O7H22VTI5A2LVEC7OF
