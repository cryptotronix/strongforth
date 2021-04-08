#!/usr/bin/env python

import requests
import argparse
import stf

parser = argparse.ArgumentParser(
        description='Send a command to the strongforth ' +
                    'server and receive a response.')
parser.add_argument('ip', type=str,
                    help='ip address of the server')

s13_priv = "pri< VXAVBAN7MB5IRYKGOH6L2TJ6SSNHHQDMDOEV3RNPXQ4M26NV3DBA "
s13_pub = "pub< MA2EUOQYVMDVDCYVQAIEHIPPJTK7OKLFBSEZ7R27D2ZXPE7ST5BTDACKQRKS2ABTZJYWN6MX6GVULLGBKSXKWTNJ2VA2NO63JWUCAWA "
s14_priv = "pri< 4HMP52TTXLRE5ZNNTLMKJF6TPLIPZ332KNDE6SOYEJTW7NYX6K2A "
s14_pub = "pub< DN5OYOGGEDGHWDAJYHZZH2SEILCZQUZ4U4ARA7JQM5SN5KZ4M6TAIMMCXTAVIUHX77QPPYBOX53ULM3R5MCOXT53WGE42JVOOYFS42Y "
rot_seed = b"see< AT2CI2VIKS5FT5O7H22VTI5A2LVEC7OF "
msg = "m< EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE "
bmsg = b"m< EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE "


def main():
    args = parser.parse_args()
    url = "http://" + args.ip

    stf.stf_init("../../forth/strongforth.zf")

    print("rotate: " + str(test_rotate(url)))
    print("aa: " + str(test_aa(url)))
    print("saa: " + str(test_saa(url)))
    print("cda: " + str(test_cda(url)))
    print("se: " + str(test_se(url)))
    print("ses: " + str(test_ses(url)))


def print_array(arr):
    for a in arr:
        print(a)


def test_rotate(url):

    responses = []

    def rotate(valid):
        validate = 0
        if valid:
            validate = -1

        resp = stf.stf_eval([rot_seed + str(validate).encode("utf-8") + b" rot1"])
        responses.append(str(resp[0][1]) + " : " + resp[0][2])

        resp = requests.post(url, s13_priv + resp[0][2])
        responses.append(resp.text)

        resp = stf.stf_eval([resp.text.encode("utf-8")])
        responses.append(str(resp[0][1]) + " : " + resp[0][2])

        return resp[0][1]

    if rotate(False) != -1:
        print("invalidate failed")
        print_array(responses)
        return 1

    resp = stf.stf_eval([s14_pub.encode("utf-8") + b"14 pub setpub"])
    responses.append(str(resp[0][1]) + " : " + resp[0][2])

    stat = rotate(True)
    if stat != -1:
        print_array(responses)

    return stat


def test_aa(url):

    responses = []

    resp = requests.post(url, "aa1")
    responses.append(resp.text)

    resp = stf.stf_eval([resp.text.encode("utf-8")])
    responses.append(str(resp[0][1]) + " : " + resp[0][2])

    resp = requests.post(url, resp[0][2])
    responses.append(resp.text)

    if int(resp.text) != -1:
        print_array(responses)

    return int(resp.text)


def test_saa(url):

    responses = []

    resp = requests.post(url, "aa1s non memzero ran memzero")
    responses.append(resp.text)

    cmd_info = resp.text.split("|")

    resp = stf.stf_eval([cmd_info[0].encode("utf-8")])
    responses.append(str(resp[0][1]) + " : " + resp[0][2])

    resp = requests.post(url, cmd_info[1] + resp[0][2])
    responses.append(resp.text)

    if int(resp.text) != -1:
        print_array(responses)

    return int(resp.text)


def test_cda(url):

    responses = []

    resp = requests.post(url, "cda1")
    responses.append(resp.text)

    resp = stf.stf_eval([resp.text.encode("utf-8")])
    responses.append(str(resp[0][1]) + " : " + resp[0][2])

    resp = requests.post(url, s14_priv + "dig getrand " + resp[0][2])
    responses.append(resp.text)

    resp = stf.stf_eval([resp.text.encode("utf-8")])
    responses.append(str(resp[0][1]) + " : " + resp[0][2])

    if resp[0][1] != -1:
        print_array(responses)

    return resp[0][1]


def test_se(url):

    responses = []

    resp = stf.stf_eval([b"se1"])
    responses.append(str(resp[0][1]) + " : " + resp[0][2])

    resp = requests.post(url, s14_priv  + resp[0][2])
    responses.append(resp.text)

    resp = stf.stf_eval([resp.text.encode("utf-8")])
    responses.append(str(resp[0][1]) + " : " + resp[0][2])

    if resp[0][1] != -1:
        print("key derivation steps failed")
        print_array(responses)
        return resp[0][1]

    resp = requests.post(url, msg + ' k uplink bufcpy 28 encrypt ." c< " c 32>')
    responses.append(resp.text)

    resp = stf.stf_eval([resp.text.encode("utf-8") + b" k dolink bufcpy decrypt m 32>"])
    responses.append(str(resp[0][1]) + " : " + resp[0][2])

    if resp[0][2] != 'EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE ':
        print_array(responses)
        return 0

    return -1


def test_ses(url):

    responses = []

    resp = stf.stf_eval([b"se1s"])
    responses.append(str(resp[0][1]) + " : " + resp[0][2])

    resp = requests.post(url, s14_priv + resp[0][2] + " dolink memzero uplink memzero pri memzero pub memzero 0 domsgid ! 0 upmsgid !")
    responses.append(resp.text)

    enc_info = resp.text.split("|")

    resp = stf.stf_eval([enc_info[0].encode("utf-8")])
    responses.append(str(resp[0][1]) + " : " + resp[0][2])

    if resp[0][1] != -1:
        print("key derivation steps failed")
        print_array(responses)
        return resp[0][1]

    resp = requests.post(url, msg + enc_info[2] + ' k uplink bufcpy 28 encrypts ." c< " c 32> m memzero')
    responses.append(resp.text)

    msg_info = resp.text.split("|")

    resp = stf.stf_eval([msg_info[1].encode("utf-8") + b' k dolink bufcpy decrypt ." m< " m 32>'])
    responses.append(str(resp[0][1]) + " : " + resp[0][2])

    resp = stf.stf_eval([resp[0][2].encode("utf-8") + b' k uplink bufcpy 28 encrypt ." c< " c 32>'])
    responses.append(str(resp[0][1]) + " : " + resp[0][2])

    resp = requests.post(url, resp[0][2] + msg_info[0] + enc_info[2] + ' k dolink bufcpy decrypts m 32>')
    responses.append(resp.text)

    if resp.text.split("|")[1] != ' EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE ':
        print_array(responses)
        return 0

    return -1

if __name__ == "__main__":
    main()
