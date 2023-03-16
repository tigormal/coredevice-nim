# This is just an example to get you started. You may wish to put all of your
# tests into a single file, or separate them into multiple `test1`, `test2`
# etc. files (better names are recommended, just make sure the name starts with
# the letter 't').
#
# To run these tests, simply execute `nimble test`.

import unittest

import coredevicepkg/protocol
# import coredevicepkg/util
import uuid
import stew/byteutils
import strutils
import nimcrypto
import random

# test "correct welcome":
#   check getWelcomeMessage() == "Hello, World!"]
let 
    pd = "This is pd" 
    recv = ($genUUIDv4()).replace("-").hexToSeqByte 
    send = ($genUUIDv4()).replace("-").hexToSeqByte
    # echo recv
    # echo send

test "Message to and from bytes":
    var myMsg = newCDMsg(kind = CDMsgKind.None, payload = pd.toBytes, recvID = recv, sendID = send, ack = true)
    var myBytes = myMsg.bytes
    # echo myBytes 
    var decodedMsg = fromBytes(myBytes)
    # echo decodedMsg.bytes
    check myMsg.kind == decodedMsg.kind
    check myMsg.num == decodedMsg.num
    check myMsg.size == decodedMsg.size
    check myMsg.ack == decodedMsg.ack
    check myMsg.hash == decodedMsg.hash
    check myMsg.recvID == decodedMsg.recvID
    check myMsg.sendID == decodedMsg.sendID
    check myMsg.payload == decodedMsg.payload

test "Message encryption":
    var msg1 = newCDMsg(kind = CDMsgKind.Command, payload = pd.toBytes, recvID = recv, sendID = send, ack = true)
    var key: seq[byte]
    for i in 0..aes256.sizeKey-1:
        key.add(byte(rand(0..255)))

    var 
        msg1Bytes = msg1.bytes()
        msg1BytesEnc = msg1.bytes(key = key)

    echo "Original msg ", msg1Bytes.toHex(false)
    echo "Encrypted msg ", msg1BytesEnc.toHex(false)

    var msg2 = fromBytes(msg1BytesEnc, key = key)
    echo "Decrypted message ", msg2.bytes.toHex(false)

    check msg1Bytes == msg2.bytes 
