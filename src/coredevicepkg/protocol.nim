import cascade
import nimcrypto
import util
import stew/byteutils
import std/random

const sizeBlock = aes256.sizeBlock
const sizeKey = aes256.sizeKey

type CDMsgKind* = enum
    None = 0,
    Command,
    DataAnnounce,
    DataPackage,
    Telemetry,
    Handshake,
    Response,
    Request

type CDMsg* = object
    startMark*: byte
    ack*: bool
    kind*: CDMsgKind
    recvID* : seq[byte]
    sendID* : seq[byte]
    num* : byte
    hash* : byte
    size* : byte
    payload* : seq[byte]

const 
    PayloadMaxSize* = 0xFF
    BroadcastBytes* = @[0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0]
    BroadcastReplyBytes* = @[0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF]


proc fromBytes*(msg: seq[byte], key: seq[byte] = @[]): CDMsg {.raises: [ValueError].} = 
    var 
        num = msg[33]
        hash = msg[34]
        size = msg[35]
        payload = msg[36..^1]
    
    # Decrypt if key
    if key.len > 0:
        # echo "DECRYPT KEY: ", key
        if key.len != sizeKey:
            raise newException(ValueError, ("Bad key. Given key of length " & $key.len & ". Should be " & $sizeKey))
        else:
            # Encrypted data as byte seq
            var 
                encoded = @[num, hash, size] & payload
            # Refresh system's randomizer
            randomize() 
            # Prepare ingridients
            const roomLen = sizeBlock # * 2
            var
                dctx: ECB[aes256]
                keyData: seq[byte]
                pos: byte = sizeBlock - byte(encoded.len) # Random position in block
                encData: array[roomLen, byte]
                decData: array[roomLen, byte]
            # Padding
            if pos == 0: pos = sizeBlock
            for i in 0..roomLen-1:
                encData[i] = pos
                decData[i] = pos
            # discard randomBytes(addr encData[0], roomLen)
            # discard randomBytes(addr decData[0], roomLen)
            # echo "pos ", pos
            # echo "encData ", encData
            # echo "decData ", decData

            # Put things into places
            copyMem(addr encData[0], addr encoded[0], roomLen)
            keyData = cast[seq[byte]](key)
            # echo "KEY: ", keyData

            # Decrypt
            dctx.init(keyData)
            dctx.decrypt(encData, decData)
            dctx.clear()
            # echo "ENCRYPTED: ", encData.toHex
            # echo "DECRYPTED: ", decData.toHex

            # Put things back
            copyMem(addr num,   addr decData[0],  1)
            copyMem(addr hash,  addr decData[1],  1)
            copyMem(addr size,  addr decData[2],  1)
            payload.setLen(size)
            copyMem(addr payload[0], addr decData[3], size)

            # Clean up traces in memory
            discard randomBytes(addr encData[0], roomLen)
            discard randomBytes(addr decData[0], roomLen)

    result = cascade CDMsg():
        startMark = ((msg[0]) and 0b11110000) shr 4
        kind = CDMsgKind((msg[0]) and 0b00000111)
        ack = bool(((msg[0]) and 0b00001000) shr 3)
        recvID = msg[1..16]
        sendID = msg[17..32]
        num = num
        hash = hash
        size = size
        payload = payload


proc bytes*(msg: CDMsg, key: seq[byte] = @[]): seq[byte] {.raises: [ValueError].} = 
    var header = byte(msg.startMark shl 4) or byte(byte(msg.ack) shl 3) or byte(msg.kind)
    
    var 
        num = msg.num
        hash = msg.hash
        size = msg.size
        payload = msg.payload

     # Encrypt if key
    if key.len > 0:
        # echo "ENCRYPT KEY: ", key
        if key.len != sizeKey:
            raise newException(ValueError, ("Bad key. Given key of length " & $key.len & ". Should be " & $sizeKey))
        else:
            # Original data as byte seq
            var 
                plain = @[num, hash, size] & payload
            # Refresh system's randomizer
            randomize() 
            # Prepare ingridients
            const roomLen = sizeBlock
            var
                ectx: ECB[aes256]
                keyData: seq[byte]
                pos: byte = sizeBlock - byte(plain.len) # Amount of bytes missing for full block
                encData: array[roomLen, byte]
                plaData: array[roomLen, byte]
            # Padding
            if pos == 0: pos = sizeBlock
            for i in 0..roomLen-1:
                encData[i] = pos
                plaData[i] = pos
            # discard randomBytes(addr encData[0], roomLen)
            # discard randomBytes(addr plaData[0], roomLen)
            # echo "pos ", pos
            # echo "encData ", encData
            # echo "plaData ", plaData

            # Put things into places
            copyMem(addr plaData[0], addr plain[0], plain.len)
            keyData = cast[seq[byte]](key)
            # echo "KEY: ", keyData

            # Decrypt
            ectx.init(keyData)
            ectx.encrypt(plaData, encData)
            ectx.clear()
            # echo "PLAIN: ", plaData.toHex
            # echo "ENCRYPTED: ", encData.toHex

            # Put things back
            copyMem(addr num,   addr encData[0],  1)
            copyMem(addr hash,  addr encData[1],  1)
            copyMem(addr size,  addr encData[2],  1)
            payload.setLen(roomLen - 3)
            copyMem(addr payload[0], addr encData[3], roomLen - 3)

            # Clean up traces in memory
            discard randomBytes(addr encData[0], roomLen)
            discard randomBytes(addr plaData[0], roomLen)

    result = @[header] & msg.recvID & msg.sendID & @[num, hash, size] & payload
    

proc newCDMsg*(kind: CDMsgKind; recvID, sendID, payload : seq[byte], ack: bool, key=""): CDMsg = 
    result = cascade CDMsg():
        startMark = 0x03
        kind = kind
        recvID = recvID
        sendID = sendID
        payload = payload
        ack = ack
        size = byte(payload.len)
        hash = crc8(payload)


proc equals*(a: CDMsg, b: CDMsg): bool = 
    result = (a.kind == b.kind and a.recvID == b.recvID and a.sendID == b.sendID and a.size == b.size and a.num == b.num and a.ack == b.ack and a.hash == b.hash and a.payload == b.payload)

proc `==`*(a: CDMsg, b: CDMsg): bool = equals(a,b)