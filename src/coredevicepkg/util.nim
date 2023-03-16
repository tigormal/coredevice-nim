# func toByteSeq*(str: string): seq[byte] {.inline.} =
#   ## Converts a string to the corresponding byte sequence.
#   @(str.toOpenArrayByte(0, str.high))

# func toString*(bytes: openArray[byte]): string {.inline.} =
#   ## Converts a byte sequence to the corresponding string.
#   let length = bytes.len
#   if length > 0:
#     result = newString(length)
#     copyMem(result.cstring, bytes[0].unsafeAddr, length)

func crc8*(payload: openArray[byte]): byte =
    result = 0xff
    for i in 0..(payload.len-1):
        result = result xor payload[i]
        for j in 0..8:
            if (result and 0x80) != 0:
                result = (result shl 1) xor 0x31
            else:
                result = result shl 1