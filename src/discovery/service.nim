import classes
import ../coredevicepkg/protocol
import ../coredevicepkg/util
import tables

class Gateway:
    var
        name: string


class NetNode:
    var name: string
    var kind: string
    var vendor: string
    var model: string
    var iconName: string
    var addresses: seq[string]

class Gadget: 
    var tags: seq[string]
    var dashboardName: string
    var uuid: seq[byte]
    var telemetry: Table[string, string]
    var lastOperation: string
    var lastMsgNum: byte

let thisGadget = Gadget().init()

var available: seq[Gadget]
var connected: seq[Gadget]

proc processMsg(msg: CDMsg, fromAddr: string, gateway: Gateway) =

    # 1. Check the receiver

    if msg.recvID != thisGadget.uuid:
        # Send to another gadget if available
        discard

    # 2. Check if sender is a connected gadget
    var connectedIDs: seq[seq[byte]] = @[]
    for g in connected:
        connectedIDs.add(g.uuid)

    if msg.sendID in connectedIDs:
        # Decrypt message
        discard

    # 3. Check message integrity
    if msg.hash != crc8(msg.payload):
        # Bad bytes
        return

    # 4. Check type
    case msg.kind:
        of CDMsgKind.None:
            # Write notification to the system
            discard
        of CDMsgKind.Command:
            discard
        of CDMsgKind.DataAnnounce:
            # Process data announce
            discard
        of CDMsgKind.DataPackage:
            # Save data
            discard
        of CDMsgKind.Telemetry:
            # Save telemetry
            discard
        of CDMsgKind.Handshake:
            # Reply to handshake
            discard
        of CDMsgKind.Request:
            # Process request
            discard
        of CDMsgKind.Response:
            # Write notification to the system
            discard

    # 5. Check ack flag

    if msg.ack:
        # Send back empty response-type message
        discard


when isMainModule:
    echo "main"