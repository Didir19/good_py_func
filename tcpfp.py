#!/usr/bin/python

import sys


sequence = []
pof_quirks = []

# MTU calculator from MSS value

def mtuConnectionTypeGuesser(iMTU):
    iMTU = int(iMTU)
    if iMTU in (576,1500):
        return ("Ethernet or modem (PPPoE)")
    elif iMTU in (1452, 1454, 1492):
        return ("DSL")
    elif iMTU == 1456:
        return ("L2TP")
    elif iMTU in (1240, 1280, 1300, 1400, 1420, 1450):
        return ("Generic Tunnel Interface (VPN, IPSec, ...)")
    elif iMTU == 1476:
        return ("IPSec or GRE")
    elif iMTU == 1480:
        return ("IPIP or SIT")
    elif iMTU in (1490, 1460):
        return ("PPTP")
    elif iMTU in (1409, 1407, 1408, 1406, 1393, 1391, 1392, 1390, 1381, 1379, 1380, 1378, 1359, 1357, 1358, 1356, 1343, 1341, 1342, 1340, 1331, 1329, 1330, 1328, 1309, 1308, 1307, 1306, 1293, 1291, 1292, 1290, 1281, 1279, 1278, 1280):
        return ("OpenVPN")
    elif iMTU == 256:
        return ("AX.25 radio modem")
    elif iMTU == 552:
        return ("SLIP")
    elif iMTU == 1470:
        return ("Google")
    elif iMTU == 1496:
        return ("VLAN")
    elif iMTU == 1656:
        return ("Ericsson HIS modem")
    elif iMTU == 9000:
        return ("Jumbo Ethernet")
    elif iMTU in (3924, 16384, 16436):
        return ("Loopback interface")
    else:
        return ("Unknown")

# Calculate the initial TTL and Distance

def ttlClosest(iTTL):
    distance = 0
    initial_ttl = 0
    iTTL = int(iTTL)
    if (iTTL <= 32):
        distance = 32 - iTTL
    elif (iTTL <= 64):
        distance = 64 - iTTL
    elif (iTTL <= 128):
        distance = 128 - iTTL
    elif (iTTL <= 255):
        distance = 255 - iTTL
    initial_ttl = distance + iTTL
    return (distance, initial_ttl)

# Parse TCP Options & Quirks

def optionParser(iOptions, iSequence, iObj):
    option_length = len(iOptions)
    saw_eol = 0
    current_quirks = ''
    x = 0
    num_pads = 0
    payload_size = ''
    while(x < option_length - 1):
        if iOptions[x] == '0' and saw_eol == 0:
            print "EOL"
            x = x + 1
            saw_eol = 1
            iSequence.append("eol")
        elif iOptions[x] == '0' and saw_eol > 0:
            num_pads = num_pads + 1
            x = x + 1
        elif iOptions[x] == '1':
            print "NO-OP [1]"
            x = x + 1
            iSequence.append("nop")
        elif iOptions[x] == '2':
            print "MSS: ", str(int(iOptions[x+1:x+5],16)), "[MTU: ", str(int(iOptions[x+1:x+5],16)+40), "]"
            mtu = int(iOptions[x+1:x+5],16)+40
            print "Connection Type (MTU based): ", mtuConnectionTypeGuesser(mtu)
            iObj['mss'] = str(int(iOptions[x+1:x+5],16))
            x = x + 5
            iSequence.append("mss")
        elif iOptions[x] == '3':
            print "Window Scaling: ", str(int(iOptions[x+1:x+3],16))
            iObj['scale'] = str(int(iOptions[x+1:x+3],16))
            x = x + 3
            iSequence.append("ws")
        elif iOptions[x] == '4':
            print "Selective Acknowledgement permitted"
            x = x + 1
            iSequence.append("sok")
        elif iOptions[x] == '5':
            print "Selective ACK [BBBB,EEEE]"
            iSequence.append("sack")
            x = x + 1
        elif iOptions[x] == '!':
            print "TCP Option ", iOptions[x+1:x+3]
            x = x + 3
        elif iOptions[x] == '+':
            current_quirks = iOptions[x+2:]
            payload_size = iOptions[x+1]

            break
        elif iOptions[x] == '8':
            print "TTTT,EEEE [Timestamp, Echo]"
            iSequence.append("ts")
            x = x + 1
        else:
            print "TCP Option ", iOptions[x]
            x = x + 1
    if num_pads > 0:
        iSequence[-1] = iSequence[-1] + "+" + str(num_pads)
    print "--- TCP Quirks ---"

    quirks = {}
    quirks['A'] = "don't fragment bit set (ipv4)"
    quirks['B'] = "don't fragment bit set and id non-zero (ipv4)"
    quirks['C'] = "don't fragment bit set and id zero (ipv4)"
    quirks['D'] = "ecn capable in ip header (ipv4)"
    quirks['E'] = "flow-label non-zero (ipv6)"
    quirks['F'] = "reserved bits non-zero (tcp)"
    quirks['G'] = "sequence number for syn is zero (tcp)"
    quirks['H'] = "ack number non-zero but ack flag not set (tcp)"
    quirks['I'] = "ack number zero but ack flag set (tcp) (dropped by kernel for syn)"
    quirks['J'] = "urg pointer non-zero but urg flag not set (tcp)"
    quirks['K'] = "urg flag set (tcp) (dropped by kernel for syn)"
    quirks['L'] = "push flag set (tcp) (dropped by kernel for syn)"
    quirks['M'] = "timestamp option is zero (tcp)"
    quirks['N'] = "echo timestamp option is non-zero for syn (tcp)"
    quirks['O'] = "tcp options contain non-zero trailing bits (tcp)"
    quirks['P'] = "tcp option window scaling factor > 14 (tcp)"
    quirks['Q'] = "malformed tcp options (tcp)"

    short_quirks = {}
    short_quirks['A'] = "df"
    short_quirks['B'] = "df,id+"
    short_quirks['C'] = "id-"
    short_quirks['D'] = "ecn"
    short_quirks['E'] = "flow"
    short_quirks['F'] = "0+"
    short_quirks['G'] = "seq-"
    short_quirks['H'] = "ack+"
    short_quirks['I'] = "ack-"
    short_quirks['J'] = "uptr+"
    short_quirks['K'] = "urgf+"
    short_quirks['L'] = "pushf+"
    short_quirks['M'] = "ts1-"
    short_quirks['N'] = "ts2+"
    short_quirks['O'] = "opt+"
    short_quirks['P'] = "exws"
    short_quirks['Q'] = "bad"

    y = 0
    while (y < len(current_quirks)):
        print "Quirk: ", quirks[current_quirks[y]]
        pof_quirks.append(short_quirks[current_quirks[y]])
        y = y+1

def osGuesser(iPof):
    os_fp = {}
    os_fp['s:unix:Linux:3.11 and newer'] = ['*:64:0:*:mss*20,10:mss,sok,ts,nop,ws:df,id+:0','*:64:0:*:mss*20,7:mss,sok,ts,nop,ws:df,id+:0']
    os_fp['s:unix:Linux:3.1-3.10'] = ['*:64:0:*:mss*10,4:mss,sok,ts,nop,ws:df,id+:0','*:64:0:*:mss*10,5:mss,sok,ts,nop,ws:df,id+:0','*:64:0:*:mss*10,6:mss,sok,ts,nop,ws:df,id+:0','*:64:0:*:mss*10,7:mss,sok,ts,nop,ws:df,id+:0']
    os_fp['s:unix:Linux:2.6.x'] = ['*:64:0:*:mss*4,6:mss,sok,ts,nop,ws:df,id+:0','*:64:0:*:mss*4,7:mss,sok,ts,nop,ws:df,id+:0','*:64:0:*:mss*4,8:mss,sok,ts,nop,ws:df,id+:0']
    os_fp['s:unix:Linux:2.4.x'] = ['*:64:0:*:mss*4,0:mss,sok,ts,nop,ws:df,id+:0','*:64:0:*:mss*4,1:mss,sok,ts,nop,ws:df,id+:0','*:64:0:*:mss*4,2:mss,sok,ts,nop,ws:df,id+:0']
    os_fp['s:unix:Linux:2.2.x'] = ['*:64:0:*:mss*11,0:mss,sok,ts,nop,ws:df,id+:0','*:64:0:*:mss*20,0:mss,sok,ts,nop,ws:df,id+:0','*:64:0:*:mss*22,0:mss,sok,ts,nop,ws:df,id+:0']
    os_fp['s:unix:Linux:2.0'] = ['*:64:0:*:mss*12,0:mss::0','*:64:0:*:16384,0:mss::0']
    os_fp['s:unix:Linux:3.x (loopback)'] = ['*:64:0:16396:mss*2,4:mss,sok,ts,nop,ws:df,id+:0','*:64:0:16376:mss*2,4:mss,sok,ts,nop,ws:df,id+:0']
    os_fp['s:unix:Linux:2.6.x (loopback)'] = ['*:64:0:16396:mss*2,2:mss,sok,ts,nop,ws:df,id+:0','*:64:0:16376:mss*2,2:mss,sok,ts,nop,ws:df,id+:0']
    os_fp['s:unix:Linux:2.4.x (loopback)'] = ['*:64:0:16396:mss*2,0:mss,sok,ts,nop,ws:df,id+:0']
    os_fp['s:unix:Linux:2.2.x (loopback)'] = ['*:64:0:3884:mss*8,0:mss,sok,ts,nop,ws:df,id+:0']
    os_fp['s:unix:Linux:2.6.x (Google crawler)'] = ['4:64:0:1430:mss*4,6:mss,sok,ts,nop,ws::0']
    os_fp['s:unix:Linux:(Android)'] = ['*:64:0:*:mss*44,1:mss,sok,ts,nop,ws:df,id+:0','*:64:0:*:mss*44,3:mss,sok,ts,nop,ws:df,id+:0']
    os_fp['g:unix:Linux:3.x'] = ['*:64:0:*:mss*10,*:mss,sok,ts,nop,ws:df,id+:0']
    os_fp['g:unix:Linux:2.4.x-2.6.x'] = ['*:64:0:*:mss*4,*:mss,sok,ts,nop,ws:df,id+:0']
    os_fp['g:unix:Linux:2.2.x-3.x'] = ['*:64:0:*:*,*:mss,sok,ts,nop,ws:df,id+:0']
    os_fp['g:unix:Linux:2.2.x-3.x (no timestamps)'] = ['*:64:0:*:*,*:mss,nop,nop,sok,nop,ws:df,id+:0']
    os_fp['g:unix:Linux:2.2.x-3.x (barebone)'] = ['*:64:0:*:*,0:mss:df,id+:0']
    os_fp['s:win:Windows:XP'] = ['*:128:0:*:16384,0:mss,nop,nop,sok:df,id+:0','*:128:0:*:65535,0:mss,nop,nop,sok:df,id+:0','*:128:0:*:65535,0:mss,nop,ws,nop,nop,sok:df,id+:0','*:128:0:*:65535,1:mss,nop,ws,nop,nop,sok:df,id+:0','*:128:0:*:65535,2:mss,nop,ws,nop,nop,sok:df,id+:0']
    os_fp['s:win:Windows:7 or 8'] = ['*:128:0:*:8192,0:mss,nop,nop,sok:df,id+:0','*:128:0:*:8192,2:mss,nop,ws,nop,nop,sok:df,id+:0','*:128:0:*:8192,8:mss,nop,ws,nop,nop,sok:df,id+:0','*:128:0:*:8192,2:mss,nop,ws,sok,ts:df,id+:0']
    os_fp['s:win:Windows:7 (Websense crawler)'] = ['*:64:0:1380:mss*4,6:mss,nop,nop,ts,nop,ws:df,id+:0','*:64:0:1380:mss*4,7:mss,nop,nop,ts,nop,ws:df,id+:0']
    os_fp['g:win:Windows:NT kernel 5.x'] = ['*:128:0:*:16384,*:mss,nop,nop,sok:df,id+:0','*:128:0:*:65535,*:mss,nop,nop,sok:df,id+:0','*:128:0:*:16384,*:mss,nop,ws,nop,nop,sok:df,id+:0','*:128:0:*:65535,*:mss,nop,ws,nop,nop,sok:df,id+:0']
    os_fp['g:win:Windows:NT kernel 6.x'] = ['*:128:0:*:8192,*:mss,nop,nop,sok:df,id+:0','*:128:0:*:8192,*:mss,nop,ws,nop,nop,sok:df,id+:0']
    os_fp['g:win:Windows:NT kernel'] = ['*:128:0:*:*,*:mss,nop,nop,sok:df,id+:0','*:128:0:*:*,*:mss,nop,ws,nop,nop,sok:df,id+:0']
    os_fp['s:unix:Mac OS X:10.x'] = ['*:64:0:*:65535,1:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+:0','*:64:0:*:65535,3:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+:0']
    os_fp['s:unix:MacOS X:10.9 or newer (sometimes iPhone or iPad)'] = ['*:64:0:*:65535,4:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+:0']
    os_fp['s:unix:iOS:iPhone or iPad'] = ['*:64:0:*:65535,2:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+:0']
    os_fp['g:unix:Mac OS X:'] = ['*:64:0:*:65535,*:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+:0']
    os_fp['s:unix:FreeBSD:9.x or newer'] = ['*:64:0:*:65535,6:mss,nop,ws,sok,ts:df,id+:0']
    os_fp['s:unix:FreeBSD:8.x'] = ['*:64:0:*:65535,3:mss,nop,ws,sok,ts:df,id+:0']
    os_fp['g:unix:FreeBSD:'] = ['*:64:0:*:65535,*:mss,nop,ws,sok,ts:df,id+:0']
    os_fp['s:unix:OpenBSD:3.x'] = ['*:64:0:*:16384,0:mss,nop,nop,sok,nop,ws,nop,nop,ts:df,id+:0']
    os_fp['s:unix:OpenBSD:4.x-5.x'] = ['*:64:0:*:16384,3:mss,nop,nop,sok,nop,ws,nop,nop,ts:df,id+:0']
    os_fp['s:unix:Solaris:8'] = ['*:64:0:*:32850,1:nop,ws,nop,nop,ts,nop,nop,sok,mss:df,id+:0']
    os_fp['s:unix:Solaris:10'] = ['*:64:0:*:mss*34,0:mss,nop,ws,nop,nop,sok:df,id+:0']
    os_fp['s:unix:OpenVMS:8.x'] = ['4:128:0:1460:mtu*2,0:mss,nop,ws::0']
    os_fp['s:unix:OpenVMS:7.x'] = ['4:64:0:1460:61440,0:mss,nop,ws::0']
    os_fp['s:other:NeXTSTEP:'] = ['4:64:0:1024:mss*4,0:mss::0']
    os_fp['s:unix:Tru64:4.x'] = ['4:64:0:1460:32768,0:mss,nop,ws:df,id+:0']
    os_fp['s:!:NMap:SYN scan'] = ['*:64-:0:1460:1024,0:mss::0','*:64-:0:1460:2048,0:mss::0','*:64-:0:1460:3072,0:mss::0','*:64-:0:1460:4096,0:mss::0']
    os_fp['s:!:NMap:OS detection'] =['*:64-:0:265:512,0:mss,sok,ts:ack+:0','*:64-:0:0:4,10:sok,ts,ws,eol+0:ack+:0','*:64-:0:1460:1,10:ws,nop,mss,ts,sok:ack+:0','*:64-:0:536:16,10:mss,sok,ts,ws,eol+0:ack+:0','*:64-:0:640:4,5:ts,nop,nop,ws,nop,mss:ack+:0','*:64-:0:1400:63,0:mss,ws,sok,ts,eol+0:ack+:0','*:64-:0:265:31337,10:ws,nop,mss,ts,sok:ack+:0','*:64-:0:1460:3,10:ws,nop,mss,sok,nop,nop:ecn,uptr+:0']
    os_fp['s:unix:p0f:sendsyn utility'] = ['*:192:0:1331:1337,0:mss,nop,eol+18::0','*:192:0:1331:1337,0:mss,ts,nop,eol+8::0','*:192:0:1331:1337,5:mss,ws,nop,eol+15::0','*:192:0:1331:1337,0:mss,sok,nop,eol+16::0','*:192:0:1331:1337,5:mss,ws,ts,nop,eol+5::0','*:192:0:1331:1337,0:mss,sok,ts,nop,eol+6::0','*:192:0:1331:1337,5:mss,ws,sok,nop,eol+13::0','*:192:0:1331:1337,5:mss,ws,sok,ts,nop,eol+3::0']
    os_fp['s:other:Blackberry:'] = ['*:128:0:1452:65535,0:mss,nop,nop,sok,nop,nop,ts::0']
    os_fp['s:other:Nintendo:3DS'] = ['*:64:0:1360:32768,0:mss,nop,nop,sok:df,id+:0']
    os_fp['s:other:Nintendo:Wii'] = ['4:64:0:1460:32768,0:mss,nop,nop,sok:df,id+:0']
    os_fp['s:unix:BaiduSpider:'] = ['*:64:0:1460:mss*4,7:mss,sok,nop,nop,nop,nop,nop,nop,nop,nop,nop,nop,nop,ws:df,id+:0','*:64:0:1460:mss*4,2:mss,sok,nop,nop,nop,nop,nop,nop,nop,nop,nop,nop,nop,ws:df,id+:0']



    for os in os_fp.iterkeys():
        for fp in os_fp[os]:
            splitted_fingerprint = fp.split(':')
            splitted_current_pof = iPof.split(':')
            if not (splitted_fingerprint[0] == splitted_current_pof[0] or splitted_fingerprint[0] == '*'):
                continue
            if not (splitted_fingerprint[1] == splitted_current_pof[1] or splitted_fingerprint[1] == '*'):
                continue
            if not (splitted_fingerprint[2] == splitted_current_pof[2]):
                continue
            if not (splitted_fingerprint[3] == splitted_current_pof[3] or splitted_fingerprint[3] == '*'):
                continue
            splitted_iws_scale = splitted_fingerprint[4].split(',') # X,Y
            splitted_iws_scale_current = splitted_current_pof[4].split(',') # X,Y

            fiws = splitted_iws_scale[0]
            ciws = splitted_iws_scale_current[0]
            fscale = splitted_iws_scale[1]
            cscale = splitted_iws_scale_current[1]

            located_multiplier = fiws.find("*")
            if (located_multiplier == 0):
                pass
            elif (located_multiplier > 0):
                multi = 1
                multi = int(fiws[located_multiplier+1:])
                if not (int(splitted_current_pof[3]) * multi == ciws):
                    continue
            elif ciws != fiws:
                continue

            if not ((fscale == cscale) or fscale == '*'):
                continue

            if not (splitted_fingerprint[5] == splitted_current_pof[5]):
                continue
            if not (splitted_fingerprint[6] == splitted_current_pof[6]):
                continue

            if not (splitted_fingerprint[7] == splitted_current_pof[7]):
                continue

            print "OS Match: ", os
            print splitted_fingerprint
            print splitted_current_pof

## Main Section ##

if len(sys.argv) <> 2 or sys.argv[1].find('//@tcp/') <> 0:
    print "Usage: ./tcpfp.py //@tcp/XXXXXXXXXXXXX"
    exit()

fp = sys.argv[1]


# Remove the //@tcp/ prefix
fp_clean = fp[7:]

fp_obj = {}

fp_obj['format_version'] = fp_clean[0]
fp_obj['IP_protocol_ver'] = fp_clean[1]
fp_obj['IP_ttl'] = str(int(fp_clean[2:4],16))
fp_obj['IPv4_options_size'] = fp_clean[4]
fp_obj['TCP_initial_window_size'] = str(int(fp_clean[5:9],16))
fp_obj['Payload size'] = str(fp_clean[fp_clean.find('+')+1])
fp_obj['scale'] = str(0)

print "************************************************************************"
print "Ghost format: VPTTIWWWW[OOO...]+PQQQ"
print "Fingerprint: ", fp_clean
print "Format version: ", fp_obj['format_version']
print "IP protocol version: ", fp_obj['IP_protocol_ver']
(dis,init) = ttlClosest(fp_obj['IP_ttl'])
print "IP TTL: ", fp_obj['IP_ttl'], " (Distance: ", dis, " Initial TTL: ", init, ")"
print "IPv4 options size: ", fp_obj['IPv4_options_size']
print "TCP initial window size: ", fp_obj['TCP_initial_window_size']
print "--- TCP OPTIONS ---"
optionParser(fp_clean[9:], sequence, fp_obj)
print "************************************************************************"
pof_raw = fp_obj['IP_protocol_ver'] + ":" + str(init) + ":" + fp_obj['IPv4_options_size'] + ":" + fp_obj['mss'] + ":" + fp_obj['TCP_initial_window_size'] + "," + fp_obj['scale'] + ":"
pof_sig = "*:" + str(init) + ":" + fp_obj['IPv4_options_size'] + ":" + "*" + ":" + str(int(fp_obj['TCP_initial_window_size'])/int(fp_obj['mss']))+"*mss" + "," + fp_obj['scale'] + ":"
for item in sequence:
    pof_raw = pof_raw + (item + ",")
    pof_sig = pof_sig + (item + ",")

pof_raw = pof_raw[:-1]
pof_sig = pof_sig[:-1]

pof_raw = pof_raw + ":"
pof_sig = pof_sig + ":"

# Add quirks
for quirk in pof_quirks:
    pof_raw = pof_raw + (quirk + ",")
    pof_sig = pof_sig + (quirk + ",")

if len(pof_quirks) > 0:
    pof_raw = pof_raw[:-1]
    pof_sig = pof_sig[:-1]

pof_raw = pof_raw + ":" + fp_obj['Payload size'] # get the payload size
pof_sig = pof_sig + ":" + fp_obj['Payload size'] # get the payload size
print ">> P0f TCP Fingerprint: ", pof_raw
print "************************************************************************"
osGuesser(pof_raw)
print "************************************************************************"
