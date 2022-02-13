"""
Created on Sat Feb 05 14:51:17 2022
 @author: Maxens Destine
"""
import argparse
import time
import sys
from random import randint
from socket import *


def parse_arguments():

    # Instantiate the parser

    parser = argparse.ArgumentParser(description="Optional app description")

    parser.add_argument("-t", "--timeout", type=int, default=5, help="Timeout: How long to wait, in seconds, \
        before retransmitting an unanswered query. Default value: 5")

    parser.add_argument("-r", "--maxrepeat", type=int, default=3, help="Max retries: The maximum number of \
        times to retransmit an unanswered query before giving up. Default value: 3")

    parser.add_argument("-p", "--port", type=int, default=53, help="Port: The UDP port number of the DNS \
        server. Default value: 53")

    group = parser.add_mutually_exclusive_group()

    group.add_argument("-mx", action="store_true", help="Indicate whether to send a MX \
        (mail server) or NS (name server) query. At most one of these can be given, \
            and if neither is given then the client should send a type A \
            (IP address) query")

    group.add_argument("-ns", action="store_true", help="Indicate whether to send a MX \
        (mail server) or NS (name server) query. At most one of these can be given, \
        and if neither is given then the client should send a type A \
            (IP address) query")

    parser.add_argument("server", help="Server: the IPv4 address of the DNS server, \
        in a.b.c.d. format")

    parser.add_argument("name", help="Name: The domain name to query for")

    args = parser.parse_args()

    global reqType
    global destDNSServerIP
    global destDomainName
    global timeoutAfter
    global nbRetries
    global destPortVal


    timeoutAfter = args.timeout
    nbRetries = args.maxrepeat
    destPortVal = args.port
    destDomainName = args.name
    destDNSServerIP = args.server

    if args.ns:
        reqType = "NS"
    elif args.mx:
        reqType="MX"
    else:
        reqType="A"


def get_qname(name: str):
    response = []
    for label in name.split('.'):
        if len(label) > 63:
            raise RuntimeError("The domain name contains a label"\
                "\n(" + label + ")\nthat is larger than 63 characters")
        
        size = format(len(label), '08b')
        response.append(size)
        my_res = ''.join(format(ord(i), '08b') for i in label)
        response.append(my_res)
    response.append(format(0x0000, '08b'))
    return ''.join(response)


def build_question():
    global sizeOfQuestion
    queryTypeA = format(0x0001, '016b')
    queryTypeNS = format(0x0002, '016b')
    queryTypeMX = format(0x000f, '016b')
    
    queryDictionary = {
        'A':queryTypeA,
        'NS':queryTypeNS,
        'MX':queryTypeMX
    }

    queryType = queryDictionary[reqType]
    queryClass = format(0x0001, '016b')
    qname = get_qname(destDomainName)
    size = (len(qname) + 7) // 8

    myBytes = []
    myBytes += int(qname, 2).to_bytes(size, byteorder='big')
    myBytes += int(queryType, 2).to_bytes(2, byteorder='big')
    myBytes += int(queryClass, 2).to_bytes(2, byteorder='big')
    sizeOfQuestion = len(myBytes)
    return myBytes


def build_header():
    randomId = randint(1, 32767)
    transactionId = format(randomId, '016b')
    qr = '0'
    opcode = '0000'
    aa = '0'
    tc = '0'
    rd = '1'
    ra = '0'
    z = '000'
    rcode = '0000'
    flags = ''.join([qr, opcode, aa, tc, rd, ra, z, rcode])
    qdCount = format(0x0001, '016b')
    anCount = format(0x0000, '016b')
    nsCount = format(0x0000, '016b')
    arCount = format(0x0000, '016b')

    myBytes = []
    myBytes += int(transactionId, 2).to_bytes(2, byteorder='big')
    myBytes += int(flags, 2).to_bytes(2, byteorder='big')
    myBytes += int(qdCount, 2).to_bytes(2, byteorder='big')
    myBytes += int(anCount, 2).to_bytes(2, byteorder='big')
    myBytes += int(nsCount, 2).to_bytes(2, byteorder='big')
    myBytes += int(arCount, 2).to_bytes(2, byteorder='big')
    return myBytes


def build_query():
    query = build_header() + build_question()
    return query
    
def interpret_response():
    id = sent_query[:2]
    receivedId = received_response[:2]
    if id != receivedId:
        print("Error    Unexpected response. The response"\
            " transaction id does not match the query's.")
    
    flags = int.from_bytes(received_response[2:4], byteorder='big', signed=False)
    flagsBin = format(flags, '016b')
    if flagsBin[0] != '1':
        print("Error    Unexpected response. The response's"\
            " QR bit is '0' (expected '1').")
    if flagsBin[5] == '0':
        auth = False
    else: 
        auth = True

    qdCount = int.from_bytes(received_response[4:6], byteorder='big', signed=False)

    if qdCount > 1:
        print("Error    Unexpected response. The response's"\
            " QDCOUNT indicates more than one question (expected 1).")

    anCount = int.from_bytes(received_response[6:8], byteorder='big', signed=False)
    if anCount != 0:
        print("***Answer Section (" + str(anCount) + " record(s))***")

    arCount = int.from_bytes(received_response[10:12], byteorder='big', signed=False)
    if arCount != 0:
        print("***Additional Section (" + arCount + " record(s))***")
    
    if sent_query[12:12 + sizeOfQuestion] != received_response[12:12 + sizeOfQuestion]:
        print('Error    Unexpected response. The query sent is not the same as the query received. The program will proceed but packet the may have been corrupted.')

    if anCount == 0 and arCount == 0:
        print('NOTFOUND')
    else:
        print_ans_records(auth)

def get_name(offset: int):
    words = []
    toFind = 0
    curWordIndex = -1
    nbLetters = 0
    i = offset
    size = len(received_response)

    while i < size :
        myByte = received_response[i]
        if myByte == 0:
            break
        if toFind == 0:
            if i + 1 < size:
                line = int.from_bytes(received_response[i: i + 2], byteorder='big', signed=False)
                lineBin = format(line, '016b')
                if lineBin[:2] == '11':
                    break
            #print("making new word")
            toFind = myByte
            words += ['']
            curWordIndex += 1
        else:
            #print("adding letter")
            words[curWordIndex] += chr(myByte)
            toFind -= 1
            nbLetters += 1 

        i += 1

    #print("get name output" + '.'.join(words) + " length of " + str(len(words) + nbLetters))
    return (len(words) + nbLetters, '.'.join(words))


def extract_name(fromIndex: int):
    nameLength = 0
    name = ''
    nameByteList = received_response[fromIndex:]
    size = len(nameByteList)
    i = 0
    while i < size:
        myByte = nameByteList[i]
        if myByte == 0:
            break
        
        if i + 1 < size:
            line = int.from_bytes(nameByteList[i: i + 2], byteorder='big', signed=False)
            lineBin = format(line, '016b')
            if lineBin[:2] == '11':
                name += get_name(int(lineBin[2:], 2))[1]
                name += '.'
                nameLength += 2
                break
            else:
                my_tuple = get_name(fromIndex + i)
                name += my_tuple[1]
                name += '.'
                i += my_tuple[0]
                nameLength += my_tuple[0]
        else:
            my_tuple = get_name(fromIndex + i)
            name += my_tuple[1]
            name += '.'
            i += my_tuple[0]
            nameLength += my_tuple[0]

    if name[len(name) - 1] == '.':
        name = name[:len(name) - 1]

    return (nameLength, name)



def print_ans_records(auth: bool):
    domainName = ''
    size = len(received_response)
    i = 12 + sizeOfQuestion
    while i < size:
        nameLength, domainName = extract_name(i)
        index = i + nameLength
        my_type = received_response[index: index + 2]
        my_class = received_response[index + 2: index + 4]
        my_ttl = received_response[index + 4: index + 8]
        my_rdLength = received_response[index + 8: index + 10]
        cv_my_rdLength = int.from_bytes(my_rdLength, byteorder='big', signed=False)

        print_record(domainName, int.from_bytes(my_type, byteorder='big', signed=False), int.from_bytes(my_class, byteorder='big', signed=False), int.from_bytes(my_ttl, byteorder='big', signed=False), cv_my_rdLength, index + 10, auth)

        i += nameLength + 10 + cv_my_rdLength


def print_record(domainName: str, my_type: int, my_class: int, my_ttl: int, my_rdLength: int, index: int, auth: bool):
    output = ''
    authority = 'auth' if auth else 'nonauth'
    if my_type == 1:
        output = get_output_type_a_record(index)
    elif my_type == 2:
        output = get_output_type_ns_record(index)
    elif my_type == 5:
        output = get_output_type_cname_record(index)
    elif my_type == 15:
        output = get_output_type_mx_record(index)
    
    if output != '':
        print(output + '    ' + str(my_ttl) + '    ' + authority)


def extract_ip_add(offset: int):
    if len(received_response) < offset + 4:
        print("Error    Unexpected response. The response indicates a type A response, but the ip address format is invalid (less than 4 octets).")
        return '*unknown ip address*'
    else:
        octets = received_response[offset: offset + 4]
        output = [str(my_num) for my_num in octets]
        return '.'.join(output)


def get_output_type_a_record(index: int):
    ipAdd = extract_ip_add(index)
    return 'IP   ' + ipAdd

def get_output_type_ns_record(index: int):
    return 'NS    ' + extract_name(index)[1]

def get_output_type_mx_record(index: int):
    pref = received_response[index: index + 2]
    prefValue = int.from_bytes(pref, byteorder='big', signed=False)
    domainName = extract_name(index + 2)[1]
    return 'MX    ' + domainName + '    ' + str(prefValue) 

def get_output_type_cname_record(index: int):
    return 'CNAME   ' + extract_name(index)[1]


def send_request():
    global sent_query
    global received_response
    clientSocket = socket(AF_INET, SOCK_DGRAM)
    #clientSocket.bind(destDNSServerIP)
    listOfBytes = build_query()
    #print(listOfBytes)
    sent_query = listOfBytes
    #print(len(listOfBytes))
    byteArrayObj = bytearray(listOfBytes)
    print("DNS Client sending request for ")
    print(destDomainName + " Server: " + destDNSServerIP)
    print("Request type: " + reqType)
    start = time.time()
    #destDNSServerIP
    clientSocket.sendto(byteArrayObj, (destDNSServerIP, destPortVal))
    counter = start
    my_nb_retries = 0

    while 1:
        end = time.time()
        try:
            response, serverAddress = clientSocket.recvfrom(2048)
            break
        except:
            pass
        
        diff = end - counter

        if int(diff // 60) > 0 or int(diff % 60) > timeoutAfter:
            if my_nb_retries < nbRetries:
                clientSocket.sendto(byteArrayObj, (destDNSServerIP, destPortVal))
                counter = time.time()
                my_nb_retries += 1
            else:
                my_nb_retries = -1
                break


    if my_nb_retries == -1:
        print('Error    Maximum number of retries reached. The program will now exit.')
        sys.exit(1)

    received_response = list(response)
    print('Response received after ' + sci_notation(end - start, 2)  + ' seconds ('+ str(my_nb_retries) +' retries)')
    interpret_response()

# @author 'Will' stackoverflow user
# obtained from https://stackoverflow.com/questions/29260893/convert-to-scientific-notation-in-python-a-%C3%97-10b
def sci_notation(number, sig_fig=2):
    ret_string = "{0:.{1:d}e}".format(number, sig_fig)
    a, b = ret_string.split("e")
    # remove leading "+" and strip leading zeros
    b = int(b)
    return a + " * 10^" + str(b)


reqType = ""
destDNSServerIP = ""
destDomainName = ""
timeoutAfter = 5
nbRetries = 3
destPortVal = 53
sent_query = []
received_response = []
sizeOfQuestion = 0

parse_arguments()
send_request()





