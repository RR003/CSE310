import dpkt

if __name__ == '__main__':
    pcap_file = input("Please give filename: ") #gets file name
    f = open(pcap_file, 'rb')
    pcap = dpkt.pcap.Reader(f)

    arpRequestDict = {}
    arpResponse = []
    arpRequest = []

    for ts, buf in pcap:
        ## check if it is ARP packet
        opcode = buf[12:14].hex()
        if opcode != "0806":
            continue

        opcode = buf[20:22].hex()

        if opcode == "0001":
            ## check if its rly a request
            address = buf[0:6].hex()
            if address != "ffffffffffff":
                requestIP1 = buf[28:32].hex()
                requestIP2 = buf[38:42].hex()
                arpRequestDict[(requestIP1, requestIP2)] = buf
        else:
            ## check if its rly a response
            opcode = buf[20:22].hex()
            if opcode != "0002":
                continue

            responseIP1 = buf[28:32].hex()
            responseIP2 = buf[38:42].hex()
            if (responseIP2, responseIP1) in arpRequestDict:
                arpResponse.append(buf)
                arpRequest.append(arpRequestDict[(responseIP2, responseIP1)])
                break

    req = arpRequest[0]
    reply = arpResponse[0]

    print("ARP Request:")
    print("  Hardware Type: {}".format(req[14:16].hex()))
    print("  Hardware Size: {}".format(req[18:19].hex()))
    print("  Protocol Type: {}".format(req[16:18].hex()))
    print("  Protocol Size: {}".format(req[19:20].hex()))
    print("  Opcode: request {}".format(req[20:22].hex()))
    print("  Sender MAC address: {}:{}:{}:{}:{}:{}".format(req[22:23].hex(), req[23:24].hex(), req[24:25].hex(),
                                                           req[25:26].hex(), req[26:27].hex(), req[27:28].hex()))

    print("  Sender IP address: {}.{}.{}.{}".format(int(req[28:29].hex(), 16),
                                                    int(req[29:30].hex(), 16),
                                                    int(req[30:31].hex(), 16),
                                                    int(req[31:32].hex(), 16)))
    print("  Target MAC address: {}:{}:{}:{}:{}:{}".format(req[32:33].hex(), req[33:34].hex(), req[34:35].hex(),
                                                           req[35:36].hex(), req[36:37].hex(), req[37:38].hex()))
    ip1 = req[38:39].hex()
    ip2 = req[39:40].hex()
    ip3 = req[40:41].hex()
    ip4 = req[41:42].hex()
    print("  Target IP address: {}.{}.{}.{}".format(int(ip1, 16), int(ip2, 16), int(ip3, 16), int(ip4, 16)))


    print("ARP Reply:")
    print("  Hardware Type: {}".format(reply[14:16].hex()))
    print("  Hardware Size: {}".format(reply[18:19].hex()))
    print("  Protocol Type: {}".format(reply[16:18].hex()))
    print("  Protocol Size: {}".format(reply[19:20].hex()))
    print("  Opcode: reply {}".format(reply[20:22].hex()))
    print("  Sender MAC address: {}:{}:{}:{}:{}:{}".format(reply[22:23].hex(), reply[23:24].hex(), reply[24:25].hex(),
                                                           reply[25:26].hex(), reply[26:27].hex(), reply[27:28].hex()))

    print("  Sender IP address: {}.{}.{}.{}".format(int(reply[28:29].hex(), 16),
                                                    int(reply[29:30].hex(), 16),
                                                    int(reply[30:31].hex(), 16),
                                                    int(reply[31:32].hex(), 16)))
    print("  Target MAC address: {}:{}:{}:{}:{}:{}".format(reply[32:33].hex(), reply[33:34].hex(), reply[34:35].hex(),
                                                           reply[35:36].hex(), reply[36:37].hex(), reply[37:38].hex()))

    print("  Target IP address: {}.{}.{}.{}".format(int(reply[38:39].hex(), 16),
                                                    int(reply[39:40].hex(), 16),
                                                    int(reply[40:41].hex(), 16),
                                                    int(reply[41:42].hex(), 16)))