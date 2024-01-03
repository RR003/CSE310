import dpkt
import socket

def analysis_pcap_tcp():


    file_input = input("Enter pcap file: ")
    f = open(file_input, "rb")

    ## hard coding the sender and receiver ip addresses
    Sender_IP = "130.245.145.12"
    Receiver_IP = "128.208.2.198"

    pcap = dpkt.pcap.Reader(f)
    sender_to_receiver = {} ## dict to store information related to part1
    partb_information = {} ## dict to store part 2 information
    packet_information = {} ## dict to store packet information so that we can use later on

    ## part 1
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data

        ## if its not tcp packet, dont look
        if eth.type != dpkt.ethernet.ETH_TYPE_IP or ip.p != dpkt.ip.IP_PROTO_TCP:
            continue

        ## getting the source and dst ip and ports
        src_ip = socket.inet_ntoa(ip.src)
        dst_ip = socket.inet_ntoa(ip.dst)
        src_port = tcp.sport
        dst_port = tcp.dport


        if tcp.flags & dpkt.tcp.TH_SYN: ## check if the packet is a syn or fin ##
            if src_ip == Sender_IP and dst_ip == Receiver_IP:
                if (src_port, dst_port) not in sender_to_receiver:
                    ## initalize in proper dicts
                    sender_to_receiver[(src_port, dst_port)] = [ts, None, [], [],[], [] ,[], 0, None, None]
                    partb_information[(src_port, dst_port)] = [0,0,1, None, None, None, None, [], 0]
                    packet_information[(src_port, dst_port)] = {}
        elif tcp.flags & dpkt.tcp.TH_FIN: ## if the flow is done, then finalize the timings in maps
            if src_ip == Sender_IP and dst_ip == Receiver_IP:
                if (src_port, dst_port) in sender_to_receiver:
                    sender_to_receiver[(src_port, dst_port)][1] = ts
        else: ## if it is anything else
            if (src_port, dst_port) in sender_to_receiver: ## if it is sender -> receiver
                connection = sender_to_receiver[(src_port, dst_port)]
                connection[6].append((buf, ts, tcp, ip))
                ## getting transaction information
                if connection[2] == []:
                    temp = [tcp.seq, tcp.ack, tcp.win]
                    connection[2] = temp
                elif connection[4] == []:
                    if tcp.seq != connection[2][0]:
                        temp = [tcp.seq, tcp.ack, tcp.win]
                        connection[4] = temp


                connection2 = partb_information[(src_port, dst_port)]
                connection2[0] += 1

                if connection2[6] == None:
                    connection2[6] = ts


            if (dst_port, src_port) in sender_to_receiver: ## if it is receiver -> sender
                connection = sender_to_receiver[(dst_port, src_port)]
                connection[6].append((buf, ts, tcp, ip))
                ## getting transaction information
                if connection[3] == []:
                    if connection[2] != []:
                        if connection[2][1] == tcp.seq:
                            temp = [tcp.seq, tcp.ack, tcp.win]
                            connection[3] = temp
                elif connection[5] == []:
                    if connection[4] != []:
                        if connection[4][1] == tcp.seq:
                            temp = [tcp.seq, tcp.ack, tcp.win]
                            connection[5] = temp

                connection2 = partb_information[(dst_port, src_port)]
                connection2[1] += 1

                ## filling in the rtt windows
                if connection2[1] == connection2[2]:
                    if connection2[3] == None:
                        connection2[3] = connection2[0]
                    elif connection2[4] == None:
                        connection2[4] = connection2[0]
                    elif connection2[5] == None:
                        connection2[5] = connection2[0]

                    connection2[2] = connection2[0] - 1
                    connection2[0] = 0
                    connection2[1] = 0

                    connection2[7].append(ts - connection2[6])
                    connection2[6] = None

        ## calculating the total amount of bytes
        if Sender_IP == socket.inet_ntoa(ip.src):
            connection = sender_to_receiver[(src_port, dst_port)]
            if connection[8] is None:
                connection[8] = ts
            ## bytes = len(tcp)

            if tcp.flags & dpkt.tcp.TH_ACK: ## anything but Fin, make it final time
                connection[9] = ts
                connection[7] += tcp.__len__()
        else:
            connection = sender_to_receiver[(dst_port, src_port)]
            if connection[8] is None:
                connection[8] = ts
            if tcp.flags & dpkt.tcp.TH_ACK:
                connection[9] = ts
                connection[7] += tcp.__len__()

    avg_rtt = {} ## finding the rtt for each flow
    triple_ack = {} ## finding number of triple acks
    total_transmissions = {} ## finding total number of transmissions
    cwnd = {}

    ## partb contains all the rtts, we put the main one inside avg_Rtt dict
    for key in partb_information:
        value = partb_information[key][7]
        ## value.sort()
        avg_rtt[key] = value[0]

    ## all calculations for part B stuff
    for key in sender_to_receiver:
        ## intializing stuff, key is the (src_port, dst_port)
        values = sender_to_receiver[key][6] ## contains all the packets for the particular flow
        triple_ack[key] = [None, 0, [], 0]
        total_transmissions[key] = [{}, 0]
        cwnd[key] = [None, 0, 0, 0, 1]

        for buf,ts, tcp, ip in values:

            if eth.type != dpkt.ethernet.ETH_TYPE_IP or ip.p != dpkt.ip.IP_PROTO_TCP:
                continue

            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)
            src_port = tcp.sport
            dst_port = tcp.dport


            ## transmission stuff
            if src_ip == Sender_IP: ## if sender -> receiver
                map = packet_information[(src_port, dst_port)]

                if tcp.seq not in map: ## initilzie the seq number into map
                    map[tcp.seq] = ts

                ack = triple_ack[(src_port, dst_port)] ## getting recent ack
                if tcp.seq in ack[2]:
                    ack[3] += 1 ## increment recent ack if it is equal to previous

                transmission = total_transmissions[(src_port, dst_port)]
                if tcp.seq in transmission[0] and transmission[0][tcp.seq] == 0: ## if its a transmission
                    transmission[0][tcp.seq] += 1
                    transmission[1] += 1 ## increment
                elif tcp.seq not in transmission[0]:
                    transmission[0][tcp.seq] = 0 ## include seq number in the set

                cw = cwnd[(src_port, dst_port)] ## congestion window initialization
                if cw[0] == None:
                    cw[0] = ts ## initialize first entry

                if cw[4] < 4: ## if less than 3 entries
                    if cw[0] + avg_rtt[(src_port, dst_port)] < ts: ## checking if its not timeout
                        cw[0] = ts
                        cw[4] += 1
                    else: ## if it is then increment
                        cw[cw[4]] += 1
            elif src_ip == Receiver_IP: ## if its receiver to sender
                map = packet_information[(dst_port, src_port)]
                if tcp.ack in map:
                    if ts - map[tcp.ack] > avg_rtt[(dst_port, src_port)] * 2:
                        connection2 = partb_information[(dst_port, src_port)]
                        connection2[8] += 1
                    map.pop(tcp.ack)

                ack = triple_ack[(dst_port, src_port)] ## triple ack information
                if ack[0] == None:
                    ack[0] = tcp.ack ## initialize

                if ack[0] == tcp.ack:
                    ack[1] += 1 ## increment count if equal
                else: ## if not equal, set to defualt
                    ack[0] = tcp.ack
                    ack[1] = 1

                if ack[1] == 3:## if it is equal, then append this to the "special array"
                    ack[2].append(tcp.ack)



    iteration = 1

    print(len(sender_to_receiver), "total network flows")
    print("---------------------------------------------------")
    for key, value in sender_to_receiver.items():
        ## if value[2] == [] or value[3] == [] and value[4] == [] and value[5] == []:
            ## continue
        print("TCP Flow #{0}".format(iteration))
        print('  SrcIP: {0}, DstIP:{1}, SrcPort:{2}, DstPort:{3}'.format(Sender_IP, Receiver_IP, key[0], key[1]))
        ## print('  Start time: {0}'.format(value[0]))
        ## print('  End time: {0}'.format(value[1]))

        print("  Transaction 1")
        print("    Sender -> Receiver     Sequence_Number:{0}  ACK:{1}  Receive_Window_Size:{2}".format
              (value[2][0], value[2][1], value[2][2]))
        print("    Receiver -> Sender     Sequence_Number:{0}  ACK:{1}  Receive_Window_Size:{2}".format
              (value[3][0], value[3][1], value[3][2]))

        print("  Transaction 2")
        print("    Sender -> Receiver     Sequence_Number:{0}  ACK:{1}  Receive_Window_Size:{2}".format
              (value[4][0], value[4][1], value[4][2]))
        print("    Receiver -> Sender     Sequence_Number:{0}  ACK:{1}  Receive_Window_Size:{2}".format
              (value[5][0], value[5][1], value[5][2]))

        ## print(value[7], value[9], value[8])

        ## print("total bytes={0}".format(value[7]))
        ## print("time = {0}".format(value[9] - value[8]))

        throughput = value[7] / (value[9] - value[8])
        print("  Throughput = {0} bytes/second".format(throughput))

        partb = partb_information[key]
        cw = cwnd[key]


        print("  Congestion Window Sizes: [{0},{1},{2}]".format(cw[1], cw[2], cw[3]))

        avg_timeout = partb[7]
        avg_timeout.sort()

        ## print("rtt = {0}".format(avg_timeout[round(len(avg_timeout) / 2)]))
        print("  Total Transmissions ... {0}".format(total_transmissions[key][1]))
        print("    due to Triple Acks = {0}".format(triple_ack[key][3]))
        print("    due to Timeout = {0}".format(partb[8]))
        print("    special = {0}".format(total_transmissions[key][1] - (partb[8]  + triple_ack[key][3])))


        print("---------------------------------------------------")

        iteration += 1

analysis_pcap_tcp()