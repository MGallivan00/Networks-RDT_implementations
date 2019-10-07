import Network
import argparse
from time import sleep
import hashlib

## TODO: Add a bit for error detection, in the checksum field, in the send method
# TODO: Add nack and ack in the receive method.
# TODO: add binary sequence number

class Packet:
    ## the number of bytes used to store packet length
    seq_num_S_length = 10
    length_S_length = 10
    ## length of md5 checksum in hex
    checksum_length = 32

    def __init__(self, seq_num, msg_S, ack):
        self.seq_num = seq_num
        self.msg_S = msg_S
        self.ack = ack

    @classmethod # fix this. Error detection!
    def from_byte_S(self, byte_S):
        if not Packet.corrupt(byte_S):
            seq_num = int(byte_S[Packet.length_S_length : Packet.length_S_length+Packet.seq_num_S_length])
            msg_S = byte_S[Packet.length_S_length+Packet.seq_num_S_length+Packet.checksum_length :]
            return self(seq_num, msg_S, False)
        else:
            return self(None, None, True)

    def get_byte_S(self):
        # Changes the length of the sequence number by adding 0 to the left until its seq_num_S_length
        seq_num_S = str(self.seq_num).zfill(self.seq_num_S_length)
        #convert length to a byte field of length_S_length bytes
        length_S = str(self.length_S_length + len(seq_num_S) + self.checksum_length + len(self.msg_S)).zfill(self.length_S_length)
        #compute the checksum
        checksum = hashlib.md5((length_S+seq_num_S+self.msg_S).encode('utf-8'))
        checksum_S = checksum.hexdigest()
        #compile into a string
        return length_S + seq_num_S + checksum_S + self.msg_S # returns a string


    @staticmethod
    def corrupt(byte_S):
        #extract the fields
        length_S = byte_S[0:Packet.length_S_length]
        seq_num_S = byte_S[Packet.length_S_length : Packet.seq_num_S_length+Packet.seq_num_S_length]
        checksum_S = byte_S[Packet.seq_num_S_length+Packet.seq_num_S_length : Packet.seq_num_S_length+Packet.length_S_length+Packet.checksum_length]
        msg_S = byte_S[Packet.seq_num_S_length+Packet.seq_num_S_length+Packet.checksum_length :]

        #compute the checksum locally
        checksum = hashlib.md5(str(length_S+seq_num_S+msg_S).encode('utf-8'))
        computed_checksum_S = checksum.hexdigest()
        #and check if the same
        return checksum_S != computed_checksum_S


class RDT:
    ## latest sequence number used in a packet
    seq_num = 1
    ## buffer of bytes read from network
    byte_buffer = ''

    def __init__(self, role_S, server_S, port):
        self.network = Network.NetworkLayer(role_S, server_S, port)

    def disconnect(self):
        self.network.disconnect()

    def sendNACK(self):
        if(self.seq_num == 0):
            self.network.udt_send("10".zfill(16)) # sequence number 0 and NACK
        else:
            self.network.udt_send("11".zfill(16)) # sequence number 1 and NACK

    def sendACK(self):
        if(self.seq_num == 0):
            self.network.udt_send("00".zfill(16)) # sequence number 0 and ACK
        else:
            self.network.udt_send("01".zfill(16)) # sequence number 1 and ACK


    def rdt_1_0_send(self, msg_S):
        p = Packet(self.seq_num, msg_S, None)
        self.seq_num += 1
        self.network.udt_send(p.get_byte_S())



    def rdt_2_1_send(self, msg_S): # copied from rdt 1.0
        p = Packet(self.seq_num, msg_S, None)
        self.network.udt_send(p.get_byte_S())#send the packet

        byte_S=self.network.udt_receive()#receive the ack or nack

        print("ACK NACK : "+byte_S+ "\n\n")
        acknack = byte_S
        if self.seq_num == 0:#check the ack or nack
            while acknack != "00".zfill(16):
                print("corrupt: not 00. receive ACK/NACK")
                self.network.udt_send(p.get_byte_S())
                while byte_S != " ":
                    print("b:", byte_S + "5")
                    byte_S=self.network.udt_receive()
                acknack = byte_S
                print("Acknack: ", acknack)
            print("Received right ack\n")


        elif self.seq_num == 1:
            while acknack != "10".zfill(16):
                print("corrupt: not 10. receive ACK/NACK")
                self.network.udt_send(p.get_byte_S())
                print("byte_S: ", byte_S)
                while byte_S != " ":
                    print("b:", byte_S + "5")
                    byte_S=self.network.udt_receive()
                acknack = byte_S
                print("Acknack: ", acknack)
            print("Received right ack\n")

        else:
            print("error\n")

        #alternate sequence number
        if self.seq_num == 0 :
            self.seq_num =1
        elif self.seq_num == 1 :
            self.seq_num =0
        else:
            print("error\n")



    def rdt_2_1_receive(self):  # copied, will get back to later
        ret_S = None
        byte_S = self.network.udt_receive()
        self.byte_buffer += byte_S
        #keep extracting packets - if reordered, could get more than one
        while True:
            #check if we have received enough bytes
            if(len(self.byte_buffer) < Packet.length_S_length):
                return ret_S #not enough bytes to read packet length
            #extract length of packet
            length = int(self.byte_buffer[:Packet.length_S_length])
            if len(self.byte_buffer) < length:
                return ret_S #not enough bytes to read the whole packet
            #create packet from buffer content and add to return string

            p = Packet.from_byte_S(self.byte_buffer[0:length])

            while p.ack: # while packet is corrupt...
                self.sendNACK() # keep sending NACKs
                byte_S = self.network.udt_receive()
                self.byte_buffer += byte_S
                length = int(self.byte_buffer[:Packet.length_S_length])
                p = Packet.from_byte_S(self.byte_buffer[0:length])
                sleep(0.5)
                receive = None
                print("Hello")





            # if(p.ack):
            #     self.sendNACK()
            #     sleep(0.5)
            #     while(not p.ack)
            #     receive = None
            #     print("Hello")

            self.sendACK()  # we received the packet uncorrupted. We will send the ACK.
            sleep(0.5)


            ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S

            #remove the packet bytes from the buffer
            self.byte_buffer = self.byte_buffer[length:]
            #if this was the last packet, will return on the next iteration

    def rdt_1_0_receive(self):
        ret_S = None
        byte_S = self.network.udt_receive()
        self.byte_buffer += byte_S
        #keep extracting packets - if reordered, could get more than one
        while True:
            #check if we have received enough bytes
            if(len(self.byte_buffer) < Packet.length_S_length):
                return ret_S #not enough bytes to read packet length
            #extract length of packet
            length = int(self.byte_buffer[:Packet.length_S_length])
            if len(self.byte_buffer) < length:
                return ret_S #not enough bytes to read the whole packet
            #create packet from buffer content and add to return string
            p = Packet.from_byte_S(self.byte_buffer[0:length])

            ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
            #remove the packet bytes from the buffer
            self.byte_buffer = self.byte_buffer[length:]
            #if this was the last packet, will return on the next iteration




if __name__ == '__main__':
    parser =  argparse.ArgumentParser(description='RDT implementation.')
    parser.add_argument('role', help='Role is either client or server.', choices=['client', 'server'])
    parser.add_argument('server', help='Server.')
    parser.add_argument('port', help='Port.', type=int)
    args = parser.parse_args()

    rdt = RDT(args.role, args.server, args.port)
    if args.role == 'client':
        rdt.rdt_1_0_send('MSG_FROM_CLIENT')
        sleep(2)
        print(rdt.rdt_1_0_receive())
        rdt.disconnect()


    else:
        sleep(1)
        print(rdt.rdt_1_0_receive())
        rdt.rdt_1_0_send('MSG_FROM_SERVER')
        rdt.disconnect()
