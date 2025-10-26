class Packet:
    """Represents a packet with essential attributes."""

    def __init__(self, source_address, destination_address, sequence_number,
                 is_ack=False, data=None):
        """Constructor for Packet
                Args:
                        source_address : Source IP address. [STR]
                        destination_address : Destination IP address. [STR]
                        sequence_number : Sequence number of the packet. [INT]
                        is_ack : Whether the packet is an acknowledgment packet. Defaults to False. [BOOL]
                        data : Data contained in the packet. Defaults to None. [STR]
                    """
        self.__source_address = source_address
        self.__destination_address = destination_address
        self.__sequence_number = sequence_number
        self.__is_ack = is_ack
        self.__data = data


    def __repr__(self):
        """String representation of the Packet object."""
        return "Packet(Source IP : {} , Dest IP : {} , #Seq : {} , Is ACK : {} , Data : {})".format(
            self.__source_address, self.__destination_address, self.__sequence_number, self.__is_ack, self.__data)


    def get_source_address(self):
        """Return the source address"""
        return self.__source_address

    def get_destination_address(self):
        """Return the destination"""
        return self.__destination_address

    def get_sequence_number(self):
        """Return the sequence number"""
        return self.__sequence_number

    def set_sequence_number(self, seq_num):
        """Set the sequence number of the packet."""
        self.__sequence_number = seq_num

    def get_is_ack(self):
        """Return if the packet is an acknowledgment"""
        return self.__is_ack

    def get_data(self):
        """Return the data contained in the packet"""
        return self.__data


class Communicator:
    """Base class for communicators."""

    def __init__(self, address):
        """Initialize the communicator
        address : The address of the communicator. [STR]
            current_seq_num : The current sequence number of the communicator. [INT]
        """
        self.address = address
        self.__current_seq_num = None

    def get_address(self):
        """Return the address of the communicator"""
        return self.address

    def get_current_sequence_number(self):
        """Return the current sequence number of the communicator"""
        return self.__current_seq_num

    def set_current_sequence_number(self, seq_num):
        """Set the current sequence number of the communicator."""
        self.__current_seq_num = seq_num

    def send_packet(self, packet):
        """Send a packet to the communicator"""
        seq_num = packet.get_sequence_number()
        print("Sender : Packet Seq Num : {}".format(seq_num))
        return packet

    def increment_current_seq_num(self):
        """Increment the current sequence"""
        if self.__current_seq_num is None:
            self.__current_seq_num = 0
        else:
            self.__current_seq_num += 1


class Sender(Communicator):
    """Send a packet to the communicator"""

    def __init__(self, address, num_letters_in_packet):
        """Initialize Sender with provided address and packet size."""
        super().__init__(address)
        self.__num_letters_in_packet = num_letters_in_packet

    def prepare_packets(self, message, destination_address):
        """Prepare packets for transmission based on message and destination address."""
        packets = []
        special_characters = "!#$%&'()*+,-./:;<>=?@[]\^_'{}|~" #Took from ascii table numbers = [33-47] , [58-64] , [91-96] , [123-126]
        if len(message) == 0:
            print("Not sending an empty strings !")
            quit()

        if all(c in special_characters for c in message):
            print("Message contains only special characters")
            quit()



        for i in range(0, len(message), self.__num_letters_in_packet):
            data = message[i:i + self.__num_letters_in_packet]
            packet = Packet(self.address, destination_address, i // self.__num_letters_in_packet, data=data)
            packets.append(packet)
        return packets

    def receive_ack(self, acknowledgment_packet):
        """Receive the acknowledgment"""
        return acknowledgment_packet.get_is_ack()


class Receiver(Communicator):
    """Receiver class"""

    def __init__(self, address):
        """Initialize the receiver"""
        super().__init__(address)
        self.packets_received = []

    def receive_packet(self, packet):
        """Receive a packet from the sender."""
        self.packets_received.append(packet)
        ack_packet = Packet(packet.get_destination_address(),
                            packet.get_source_address(),
                            packet.get_sequence_number(),
                            is_ack=True)
        print("Receiver: Received packet seq num:", packet.get_sequence_number())
        return ack_packet

    def get_message_by_received_packets(self):
        """Get the reconstructed message from received packets"""
        message = ''
        for packet in self.packets_received:
            message += packet.get_data()
        return message.strip()


if __name__ == '__main__':
    source_address = "192.168.1.1"
    destination_address = "192.168.2.2"
    message = "!@#$% ^&^*^&"
    num_letters_in_packet = 4

    sender = Sender(source_address, num_letters_in_packet)
    receiver = Receiver(destination_address)

    packets = sender.prepare_packets(message, receiver.get_address())

    # setting current packet
    start_interval_index = packets[0].get_sequence_number()
    # setting current packet in the sender and receiver
    sender.set_current_sequence_number(start_interval_index)
    receiver.set_current_sequence_number(start_interval_index)

    # setting the last packet
    last_packet_sequence_num = packets[-1].get_sequence_number()
    receiver_current_packet = receiver.get_current_sequence_number()

    while receiver_current_packet <= last_packet_sequence_num:
        current_index = sender.get_current_sequence_number()
        packet = packets[current_index]
        packet = sender.send_packet(packet)

        ack = receiver.receive_packet(packet)

        result = sender.receive_ack(ack)

        if result == True:
            sender.increment_current_seq_num()
            receiver.increment_current_seq_num()

        receiver_current_packet = receiver.get_current_sequence_number()

    full_message = receiver.get_message_by_received_packets()
    print(f"Receiver message: {full_message}")
