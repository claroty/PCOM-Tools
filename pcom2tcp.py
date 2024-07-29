import serial
import struct
import time
import struct
import socket
import binascii
import sys

# User configable - change to your setup
COM_PORT = "COM1"
COM_RATE = 115200 # Old series - 57600
PCOM_PORT = 20256


# Consts
BINARY_PREFIX = b"/_"
ASCII_REQUEST = b"/0"
ASCII_RESPONSE = b"/A"
ASCII_TERMINATE = ord("\r")
BINARY_TERMINATE = b"\\"


# This function reads PCOM message (Binary/ASCII) and returns the
# message, or 0 if encountered an error
def read_until(reader):
    
    # Read magic
    magic = reader.read(size=2)
    
    # If no magic - return error
    if not magic:
        return 0
    
    # Match magic to correct packet type
    if magic == BINARY_PREFIX:
        rest_of_header = reader.read(size=22)
        if len(rest_of_header) != 22:
            return 0

        header = magic + rest_of_header
        packet_length = struct.unpack("<H", header[20:22])[0]
        packet_data = reader.read(size=packet_length+3)
        return header + packet_data
    elif magic in (ASCII_REQUEST, ASCII_RESPONSE):
        data = magic

        # Read until we encounter ASCII_TERMINATE (\)
        while True:
            data += reader.read(size=1)
            if data[-1] == ASCII_TERMINATE:
                return data
    else:
        return 0 # Error - got no magic
def main():

    # Open serial port
    forwarder = serial.Serial(COM_PORT, COM_RATE)
    forwarder.timeout = 0.5

    # Open socket
    s = socket.socket(2,1)
    s.bind(("0.0.0.0", PCOM_PORT))
    s.listen()
    conn, addr = s.accept()

    # While true - forward messages
    while True:
        data = conn.recv(1024)

        # Reset connection if closed
        if not data:
            conn, addr = s.accept()
            continue

        # Extract fileds from PCOM/TCP layer, to insert to response
        com_data = data[6:]
        transaction_id = data[:2]
        protocol_type = data[2:3]
        
        print(f"TCP-->PCOM: {data}") 
        forwarder.write(com_data)
        pcom_response = read_until(forwarder)

        # If did not get data - try retransmittion
        if not pcom_response:
            continue

        tcp_response = transaction_id
        tcp_response += protocol_type
        tcp_response += b"\x00" 
        tcp_response += struct.pack("<H", len(pcom_response) + 6 ) 
        tcp_response += pcom_response

        print(f"PCOM-->TCP: {tcp_response}")
        conn.send(tcp_response)


if __name__ == "__main__":
    main()        