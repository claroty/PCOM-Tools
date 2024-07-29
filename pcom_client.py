import time
import zlib
import socket
import re
import binascii
import struct
import sys
import datetime
import random
from io import BytesIO

# Helper functions
def tx(d):
    return binascii.hexlify(d).decode()

def up_I(r):
    return struct.unpack("<I", r.read(4))[0]

def dex(d):
    return binascii.unhexlify(d)

def print_body_info(key, info):
    if info:
        info_data = info
        try:
            if type(info_data) == bytes:
                info_data = info_data.decode("windows-1252")
        except Exception as e:
            info_data = info
        print(f"\t\t\t[-] {key}: {info_data}")
    else:
        print(f"\t\t\t[-] {key}")


RESOURCE_ID_PROJECT_ZIP = 6
PASSWORD_DEFAULT = "*"*8


class PCOM_CLIENT:

    MODELS = { 'PRBT': 'FACTORY BOOT', '13PRBT': 'V130 FACTORY BOOT', '35PRBT': 'V350 FACTORY BOOT', '43PRBT': 'V430 FACTORY BOOT', '10PRBT': 'V1040/V1210 FACTORY BOOT', 'PC15': 'EXF-RC15 FACTORY BOOT', 'SM35PB': 'SM35-J FACTORY BOOT', 'SM43PB': 'SM43-J FACTORY BOOT', 'SM70PB': 'SM70-J FACTORY BOOT', 'SM7OPB': 'SM70-OEM FACTORY BOOT', '70PR': 'V700-T20BJ FACTORY BOOT', 'ADF1': 'ADP-PB1 FACTORY BOOT', 'BOOT': 'BOOT', 'CLBT': 'CLR BOOT', '13BOOT': 'V130 BOOT', '35BOOT': 'V350 BOOT', 'SM35BT': 'SM35-J BOOT', 'SM43BT': 'SM43-J BOOT', 'SM70BT': 'SM70-J BOOT', 'SM7OBT': 'SM70-OEM BOOT', 'SMBT': 'SM35 BOOT', '10BOOT': 'V1040 BOOT', '12BOOT': 'V1210 BOOT', '43BOOT': 'V430 BOOT', '70BOOT': 'V700-T20BJ BOOT', 'ADB1': 'ADP-PB1 BOOT', 'BM90': 'BOOT', 'BNX1': 'BOOT', 'BNR1': 'BOOT', 'BRC1': 'EX-RC1 BOOT', 'BC15': 'EXF-RC15 BOOT', 'B1': 'M90-19-B1', 'B1A': 'M90-19-B1A', 'R1': 'M90-R1', 'R1C': 'M90-R1-CAN', 'R2C': 'M90-R2-CAN', 'T': 'M90-T', 'T1': 'M90-T1', 'T1C': 'M90-T1-CAN', 'TA2C': 'M90-TA2-CAN', 'TA3C': 'M90-TA3-CAN', '1TC2': 'M91-19-TC2', '1UN2': 'M91-19-UN2', '1R1': 'M91-19-R1', '1R2': 'M91-19-R2', '1R2C': 'M91-19-R2C', '1T1': 'M91-19-T1', '1UA2': 'M91-19-UA2', '1T2C': 'M91-19-T2C', '7B1': 'M90-2-B1', '7B1A': 'M90-2-B1A', '7R1': 'M90-2-R1', '7R1C': 'M90-2-R1-CAN', '7R2C': 'M90-2-R2-CAN', '7T': 'M90-2-T', '7T1': 'M90-2-T1', '7T1C': 'M90-2-T1-CAN', '7TA2': 'M90-2-TA2-CAN', '7TA3': 'M90-2-TA3-CAN', '8TC2': 'M91-2-TC2', '8UN2': 'M91-2-UN2', '8R1': 'M91-2-R1', '8R2': 'M91-2-R2', '8R2C': 'M91-2-R2C', '8T1': 'M91-2-T1', '8UA2': 'M91-2-UA2', '8T38': 'M91-2-T38', '8T2C': 'M91-2-T2C', '8R6C': 'M91-2-R6C', '8R34': 'M91-2-R34', '8A19': 'M91-2-RA19', '8A22': 'M91-2-RA22', '1T38': 'M91-19-T38', 'JR14': 'BOSCH', 'JR17': 'JZ10-11-R17', 'JR10': 'JZ10-11-R10', 'JR16': 'JZ10-11-R16', 'JT10': 'JZ10-11-T10', 'JT17': 'JZ10-11-T17', 'JEW1': 'JZB2-11-EW1', 'JE10': 'JZB1-11-SE10', 'JR31': 'JZ10-11-R31', 'JT40': 'JZ10-11-T40', 'JP15': 'JZ10-11-PT15', 'JE13': 'JZ10-11-UE13', 'JA24': 'JZ10-11-UA24', 'JN20': 'JZ10-11-UN20', '8RZ': 'M91-2-R1-AZ1', '2320': 'V230-13-B20', '2620': 'V260-16-B20', '2820': 'V280-18-B20', '2920': 'V290-19-B20', 'VUN2': 'V120-12-UN2', 'VR1': 'V120-12-R1', 'VR2C': 'V120-12-R2C', 'VUA2': 'V120-12-UA2', 'VT1': 'V120-12-T1', 'VT40': 'V120-12-T40', 'VT2C': 'V120-12-T2C', 'VT38': 'V120-12-T38', 'WUN2': 'V120-22-UN2', 'WR1': 'V120-22-R1', 'WR2C': 'V120-22-R2C', 'WUA2': 'V120-22-UA2', 'WT1': 'V120-22-T1', 'WT40': 'V120-22-T40', 'WT2C': 'V120-22-T2C', 'WT38': 'V120-22-T38', 'WR6C': 'V120-22-R6C', 'WR34': 'V120-22-R34', 'WA19': 'V120-22-RA19', 'WA22': 'V120-22-RA22', 'ERC1': 'EX-RC1', '5320': 'V530-53-B20B', '49C3': 'V570-57-C30 / V290-19-C30', '57C3': 'V570-57-C30 / V290-19-C30', '49T3': 'V570-57-T34 / V290-19-T34', '57T3': 'V570-57-T34 / V290-19-T34', '49T2': 'V570-57-T20 / V290-19-T20', '57T2': 'V570-57-T20 / V290-19-T20', '49T4': 'V570-57-T40 / V290-19-T40', '57T4': 'V570-57-T40 / V290-19-T40', '56C3': 'V560-56-C30', '56T4': 'V560-56-T40', '56T3': 'V560-56-T34', '56T2': 'V560-56-T25B', '13TR22': 'V130-33-TRA22', '13XXXX': 'V130-33-XXXX', '13R2': 'V130-33-R2', '13R34': 'V130-33-R34', '13T2': 'V130-33-T2', '13T38': 'V130-33-T38', '13RA22': 'V130-33-RA22', '13TA24': 'V130-33-TA24', '13B1': 'V130-33-B1', '13T40': 'V130-33-T40', '13R6': 'V130-33-R6', '13TR34': 'V130-33-TR34', '13TR20': 'V130-33-TR20', '13TR6': 'V130-33-TR6', '13TU24': 'V130-33-TU24', '35R2': 'V350-35-R2', '35R34': 'V350-35-R34', '35T2': 'V350-35-T2', '35T38': 'V350-35-T38', '35RA22': 'V350-35-RA22', '35TA24': 'V350-35-TA24', '35B1': 'V350-35-B1', '35T40': 'V350-35-T40', '35R6': 'V350-35-R6', '35TR34': 'V350-35-TR34', '35TR22': 'V350-35-TRA22', '35TR20': 'V350-35-TR20', '35TR6': 'V350-35-TR6', '35TU24': 'V350-35-TU24', '35XXXX': 'V350-35-XXXX', 'S3T20': 'SM35-J-T20', 'S3TA2': 'SM35-J-R20', 'S3R20': 'SM35-J-R20', 'S4T20': 'SM43-J-T20', 'S4TA2': 'SM43-J-R20', 'S4R20': 'SM43-J-R20', '70T2': 'V700-T20BJ', 'EC15': 'EXF-RC15', '10T2': 'V1040', '12T2': 'V1210', 'ADP1': 'ADP-PB1'}
    FW_TYPE_TO_NAME = {'B':'O/S', 'P':'BOOT', 'F':'FactoryBoot', 'FT': 'BinLib'}
    binary_header_magic = b"/_OPLC"
    ascii_header_magic = b"/"
    binary_suffix = b"\\"
    ascii_suffix = b"\x0d"
    PCOM_TCP_HEADER_SIZE = 6
    PCOM_HEADER_SIZE = 24
    PCOM_BINARY_FOOTER_SIZE = 3
    current_tcp_id = 30412

    
    def __init__(self, isTcp=False, debugMode=False) -> None:
        self.isTcp = isTcp
        self.debugMode = debugMode
    

    def print_pcom_binary(self, data):
        opcode_table = {
            b"\x01": "Read Memory Reqeust",
            b"\x81": "Read Memory Response",
            b"\x02": "Check Password",
            b"\x82": "Password OK",
            b"\x0c": "Get PLC Name Request",
            b"\x8C": "Get PLC Name Response",
            b"\x10": "Where Resource Reqeust",
            b"\x90": "Where Resource Response",
            b"\x16": "Translate Index to Address Request",
            b"\x96": "Translate Index to Address Response",
            b"\x1A": "Flash Memory Buffer Request",
            b"\x9A": "Flash Memory Buffer Response",
            b"\x41": "Write Memory Reqeust",
            b"\xC1": "Write Memory Response",
            b"\x4D": "Read Operand Request",
            b"\xCD": "Read Operand Response",
            b"\xFF": "Error",
        }
        opcode = data[12:13]
        opcode_message = opcode_table.get(opcode, "")
        if int.from_bytes(opcode, 'little') & 0b10000000:
            direction = "Client <--- Server"
        else:
            direction = "Client ---> Server"
        
        print(f"{direction}: Binary PCOM Command {opcode_message} ({hex(int.from_bytes(opcode, 'little'))})")

    
    def print_pcom_ascii(self, data):
        opcode_table = {
            b"ID": "Get PLC Version ",
            b"UG": "Get UnitID Command ",
            b"GF": "Read Integers ",
            b"CCS": "Stop PLC "
        }
        if data[0:2] == b"/A":
            direction = "Client (EWS) <--- Server (PLC)"
            type_of_msg = "Response"
            opcode = data[4:6]
        else:
            direction = "Client (EWS) ---> Server (PLC)"
            type_of_message = "Request"
            opcode = data[3:5]
        
        opcode_message = opcode_table.get(opcode, "")
        print(f"{direction}: ASCII PCOM Command {opcode_message} ({opcode.decode()})")


    def extract_pcom_data(self, data):
        # Move after the PCOM/TCP header
        if self.isTcp:
            data = data[self.PCOM_TCP_HEADER_SIZE:]
        if self.debugMode:
            self.print_pcom_binary(data)
        return data[self.PCOM_HEADER_SIZE:-self.PCOM_BINARY_FOOTER_SIZE]

    
    def make_tcp(self,data, isAscii=False):
        tcp = struct.pack("<H", self.current_tcp_id) # Transaction ID (2 bytes)
        self.current_tcp_id += 1
        tcp += struct.pack("B", 101) if isAscii else struct.pack("B", 102) # 101 for Ascii mode or 102 for Binary mode
        tcp += b"\x00" # Reserved
        tcp += struct.pack("<H", len(data)) # PCOM length
        tcp += data
        return tcp 

    
    def calc_binary_hedear_crc(self,data):
        # Packet[0:22]
        return struct.pack("<H", (( ~ (sum(data[0:22]) % 0x10_000) + 1 ) % 0xffff + 1))
    
    
    def calc_binary_footer_crc(self,data):
        # Packet[24:-3]
        return struct.pack("<H", (( ~ (sum(data[self.PCOM_HEADER_SIZE:]) % 0x10_000) + 1 ) % 0xffff + 1))
    
    
    def calc_ascii_crc(self, data):
        # Packet[1:-3]
        return hex(sum((data)[1:]) % 256).upper()[2:].rjust(2,"0").encode()
    

    def create_binary_request(self, command_opcode, command_details = b'\x00\x00\x00\x00\x00\x00', command_data = b"", res1=b"\xfe", res2=b"\x01", res3=b"\x01\x00\x00", res4=b"\x00"):
        header = self.binary_header_magic # Magic
        header += b'\x00' # ID
        header += res1 # default: b'\xfe' # Reserved
        header += res2 # default: b'\x01' # Reserved
        header += res3 # default: b'\x01\x00\x00' # Reserved
        header += struct.pack("b", command_opcode) # Command Opcode
        header += res4 # default: b'\x00' # Reserved
        header += command_details[0:6] # Command details (6 bytes)
        header += struct.pack("<H", len(command_data)) # Command length
        header += self.calc_binary_hedear_crc(header) # CRC
        packet = header
        packet += command_data # Data

        if not command_data:
            footer_crc = b'\x00\x00'
        else:
            footer_crc = self.calc_binary_footer_crc(packet) # CRC
        packet += footer_crc
        packet += self.binary_suffix # Suffix (\)

        if self.debugMode:
            self.print_pcom_binary(packet)
        
        if self.isTcp:
            return self.make_tcp(packet)
        
        return packet
   

    # Binary Request
    def create_read_plc_name(self):
        opcode = 0x0c
        return self.create_binary_request(opcode)

    
    # Binary Response
    def parse_read_plc_name(self,data):

        # Move after the PCOM/TCP header
        if self.isTcp:
            data = data[self.PCOM_TCP_HEADER_SIZE:]

        if self.debugMode:
            self.print_pcom_binary(data)
        
        # The header length should be 27 bytes long (including footer + suffix)
        if len(data) < 27:
            return 0

        name_len = struct.unpack("<H", data[20:22])[0]
        
        if not name_len:
            return 0
        
        # Check packet is long enough to contain name
        if len(data) < 27 + name_len:
            return 0
        
        name = data[self.PCOM_HEADER_SIZE:self.PCOM_HEADER_SIZE + name_len]
        
        return name


    # ASCII Request
    def create_read_system_integers(self):
        request = self.ascii_header_magic # Magic (/)
        request += b"00" # Unit ID (00 const)
        request += b"GF" # Opcode 
        request += b"00FC" # Address
        request += b"01" # Length
        request += self.calc_ascii_crc(request)
        request += self.ascii_suffix

        if self.debugMode:
            self.print_pcom_ascii(request)
        
        if self.isTcp:
            return self.make_tcp(request, isAscii=True)
        
        return request    

    
    # ASCII Requset
    def create_read_plc_versions(self):
        request = self.ascii_header_magic # Magic (/)
        request += b"00" # Unit ID (00 const)
        request += b"ID" # Opcode
        request += self.calc_ascii_crc(request) # CRC
        request += self.ascii_suffix # Suffix
        
        if self.debugMode:
            self.print_pcom_ascii(request)
        
        if self.isTcp:
            return self.make_tcp(request, isAscii=True)
        
        return request
    

    # ASCII Response
    def parse_version(self, data):
        
        # Move after the PCOM/TCP header
        if self.isTcp:
            data = data[self.PCOM_TCP_HEADER_SIZE:]
        
        if self.debugMode:
            self.print_pcom_ascii(data)

        # 49T4 C 
        # 004 010 36 B --> 4.10.36 B (OS)
        # 002 002 53 P --> 2.2.53 P (BOOT)
        # 000 000 43 F --> 0.0.43 F (BinLib / Force)
        # 11100001     --> ?????

        data = data.decode()
        data = data[self.PCOM_TCP_HEADER_SIZE:-self.PCOM_BINARY_FOOTER_SIZE]
        REGEX_FW_SINGLE = "(([0-9x]{3})([0-9x]{3})([0-9x]{2})([A-Z]+))"
        res = {}
        model_len = 6
        
        while self.MODELS.get(data[:model_len]) is None:
            model_len -= 1
            if model_len == 2:
                return data
        
        res["model"] = data[:model_len]
        res["model_desc"] = self.MODELS.get(data[:model_len])
        res["hw_rev"] = data[model_len:model_len+1]
        res["fw_ver"] = []
        sub_fw = re.findall(REGEX_FW_SINGLE, data)
        
        for match in sub_fw:
            full_match, ver, ver_major, ver_minor, ver_type = match
            if ver_type == "FT":
        
                # 03100020 --> 0-3.10 (20)
                # 11100001 --> 1-1.10 (10)
                version = f"{full_match[0:1]}-{full_match[1:2]}.{full_match[2:4]} ({full_match[4:8]})"
        
            else:
                ver = int(ver) if ver.isdigit() else ver
                ver_major = int(ver_major) if ver_major.isdigit() else ver_major
                ver_minor = int(ver_minor) if ver_minor.isdigit() else ver_minor
                version = f"{ver}.{str(ver_major).zfill(3)} ({str(ver_minor).zfill(2)})" # 2.011 (02)
        
            res["fw_ver"].append({"version": version, "type": ver_type})
        
        leftovers = data.split(full_match)[-1]
        res["leftover"] = leftovers
        return res

    
    # Binary Request
    def create_read_operand(self):
        command_opcode = 0x4d
        command_details = b"\x00\x00\x00\x00\x02\x00" # Const for read_operand
        command_data = b"\x01\x00\x02\xff\x8d\x00\x03\x00\x11\xff\x00\x00\x09\x00\x03\x00" # Const for read Operand
        return self.create_binary_request(command_opcode=command_opcode, command_details=command_details, command_data=command_data)


    # Binary Response
    def parse_read_operand(self,data):
        
        # Move after the PCOM/TCP header
        if self.isTcp:
            data = data[self.PCOM_TCP_HEADER_SIZE:]
        
        if self.debugMode:
            self.print_pcom_binary(data)

        # Not interesting data for us here
        pass

    
    # ASCII Requset
    def create_stop_command(self):
        request = self.ascii_header_magic # Magic (/)
        request += b"00" # Unit ID (00 const)
        request += b"CCS" # Opcode
        request += self.calc_ascii_crc(request)
        request += self.ascii_suffix
        
        if self.debugMode:
            self.print_pcom_ascii(request)

        if self.isTcp:
            return self.make_tcp(request, isAscii=True)
        
        return request


    # ASCII Requset
    def create_read_unitID(self):
        request = self.ascii_header_magic # Magic (/)
        request += b"00" # Unit ID (00 const)
        request += b"UG" # Opcode
        request += self.calc_ascii_crc(request)
        request += self.ascii_suffix
        
        if self.debugMode:
            self.print_pcom_ascii(request)

        if self.isTcp:
            return self.make_tcp(request, isAscii=True)
        
        return request


    # ASCII Response
    def parse_read_unitID(self,data):

        # Move after the PCOM/TCP header
        if self.isTcp:
            data = data[self.PCOM_TCP_HEADER_SIZE:]
        
        if self.debugMode:
            self.print_pcom_ascii(data)

        return data[self.PCOM_TCP_HEADER_SIZE:-self.PCOM_BINARY_FOOTER_SIZE]

    
    # Binary Request
    def create_where_resource(self, resource_id):
        opcode = 0x10
        res1 = b"\xfe"
        res2 = b"\x01"
        res3 = b"\x00\x00\x00"
        res4 = struct.pack("b", resource_id)
        command_details = b"\x00"*6
        return self.create_binary_request(command_opcode=opcode, res1=res1, res2=res2, res3=res3, res4=res4, command_details=command_details)

    
    # Binary Response
    def parse_where_resource(self, data):
        
        # Move after the PCOM/TCP header
        if self.isTcp:
            data = data[self.PCOM_TCP_HEADER_SIZE:]

        if self.debugMode:
            self.print_pcom_binary(data)

        addr, size, res_id = struct.unpack("<III", data[self.PCOM_HEADER_SIZE:-self.PCOM_BINARY_FOOTER_SIZE])
        return addr, size, res_id

    
    # Binary Request
    def create_read_memory(self, address, size, flag=1):
        opcode = 0x01
        res1 = b"\xfe"
        res2 = b"\x01"
        res3 = b"\x00\x00\x00"
        res4 = struct.pack("b", flag)
        command_details = address
        command_details += struct.pack("<H", size)
        return self.create_binary_request(command_opcode=opcode, res1=res1, res2=res2, res3=res3, res4=res4, command_details=command_details)


    # This function parses the resource table struct from memory read from the PLC (using read_memory)
    # Binary Response
    def parse_read_resource_table(self, data):
        # Move after the PCOM/TCP header
        if self.isTcp:
            data = data[self.PCOM_TCP_HEADER_SIZE:]
        
        if len(data) < 67:
            return 0
        
        if self.debugMode:
            self.print_pcom_binary(data)

        # OPLC_HEADER (size 24)
        # Resource table struct (each size 4)
        # We need the 10th resource (signature table) --> 24 + 9*4 
        index =  struct.unpack("<I", data[self.PCOM_HEADER_SIZE + 9*4: self.PCOM_HEADER_SIZE + 10*4])[0]
        return index
    

    # Binary Request
    def create_write_memory(self, address, size, data, flag=1):
        opcode = 0x41
        res1 = b"\xfe"
        res2 = b"\x01"
        res3 = b"\x00\x00\x00"
        res4 = struct.pack("b", flag)
        command_details = address
        command_details += struct.pack("<H", size)
        return self.create_binary_request(command_opcode=opcode, res1=res1, res2=res2, res3=res3, res4=res4, command_details=command_details, command_data=data)

    
    # This function creates a request translating a resource index to its address. For example, the resource table has index 0x0d
    # Binary Request
    def create_translate_resource_index_to_address(self, index):
        command_opcode = 0x16
        command_data = b"\x64\x00" # Const
        command_data += struct.pack("<H", index) # Resource Index
        res3 = b"\x00\x00\x00"
        return self.create_binary_request(command_opcode=command_opcode, command_data=command_data, res3=res3)


    # Binary Response
    def parse_translate_index(self,data):
        
        # Move after the PCOM/TCP header
        if self.isTcp:
            data = data[self.PCOM_TCP_HEADER_SIZE:]
        
        if self.debugMode:
            self.print_pcom_binary(data)

        if len(data) < 37:
            return 0
        
        # Message Struct:
        #   OPLC_HEADER (size 24)
        #   PCOM_DATA (should be <= size 10)
        #   OPLC_FOOTER (size 3)

        # PCOM_DATA Struct:
        #   ???? (size 4)
        #   Index Address (Size 4)
        #   Content Length (Size 2)
        address = data[self.PCOM_HEADER_SIZE + 2: self.PCOM_HEADER_SIZE + 6]
        size = struct.unpack("<H", data[self.PCOM_HEADER_SIZE + 6: self.PCOM_HEADER_SIZE + 8])[0]
        return (address, size)

    
    # Gets the address of the resource table
    # Binary Request
    def create_read_resource_table_address(self):
        return self.create_translate_resource_index_to_address(0x0d)


    # Unknown opcode
    # Binary Request
    def create_opcode_1a_request(self):
        command_opcode = 0x1a
        res3 = b"\x00\x00\x00"
        return self.create_binary_request(command_opcode=command_opcode, res3=res3)


    # Binary Response    
    def parse_opcode_1a(self,data):
        # Move after the PCOM/TCP header
        if self.isTcp:
            data = data[self.PCOM_TCP_HEADER_SIZE:]
        
        if self.debugMode:
            self.print_pcom_binary(data)


    # Parse a single signature record
    def parse_signature(self,data):
        reader = BytesIO(data)
        magic = up_I(reader)
        print(f"\t[-] Magic: {hex(magic)}")
        total_len = up_I(reader)
        print(f"\t[-] Total Len: {hex(total_len)} ({total_len == len(data)})")

        while reader.tell() < len(data):
            print(f"\t[-] Signature Topic")

            unk1 = reader.read(4)
            print(f"\t\t[-] Unk1: {tx(unk1)}")
            
            unk2 = reader.read(4)
            print(f"\t\t[-] Unk2: {tx(unk2)}")

            block_size = up_I(reader)
            print(f"\t\t[-] Size: {hex(block_size)}")

            name = reader.read(18)
            name = name.decode("utf-16")
            print(f"\t\t[-] Name: {name}")

            if 1000 > block_size > 200:
                body = reader.read(block_size-4-4-4-18-4)
            else:
                block_size = 1000 # default
                body = reader.read(block_size-4-4-4-18-4)
            
            if not (reader.tell() < len(data)):
                footer = int.from_bytes(body[-4:],"little")
                body = body[:-4]
            else:
                footer = up_I(reader)
            
            try:
                decompressed_body = zlib.decompress(body[11:],-15)
                print(f"\t\t[-] Decompressed Body: {len(decompressed_body)} bytes")
                self.parse_decompressed(decompressed_body)
                print(f"\t\t[-] Footer: {hex(footer)}")
            except Exception as e:
                pass
    

    def parse_decompressed(self, data):
        
        try:
            
            # data[0x4:0xc] - PC Date
            pc_date_double, = struct.unpack('<d', data[0x4:0xc])
            pc_date = datetime.datetime(1899, 12, 30) + datetime.timedelta(pc_date_double)
            print_body_info("PC Date", pc_date)

            # data[0xc:0x1c] - GUID
            guid_tuple = struct.unpack('<IHH2s6s', data[0xc:0x1c])
            guid_first_part = '-'.join([hex(item).strip('0x').upper() for item in guid_tuple[:-2]])
            guid_second_part = f"{binascii.hexlify(guid_tuple[-2]).decode().upper()}-{binascii.hexlify(guid_tuple[-1]).decode().upper()}"
            guid = f"{{{guid_first_part}-{guid_second_part}}}"
            print_body_info('GUID', guid)

            # data[0x1c:0x2c] - Username
            print_body_info('User', data[0x1c:0x2c])

            # data[0x2c:0x40] - Description
            print_body_info('Description', data[0x2c:0x40])

            # data[0x40:0x68] - Path
            print_body_info('Path', data[0x40:0x68])

            # data[0x68:0x6a] - DB
            db, = struct.unpack('<H', data[0x68:0x6a])
            print_body_info('DB', db)

            # data[0x6a:0x6c] - Version Created
            created, = struct.unpack('<H', data[0x6a:0x6c])
            
            try:
                created_str = str(created)
                created_str = f"{created_str[0]}.{created_str[1]}.{created_str[2:]}"
            
            except Exception as e:
                created_str = str(created)
            
            print_body_info('Created Version', created_str)
            
            # data[0x6c:0x6e] - Modified Version
            modified, = struct.unpack('<H', data[0x6c:0x6e])
            
            try:
                modified_str = str(modified)
                modified_str = f"{modified_str[0]}.{modified_str[1]}.{modified_str[2:]}"
            
            except Exception as e:
                modified_str = str(modified)
            
            print_body_info('Modified Version', modified_str)

            # data[0x6e:0x70] - Booleans bitmask
            features_bitmask, = struct.unpack('<H', data[0x6e:0x70])
            features_bitmask_str = bin(features_bitmask)[2:].zfill(16)[::-1]

            info_table_bit, ladder_bit, ladder_data_bit, page_bit, misc_data_bit, eDT_Reserved1_bit, page_idx_bit, eDT_Reserved2_bit, variables_bit, eDT_Reserved3_bit, counters_bit, functionBlocks_bit, func_blocks_inst_bit, timers_bit, data_tables_bit, hw_config_bit = [bool(int(x)) for x in features_bitmask_str]

            # data[0x70:0x78] - Unk1/2
            unk1, unk2 = struct.unpack('<II', data[0x70:0x78])
            print_body_info('Unk1 (0)', unk1)
            print_body_info('Unk2 (0)', unk2)

            # data[0x78:0xb8] - All other integers

            info_table, ladder, ladder_data, page, misc_data, eDT_Reserved1, page_idx, eDT_Reserved2, variables, eDT_Reserved3, counters, functionBlocks, func_blocks_inst, timers, data_tables, hw_config, eDT_Reserved4 = struct.unpack('<'+'I'*17, data[0x78:0x78 + 4*17])
            
            print_body_info(f'Info Tables Downloaded: {info_table_bit} (CRC={info_table})', None)
            
            print_body_info(f'Ladder Downloaded: {ladder_bit} (CRC={ladder})', None)
            
            print_body_info(f'Ladder Data Downloaded: {ladder_data_bit} (CRC={ladder_data})', None)
            
            print_body_info(f'Page Downloaded: {page_bit} (CRC={page})', None)
            
            print_body_info(f'Misc.Data Downloaded: {misc_data_bit} (CRC={misc_data})', None)
            
            print_body_info(f'eDT_Reserved1 Downloaded: {eDT_Reserved1_bit} (CRC={eDT_Reserved1})', None)
            
            print_body_info(f'Pages->Idx Downloaded: {page_idx_bit} (CRC={page_idx})', None)
            
            print_body_info(f'eDT_Reserved2 Downloaded: {eDT_Reserved2_bit} (CRC={eDT_Reserved2})', None)
            
            print_body_info(f'Variables Downloaded: {variables_bit} (CRC={variables})', None)
            
            print_body_info(f'eDT_Reserved3 Downloaded: {eDT_Reserved3_bit} (CRC={eDT_Reserved3})', None)
            
            print_body_info(f'Counters Downloaded: {counters_bit} (CRC={counters})', None)
            
            print_body_info(f'FunctionBlocks Downloaded: {functionBlocks_bit} (CRC={functionBlocks})', None)
            
            print_body_info(f'Function Blocks Instance Downloaded: {func_blocks_inst_bit} (CRC={func_blocks_inst})', None)
            
            print_body_info(f'Timers Downloaded: {timers_bit} (CRC={timers})', None)
            
            print_body_info(f'Data Tables Downloaded: {data_tables_bit} (CRC={data_tables})', None)
            
            print_body_info(f'HW Configuration Downloaded: {hw_config_bit} (CRC={hw_config})', None)
            
            # data[0xbc:0xcc] - Connection info
            conn_info = data[0xbc:0xcc]
            conn_info_type = conn_info[0]
            
            if conn_info_type == 0:
                conn_info_general = "Serial"
                conn_info_details = conn_info[1:]
            
            elif conn_info_type == 3:
                conn_info_general = "TCP/IP"
                conn_info_ip = socket.inet_ntoa(conn_info[1:5])
                conn_info_port, = struct.unpack("<H", conn_info[7:9])
                conn_info_details = f"{conn_info_ip} TCP {conn_info_port}"
            else:
                conn_info_general = f"Unknown (type {conn_info_type})"
                conn_info_details = conn_info[1:].hex()
            
            print_body_info('Connection Info General', conn_info_general)
            
            print_body_info('Connection Info Details', conn_info_details)

            # data[0xcd:0xce] - PLC Reset Event
            plc_reset_event, = struct.unpack("<B", data[0xcd:0xce])
            PLC_RESET_DICT = {
                0: "None",
                1: "Flash",
                2: "Password",
                3: "Hardware Config",
                4: "Function Block",
                5: "Memory",
                6: "ISC",
                7: "Compiled STL Size",
                8: "Build All",
                9: "User",
            }
            plc_reset_event_desc = PLC_RESET_DICT.get(plc_reset_event, f"Unknown") + f" (type {hex(plc_reset_event)})"
            print_body_info('PLC Reset', plc_reset_event_desc)

            # data[0xd4:0xd8] - UnitID
            unitid, = struct.unpack("<I", data[0xd4:0xd8])
            print_body_info('Unit ID', unitid)

            #data[0xe4:0xe8] - User OS
            pc_os_type, = struct.unpack("<f", data[0xe4:0xe8])
            pc_os_desc = "Unknown"
            
            if pc_os_type == 5.0:
                pc_os_desc = "Windows XP"
            
            elif pc_os_type == 6.0:
                pc_os_desc = "Windows 7 or later"
            
            else:
                pc_os_desc = "Windows Unknown"

            pc_os_desc = f"{pc_os_desc} (type {pc_os_type})"
            print_body_info('PC OS', pc_os_desc)

            # data[0xe8:0x128] - User Computer Langauge
            language = data[0xe8:0x128]
            print_body_info('Language', language)

            # data[0x128:0x138] - PLC Model
            plc_model = data[0x128:0x138]
            print_body_info('PLC Model', plc_model)
            
            # data[0x138:0x148] - PLC Boot Version
            boot = data[0x138:0x148]
            print_body_info('Boot', boot)

            # data[0x148:0x158] - PLC Bin Lib Version
            bin_lib = data[0x148:0x158]
            print_body_info('BinLib', bin_lib)

            # data[0x158:0x168] - PLC Factory Boot Version
            factory_boot = data[0x158:0x168]
            print_body_info('Factory Boot', factory_boot)

            # data[0x168:0x16c] - User Connection Timeout
            timeout_ms, = struct.unpack("<I", data[0x168:0x16c])
            print_body_info('Timeout (ms)', timeout_ms)

            # data[0x16c:0x170] - User Connection Retry Count
            retry_count, = struct.unpack("<I", data[0x16c:0x170])
            print_body_info('Retry Count', retry_count)

            # data[0x170:] - Download Type
            download_type = data[0x170:]
            print_body_info('Download Type', download_type)

        except struct.error as e:
            print(f"\t\t{WARNING}[x] Warning: Struct failed to unpack a field.{ENDC}")
            return

        except Exception as e:
            print(f"Error: {e}")
    

    # Binary request
    def create_check_password_request(self, password):
        opcode = 0x02
        res3 = b"\x00\x00\x00"
        password = password[:8].ljust(8," ").encode()
        return self.create_binary_request(command_opcode=opcode, command_data=password, res3=res3)


    # Binary Response
    def parse_check_password(self, data):        
        # Move after the PCOM/TCP header
        if self.isTcp:
            data = data[self.PCOM_TCP_HEADER_SIZE:]
        
        if self.debugMode:
            self.print_pcom_binary(data)

        opcode = data[12]
        reserved = data[13]
        
        if opcode == 0x82 and reserved == 0x64:
            return True
        
        return False
    

def do_read(sock, pcom_client, addr, length, flag, read_size=976):
    pcom = pcom_client
    read_bytes = 0
    res = b""

    while read_bytes < length:
        print(f"\r[-] Reading from address: {hex(addr)} ({(read_bytes/length)*100:.2f}%)      ", end="")
        size = min(read_size, length-read_bytes)
        read_mem = pcom.create_read_memory(struct.pack("<I", addr), size, flag=flag)
        sock.send(read_mem)
        read_bytes += size
        addr += size
        resp = sock.recv(1024*5)
        res += pcom.extract_pcom_data(resp)
    
    print(f"\r[-] Read is completed (100%)                                                    ", end="")
    print("")
    
    return res


def do_write(sock, pcom_client, addr, data, flag):
    pcom = pcom_client
    write_size = 976
    write_bytes = 0
    length = len(data)
    res = b""
    
    while write_bytes < length:
        print(f"\r[-] Writing to address: {hex(addr)} ({(write_bytes/length)*100:.2f}%)      ", end="")
        size = min(write_size, length-write_bytes)
        current_data_chunk = data[write_bytes:write_bytes+size]
        write_mem = pcom.create_write_memory(struct.pack("<I", addr), size, current_data_chunk, flag=flag)
        sock.send(write_mem)
        write_bytes += size
        addr += size
        resp = sock.recv(1024*5)
        pcom.extract_pcom_data(resp)
    
    print(f"\r[-] Write is completed (100%)                                                    ", end="")
    
    print("")


def print_firmware_version(data):
    
    if type(data) in [bytes, str]:
        print(f"\t[-] Unknown Model (model: {data})")
    
    else:
        print("\t[-] Model: " + data.get("model_desc"))
        print("\t[-] HW Rev: " + data.get("hw_rev"))
        is_ft_exists = False
    
        for fw_ver in data["fw_ver"]:
            fw_ver_type = fw_ver.get("type")
            if fw_ver_type == "FT":
                is_ft_exists = True
            fw_ver_version = fw_ver.get("version")
            print(f"\t[-] {PCOM_CLIENT.FW_TYPE_TO_NAME.get(fw_ver_type,fw_ver_type)}: {fw_ver_version}")
    
        if not is_ft_exists and len(data.get("leftover","")) == 8:
            binlib_ver_full = data.get("leftover")
            binlib_ver = f"{binlib_ver_full[0:1]}-{binlib_ver_full[1:2]}.{binlib_ver_full[2:4]} ({binlib_ver_full[4:8]})"
            print("\t[-] BinLib: " + binlib_ver)    


def print_plc_name(sock, pcom_client):
    s = sock
    pcom = pcom_client
    # --> (B) Get Name Req (0c)
    get_name_req = pcom.create_read_plc_name()
    s.send(get_name_req)
    # <-- (B) Get Name Res (8c)
    resp = s.recv(1024*5)
    plc_name = pcom.parse_read_plc_name(resp)
    print(f"\t[-] PLC Name: {plc_name.decode()}")


def print_plc_firmware(sock, pcom_client):
    s = sock
    pcom = pcom_client
    # --> (A) Get Versions Req (ID)
    get_versions_req = pcom.create_read_plc_versions()
    s.send(get_versions_req)
    # <-- (A) Get Versions Res (ID)
    resp = s.recv(1024*5)
    firmware_version_raw = pcom.parse_version(resp)
    print_firmware_version(firmware_version_raw)


def print_plc_unitid(sock, pcom_client):
    s = sock
    pcom = pcom_client
    # --> (A) Get UnitID (UG) Req  (UG)
    get_unitid_req = pcom.create_read_unitID()
    s.send(get_unitid_req)
    # <-- (A) Get UnitID (UG) Res  (UG)
    resp = s.recv(1024*5)
    unitId = pcom.parse_read_unitID(resp)
    print(f"\t[-] UnitID: {unitId.decode()}")


def print_signature_table(sock, pcom_client):
    # Directions:
    # Client (EWS) <--> Server (PLC)
    # Type of Connection:
    # (B)inary (A)scii
    # --> (B) Get Name Req (0c)                     
    # <-- (B) Get Name Res (8c)                     
    # --> (A) Get Versions Req (ID)                 
    # <-- (A) Get Versions Res (ID)                 
    # --> (B) Read Operands Req (4D)                
    # <-- (B) Read Operands Res (CD)                
    # --> (A) Get UnitID (UG) Req  (UG)             
    # <-- (A) Get UnitID (UG) Res  (UG)             
    # --> (B) Get Resource Table Address Req (16)   
    # <-- (B) Get Resource Table Address Res (96)   
    # --> (B) Opcode 0x1a Req  (1A)                 
    # <-- (B) Opcode 0x1a Res  (9A)                 
    # --> (B) Read Resource Table Memory Req  (01)  
    # <-- (B) Read Resource Table Memory Res  (81)  
    # --> (B) Get Signature Address Req (16)        
    # <-- (B) Get Signature Address Res (96)        
    # --> (B) Opcode 0x1a Req  (1A)                 
    # <-- (B) Opcode 0x1a Res  (9A)                 
    # --> (B) Read Signature Table Memory Req  (01) 
    # <-- (B) Read Signature Table Memory Res  (81) 

    s = sock
    pcom = pcom_client

    # --> (B) Read Operands Req (4D) 
    read_operand_req = pcom.create_read_operand()
    s.send(read_operand_req)
    # <-- (B) Read Operands Res (CD)
    resp = s.recv(1024*5)

    # --> (B) Get Resource Table Address Req (16)
    get_resource_table_address_req = pcom.create_read_resource_table_address()
    s.send(get_resource_table_address_req)
    # <-- (B) Get Resource Table Address Res (96)
    resp = s.recv(1024*5)
    rTable_addr, rTable_size = pcom.parse_translate_index(resp)
    rTable_addr_hex = hex(struct.unpack("<I", rTable_addr)[0])
    print(f"\t[-] Resource Table Address: {rTable_addr_hex} Size: {hex(rTable_size)}")

    # --> (B) Opcode 0x1a Req  (1A)
    flush_req = pcom.create_opcode_1a_request()
    s.send(flush_req)
    # <-- (B) Opcode 0x1a Res  (9A)
    resp = s.recv(1024*5)
    pcom.parse_opcode_1a(resp)

    # --> (B) Read Resource Table Memory Req  (01)
    read_rTable_memory = pcom.create_read_memory(rTable_addr, rTable_size, flag=4)
    s.send(read_rTable_memory)
    # <-- (B) Read Resource Table Memory Res  (81)
    resp = s.recv(1024*5)
    sigTable_index = pcom.parse_read_resource_table(resp)
    print(f"\t[-] Signature Table Index: {sigTable_index}")

    # --> (B) Get Signature Address Req (16)
    get_signature_table_address_req = pcom.create_translate_resource_index_to_address(sigTable_index)
    s.send(get_signature_table_address_req)
    # <-- (B) Get Signature Address Res (96)
    resp = s.recv(1024*5)
    sigTable_address, sigTable_size = pcom.parse_translate_index(resp)
    sigTable_address_hex = hex(struct.unpack("<I", sigTable_address)[0])
    print(f"\t[-] Signature Table Address: {sigTable_address_hex} Size: {hex(sigTable_size)}")

    # --> (B) Opcode 0x1a Req  (1A)
    flush_req = pcom.create_opcode_1a_request()
    s.send(flush_req)
    # <-- (B) Opcode 0x1a Res  (9A)
    resp = s.recv(1024*5)
    pcom.parse_opcode_1a(resp)

    # --> (B) Read Signature Table Memory Req  (01)
    # <-- (B) Read Signature Table Memory Res  (81) - Check
    addr = struct.unpack("<I", sigTable_address)[0]
    sig_table_data = do_read(sock=s, pcom_client=pcom, addr=addr, length=sigTable_size, flag=4)
    sigTable = pcom.parse_signature(sig_table_data)


def read_project_zip(sock, pcom_client):
    s = sock
    pcom = pcom_client
    where_resource_id_req = pcom.create_where_resource(resource_id=RESOURCE_ID_PROJECT_ZIP)
    s.send(where_resource_id_req)
    resp = s.recv(1024*5)
    addr, size, res_id = pcom.parse_where_resource(resp)
    print(f"[-] Reading project file from {hex(addr)} with size {hex(size)}")
    project_zip_data = do_read(sock=s, pcom_client=pcom, addr=addr, length=size, flag=res_id) # flag should be 1
    return project_zip_data


def read_and_save_project_zip(sock, pcom_client):
    name = f"project_{int(time.time())}.zip"
    project_zip = read_project_zip(s, pcom)
    project_zip = project_zip[0x2a:]
    with open(name, "wb") as f:
        f.write(project_zip)


def read_memory(sock, pcom_client, loc_type=1, start=0, end=0x100000):
    s = sock
    pcom = pcom_client
    print(f"[-] Dumping RAM from from address {hex(start)} to address {hex(end)} (flag={loc_type})")
    data = do_read(sock=s, pcom_client=pcom, addr=start, length=end-start, flag=loc_type)
    with open(f"ram_{hex(start)}_{hex(end)}_flag_{loc_type}_{time.time()}.bin", "wb") as f:
        f.write(data)


def write_memory(sock, pcom_client, addr, data, loc_type=1):
    s = sock
    pcom = pcom_client
    print(f"[-] Writing memory from from address {hex(addr)} with size {hex(len(data))} (flag={loc_type})")
    do_write(sock, pcom_client, addr, data, loc_type)


def upload_auth(sock, pcom_client, password=PASSWORD_DEFAULT):
    s = sock
    pcom = pcom_client
    print(f"[-] Trying to check upload_auth with password: '{password}'")
    # --> (B) Opcode 0x02 Req
    req_pass = pcom.create_check_password_request(password)
    s.send(req_pass)
    # <-- (B) Opcode 0x82 Res
    resp = s.recv(1024*5)
    is_ok = pcom.parse_check_password(resp)
    if is_ok:
        print(f"\t[-] Password: OK")
        return True
    else:
        print(f"\t[-] Password: Bad")
        return False


def main():
    ip_addr = sys.argv[1]
    pcom = PCOM_CLIENT(isTcp=True, debugMode=False)
    s = socket.socket()
    port = 20256
    s.connect((ip_addr, port))

    print_plc_name(s, pcom)
    print_plc_firmware(s, pcom)
    print_plc_unitid(s, pcom)
    print_signature_table(s, pcom)
    read_and_save_project_zip(s, pcom)
    
    
if __name__ == "__main__":
    main()
