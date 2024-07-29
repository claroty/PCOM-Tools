# Unitronics Forensic Tools / by Claroty Team82

### TL;DR
Unitronics Forensic Tools, including a modular PCOM client, as well as PCOM to TCP converter (and vice versa). 

Using these tools, we implemented a custom PCOM client (Unitronics Vision/Samba communication protocol), allowing users to connect to their PLC using either serial/TCP, and query information from it. 
These tools main goal is to enable users to extract forensic infromation from attacked Unitronics PLCs.

### Background
Due to [recent attacks](https://claroty.com/team82/blog/opportunistic-hacktivists-target-plcs-at-us-water-facility) on Unitronics Vision/Samba PLCs, we research the communication protocol implemented by these PLC/HMI devices. The goal of our research was to develop a toolset enabling users to extract forensic information from attacked PLCs.

At the end of our research, we developed two tools - 
- `PCOMClient`: a PCOM client, enabling users to connect to their Unitronics Vision/Samba series PLCs/HMIs. In this module, we support PCOM Serial, PCOM TCP, PCOM ASCII and PCOM Binary messages, as well as support a wide range of built-in function codes/procedures. This tool in specific allows users to extract forensic information from their PLC.

- `PCOM2TCP`: This tool allows users to convert PCOM messages from PCOM TCP to PCOM Serial and vice versa. This allows users with only serial connection to the PLC to connect to it using PCOM TCP, and sniff packets.



### What's supported?
- `PCOM Serial`
- `PCOM\TCP`
- `PCOM ASCII`
- `PCOM Binary`
- `Supported PCOM Function Codes` - 23 opcodes
- `Supported Procedures` - read/write raw memory, upload project, read resources etc.
- `Forensic Information Extraction` - read PLC infromation (version, name, UnitID etc.), dump and parse siganture table.


### Usage
Basic Usage: `python pcom_client.py SERVER_IP`
Main functionalities:
1. Setup PCOM Client -
```
ip_addr = sys.argv[1]
pcom = PCOM_CLIENT(isTcp=True, debugMode=False)
s = socket.socket()
port = 20256
s.connect((ip_addr, port))

# You are connected, now invoke any function you choose.
print_plc_name(s, pcom)
print_plc_firmware(s, pcom)
```
2. Extract Information About PLC - 
```
print_plc_name(s, pcom)
print_plc_firmware(s, pcom)
print_plc_unitid(s, pcom)
```

3. Extract Signature Table -
```
print_signature_table(s, pcom)
```

4. Read Project File:
```
read_and_save_project_zip(s, pcom)
```

5. Read/Write RAM:
```
# Read memory:
location_id = 1 	# 1/4 - identifies memory type
start_addr	= 0 	# Read from
end_addr 	= 0x100 # Read until

read_memory(s, pcom, location_id, start_addr, end_addr)

# Write memory (use with caution):
location_id = 1 				# 1/4 - identifies memory type
addr		= 0 				# Write to
data 		= b'Claroty Team82' # Data to write

write_memory(s, pcom, addr, data, location_id)
```


### Function Codes
----------------------------------------------------
| Function Code (req/resp) | Description           |
|--------------------------|-----------------------|
| 0x01 / 0x81   		   | Read Memory           |
| 0x02 / 0x82        	   | Check Password        |
| 0x0C / 0x8C 			   | Get PLC Name 	       |
| 0x10 / 0x90			   | Find resources	       |
| 0x16 / 0x96			   | Translate Resource Index to Address*    |
| 0x1A / 0x9A			   | Flush Memory Buffer   |
| 0x41 / 0xC1			   | Write Memory 		   |
| 0x42 / 0xC2			   | Reset Upload Password ([CVE-2024-38434](https://claroty.com/team82/disclosure-dashboard/cve-2024-38434)) |
| 0x4D / 0xCD			   | Read Operand		   |
| 0xFF					   | Error				   |
| ID (ASCII) 			   | Get PLC ID 		   |
| UG (ASCII)			   | Get PLC UnitID 	   |
| GF (ASCII)			   | Get PLC Version 	   |


### Forensic Information

Using our PCOMClient tool, users which their PLC was attacked can extract *TONS* of forensic information from their PLC, containig details about the attack itself, as well as on the attacker's computer and setup.
Our tool allows users to extract forensic information using two methods:

- Project Upload - using the `read_and_save_project_zip` function, it is possible to extract the project from the PLC (only available if the project was "burned" - downloaded using "Download & Burn"). The project is an encrypted zip file (with an hardcoded password), containing an Access DB file. In this Access DB file, there is a lot of information about the project creator PC.

- Signature Table - in the Unitronics ecosystem, the Signature Table is a structure containg data about PLC connectsions, as well as the PC of the user connecting to it. using the `print_signature_table` function, it is possible to extract the Signature Table from the PLC.


Here is a table showing all forensic evidence possible for extraction from the PLC:
------------------------------------------------------------------------------
| Forensic Evidence     | Is Inside Siganture Table | Is Inside Project File |
|-----------------------|---------------------------|------------------------|
| Project Path 		    | Yes 					    | Yes 				     |
| PC Username 		    | Yes 					    | No (could be in path)  |
| Project Creation Date | No 						| Yes  		   			 |
| PLC Connection Date 	| Yes 						| Yes 					 |
| Computer Keyboards 	| Yes 						| Yes 					 |
| PLC Connection String | Yes 						| Yes 					 |
| Project Images 		| No 						| Yes 					 |
| Project Functions 	| No 						| Yes 					 |




### How to use
```
git clone https://github.com/claroty/pcom-forensic-tools.git
cd pcom-forensic-tools
python3 -m venv venv
source ./venv/bin/activate
pip install -r requirements.txt
```
then for example, `python pcom_client.py 1.2.3.4`

