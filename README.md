# 5G-UE-SecurityTesting

## Description

This project, **5G-UE-SecurityTesting**, is currently a work in progress. It focuses on security testing for 5G Standalone User Equipment (UE). The objective of this project is to develop a comprehensive framework for assessing the security aspects of 5G UE devices.

## Table of Contents

- [Description](#description)
- [Installation](#installation)
- [Usage](#usage)
- [License](#license)
- [Reference](#reference)

## Installation

### srsRAN
prerequisite:  sudo apt-get install build-essential cmake libfftw3-dev libmbedtls-dev libboost-program-options-dev libconfig++-dev libsctp-dev
1. cd srsRAN    
2. mkdir build    
3. cd build
4. cmake ../
5. make
6. sudo make install
   
More details on srsRAN installation can be found at: https://docs.srsran.com/projects/4g/en/latest/general/source/1_installation.html
    
### open5GS
prerequisite:  apt install python3-pip python3-setuptools python3-wheel ninja-build build-essential flex bison git cmake libsctp-dev libgnutls28-dev libgcrypt-dev libssl-dev libidn11-dev libmongoc-dev libbson-dev libyaml-dev libnghttp2-dev libmicrohttpd-dev libcurl4-gnutls-dev libnghttp2-dev libtins-dev libtalloc-dev meson libjson0 libjson0-dev
1. cd open5gs
2. meson build --prefix=`pwd`/install
3. ninja -C build
4. cd build
5. ninja install
   
More details on open5gs installation can be found at: https://open5gs.org/open5gs/docs/guide/01-quickstart/

### cJSON
1. git colne https://github.com/DaveGamble/cJSON.git
2. cd cJSON
3. mkdir build
4. cd build
5. cmake ..
6. make
7. sudo make install

### MongoDB
1. sudo apt update
2. sudo apt install -y mongodb-org
3. sudo systemctl start mongod (if '/usr/bin/mongod' is not running)
4. sudo systemctl enable mongod (ensure to automatically start it on system boot)

### NodeJS
1. sudo apt install curl
2. curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
3. sudo apt install nodejs

### Open5GS web UI
curl -fsSL https://open5gs.org/open5gs/assets/webui/install | sudo -E bash -


## Usage

### Setup

Before starting the automatic testing process, it is advised to check if all the components are working fine.

For the NAS test:
1. Run open5gs as follows: `sudo ./open5gs/build/tests/app/5gc -n /home/usr/Desktop/5G/Test_nas/test1.json`
2. Then run srsRAN: `sudo ./srsRAN/build/srsenb/src/srsenb configFiles/enb.conf`

For the RRC test:
1. Run open5gs as follows: `sudo ./open5gs/build/tests/app/5gc -n /home/usr/Desktop/5G/Test_nas/test1.json`
2. Then run srsRAN: `sudo ./srsRAN/build/srsenb/src/srsenb configFiles/enb.conf`
3. Finally, at the eNB side, `test /home/usr/Desktop/5G/Test_rrc/testcases1.json`

If these steps run properly, then the system is ready for the automation process using `handler.py`. Please note that in order to run the RRC test, it is necessary to run a NAS test as well. In this case, the NAS test1.json is executed concurrently with the RRC test.

For the automation process, connect the Android device to the PC using a USB connection and ensure that the phone is recognized as a connected device. This tutorial can be helpful: https://www.youtube.com/watch?v=GERlhgCcoBc

The program assumes Opne5gs, srsRAN, NAS test case folder, and RRC test case folder are in the same directory. In case of a different directory kindly change the path. For example:

1. For testcase directory: test_directory = `./path/to/testcase/directory` e.g., `test_directory = "./Test_nas"`
2. For srsRAN:  srsran_command = "sudo", "-S", **"./srsRAN/build/srsenb/src/srsenb"**, **"configFiles/enb.conf"** [change the bold part]
3. For open5gs: open5gs_command = "sudo", "-S", **"./open5gs/build/tests/app/5gc"**, "-n", **"./Test_nas/" + file_name + ".json"** [change the bold part]

### Options

The type of test case needs to be specified with -t flag, followed by an option either nas or rrc. For example 
`sudo python3 handler.py -t rrc`

### Execution

This program takes all the test cases and runs them one by one.The phone is toggled between airplane mode and normal mode a maximum of 5 times to establish a fresh connection with the network. As soon as "testing finished" keyword is found then it immediately completes that test case and goes for the next test case. If the keyword is not found (after 5 times toggling), then go for the next test case. When the whole round is completed it tries for the failed test case again. 

### Results

The program will create a folder (e.g., rrc_results). All logs and pcaps will be saved there. It will also create a real-time test case status log (e.g., Fri Jun 23 6:29:57 2023_RRC.txt ) where it can be seen if a test case is completed or not invoked.

## License

The **5G-UE-SecurityTesting** project is open-source. The specific license details will be provided later.

## Reference

If you are using or referencing this project, please cite the following paper:

[UE Security Reloaded: Developing a 5G Standalone User-Side Security Testing Framework](https://wisec2023.surrey.ac.uk/accepted-papers/#UE_Security_Reloaded__Developing_a_5G_Standalone_User_Side_Security_Testing_Framework)<br>
Evangelos Bitsikas, Syed Khandker, Ahmad Salous, Aanjhan Ranganathan, Roger Piqueras Jover, and Christina Pöpper<br>
16th ACM Conference on Security and Privacy in Wireless and Mobile Networks (WiSec '23), Guildford, Surrey, UK

Please note that the paper will be linked here once it is available.
