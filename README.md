# 5G-UE-SecurityTesting

## Description

This project, **5G-UE-SecurityTesting**, is currently a work in progress. It focuses on security testing for 5G Standalone User Equipment (UE). The objective of this project is to develop a comprehensive framework for assessing the security aspects of 5G UE devices.

## Table of Contents

- [Description](#description)
- [Installation](#installation)
- [Usage](#usage)
[//]:- [Testcase](#testcase)
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
3. Finally, at the eNB side, `test /home/usr/Desktop/5G/Test_rrc/testcases1.json` (On the terminal, after a complete gNB initialization)

If these steps run properly, then the system is ready for the automation process using `handler.py`. Please note that in order to run the RRC test, it is necessary to run a NAS test as well. In this case, the NAS test1.json is executed concurrently with the RRC test, but NAS test1.json can be a dummy testcase.

For the automation process, connect the Android device to the PC using a USB connection and ensure that the phone is recognized as a connected device. This tutorial can be helpful: https://www.youtube.com/watch?v=GERlhgCcoBc

The program assumes Open5gs, srsRAN, NAS test case folder, and RRC test case folder are in the same directory. In case of a different directory kindly change the path. For example:

1. For testcase directory: test_directory = `./path/to/testcase/directory` e.g., `test_directory = "./Test_nas"`
2. For srsRAN:  srsran_command = "sudo", "-S", **"./srsRAN/build/srsenb/src/srsenb"**, **"configFiles/enb.conf"** [change the bold part]
3. For open5gs: open5gs_command = "sudo", "-S", **"./open5gs/build/tests/app/5gc"**, "-n", **"./Test_nas/" + file_name + ".json"** [change the bold part]

In this repository we provide sample testcases for NAS and RRC. The parameters and names are selected according to our definitions in the modified messages in the files: nas-path.c (Open5GS) and rrc_nr_ue.cc (srsRAN).

### Options

The type of test case needs to be specified with -t flag, followed by an option either nas or rrc. For example 
`sudo python3 handler.py -t rrc`

### Execution

This program takes all the test cases and runs them one by one.The phone is toggled between airplane mode and normal mode a maximum of 5 times to establish a fresh connection with the network. As soon as "testing finished" keyword is found then it immediately completes that test case and goes for the next test case. If the keyword is not found (after 5 times toggling), then go for the next test case. When the whole round is completed it tries for the failed test case again. 

### Results

The program will create a folder (e.g., rrc_results). All logs and pcaps will be saved there. It will also create a real-time test case status log (e.g., Fri Jun 23 6:29:57 2023_RRC.txt ) where it can be seen if a test case is completed or not invoked.

[//]:## Testcase Generation

[//]:Some sample testcases are provided in the repository. We are currently developing a test case generation tool, which is under construction, can be found at https://github.com/MicheleGuerra/5G-UE-Test-suite-generator.

## License

The **5G-UE-SecurityTesting** project is open-source.

## Reference

If you are using or referencing this project, please cite the following paper:

<blockquote style="background-color: #f7f7f7; padding: 10px; border-left: 6px solid #1f618d;">

<pre>
@inproceedings{bitsikas23UEframework,
  <span style="color: #c0392b;">title = {UE Security Reloaded: Developing a 5G Standalone User-Side Security Testing Framework},</span>
  <span style="color: #2980b9;">author = {Bitsikas, Evangelos and Khandker, Syed and Salous, Ahmad and Ranganathan, Aanjhan and Piqueras Jover, Roger and Pöpper, Christina},</span>
  <span style="color: #27ae60;">booktitle = {Proceedings of the 16th ACM Conference on Security and Privacy in Wireless and Mobile Networks},</span>
  <span style="color: #8e44ad;">year = {2023},</span>
  <span style="color: #e67e22;">url = {https://doi.org/10.1145/3558482.3590194}</span>
}
</pre>
</blockquote>
