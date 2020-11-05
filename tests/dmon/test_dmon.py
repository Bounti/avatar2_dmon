from avatar2 import *

import sys
import os
import logging
import time
import argparse
import subprocess

import struct
import ctypes
from random import randint
# For profiling
import pstats
import numpy as np
import numpy.testing as npt

logging.basicConfig(filename='/tmp/inception-tests.log', level=logging.INFO)

GDB_PORT = 3000
firmware = "./LPC1850_WEBSERVER.elf"
dmon_stub_firmware = './DMON_ZYNQ_7020_STUB.elf'

if __name__ == '__main__':

    # start the hw_server which offers a GDBMI interface for remote debugging
    gdbserver = subprocess.Popen(
        ['hw_server', '-s TCP:localhost:%d' % GDB_PORT], shell=False
        #['xsdb', '-eval', 'xsdbserver start -host localhost -port %d' % 3121], shell=False 
    )
    time.sleep(2)

    # Initialize avatar² for ARMV7M architecture
    avatar = Avatar(arch=ARMV7M, output_directory='/tmp/xsdb-tests')
    
    # Instantiate the DMon platform
    # It takes as inputs:
    #    - the ps7 init script which is used for initializing the FPGA fabric and the zynq CPU
    #    - the system.hdf that defines the zynq memory mapping
    #    - the dmon_stub_firmware that points to the ELF of the DMon stub
    dmon_zynq_7020 = avatar.add_target(DMonTarget, "./ps7_init.tcl", "./system.hdf", dmon_stub_firmware, gdb_port=GDB_PORT, name='dmon_zynq_7020')
    
    avatar.init_targets()
    print("[*] DMon initialized")
    
    pc = dmon_zynq_7020.read_register("pc")
    npt.assert_equal(pc, 0x100a58)
    print("[*] DMon stub has initialized the MMU")

    # file ./LPC1850_WEBSERVER.elf
    dmon_zynq_7020.set_file(firmware)
    # load
    dmon_zynq_7020.download()
    print("[*] Tested firmware has been loaded on the DMon target")
    # set $pc=0x1c000115
    dmon_zynq_7020.write_register("pc", 0x1c000115)
    # b main
    ret = dmon_zynq_7020.set_breakpoint("main", hardware=True) 
    npt.assert_equal(ret, True)
    # continue
    dmon_zynq_7020.cont()
    dmon_zynq_7020.wait()
    print("[*] DMon reaches main function")
   
    dmon_zynq_7020.cont()
    print("[*] DMon running for 10 seconds")
    time.sleep(10)

    dmon_zynq_7020.stop()
    dmon_zynq_7020.shutdown()
    gdbserver.terminate()

    #Stop all threads for the profiler
    print("[*] Test completed")
    avatar.stop()

