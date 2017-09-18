import atexit
import os
import time
from optparse import OptionParser
import click
from datetime import datetime
from colors import red, green, blue
import paramiko
import traceback
from termcolor import colored, cprint


from pyVim import connect
from pyVmomi import *

def add_nic(network):
    nic_spec = vim.vm.device.VirtualDeviceSpec()
    nic_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
    nic_spec.device = vim.vm.device.VirtualVmxnet3()
    nic_spec.device.backing = vim.vm.device.VirtualEthernetCard.NetworkBackingInfo()
    nic_spec.device.backing.useAutoDetect = False
    nic_spec.device.backing.network = network
    nic_spec.device.backing.deviceName = network.name
    nic_spec.device.connectable = vim.vm.device.VirtualDevice.ConnectInfo()
    nic_spec.device.connectable.startConnected = True
    nic_spec.device.connectable.allowGuestControl = True
    nic_spec.device.connectable.connected = False
    nic_spec.device.connectable.status = 'untried'
    nic_spec.device.wakeOnLanEnabled = True
    return nic_spec


def add_scsi_ctr():
    scsi_ctr = vim.vm.device.VirtualDeviceSpec()
    scsi_ctr.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
    scsi_ctr.device = vim.vm.device.VirtualLsiLogicController()
    scsi_ctr.device.deviceInfo = vim.Description()
    scsi_ctr.device.slotInfo = vim.vm.device.VirtualDevice.PciBusSlotInfo()
    scsi_ctr.device.slotInfo.pciSlotNumber = 16
    scsi_ctr.device.controllerKey = 100
    scsi_ctr.device.unitNumber = 3
    scsi_ctr.device.busNumber = 0
    scsi_ctr.device.hotAddRemove = True
    scsi_ctr.device.sharedBus = 'noSharing'
    scsi_ctr.device.scsiCtlrUnitNumber = 7
    return scsi_ctr


def get_default_spec(name, network, size=50):
    spec = vim.vm.ConfigSpec()
    dev_changes = []
    scsi = add_scsi_ctr()
    dev_changes.append(scsi)
    dev_changes.append(add_disk_spec(scsi, name, size))
    dev_changes.append(add_nic(network))
    spec.deviceChange = dev_changes
    return spec


def add_disk_spec(scsi_ctr, name, size=50):
    unit_number = 0
    controller = scsi_ctr.device
    disk_spec = vim.vm.device.VirtualDeviceSpec()
    disk_spec.fileOperation = "create"
    disk_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
    disk_spec.device = vim.vm.device.VirtualDisk()
    disk_spec.device.backing = vim.vm.device.VirtualDisk.FlatVer2BackingInfo()
    disk_spec.device.backing.diskMode = 'persistent'
    disk_spec.device.backing.thinProvisioned = True
    disk_spec.device.backing.fileName = name
    disk_spec.device.unitNumber = unit_number
    disk_spec.device.capacityInKB = size * 1024 * 1024
    disk_spec.device.controllerKey = controller.key
    return disk_spec