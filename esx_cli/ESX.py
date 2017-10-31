#!/usr/bin/env python

import atexit
import os
import time
from optparse import OptionParser
import click
from datetime import datetime
from colors import red, green, blue
import string
from colorama import init
init()
import paramiko
import sys
import traceback
from utils import *
from commons import *

from termcolor import colored, cprint
import requests


from pyVim import connect
from pyVmomi import *


class ESX:
    def __init__(self, host, username, password):
        self.host = host
        self.username = username
        self.password = password
        print "%s:%s@%s" % (username, '***', host)
        self.esx = self.get_esxi_hosts()[0]

    def get_esxi_hosts(self):
        import ssl
        try:
            global _create_unverified_https_context
            _create_unverified_https_context = ssl._create_unverified_context
        except AttributeError:
            # Legacy Python that doesn't verify HTTPS certificates by default
            pass
        else:
            # Handle target environment that doesn't support HTTPS verification
            ssl._create_default_https_context = _create_unverified_https_context
        esxi_hosts = []
        for host in self.host.split(" "):
            esx = connect.SmartConnect(host=host,
                                       sslContext=_create_unverified_https_context(),
                                       user=self.username,
                                       pwd=self.password,
                                       port=443)

            content = esx.RetrieveContent()
            content.__dict__["hostname"] = host.split(".")[0]
            esxi_hosts.append(content)
        return esxi_hosts


    def get_datacenter(self):
        for esx in self.get_esxi_hosts():
            return esx.rootFolder.childEntity[0]


    def get_resource_pool(self):
        hosts = self.get_datacenter().hostFolder.childEntity
        return hosts[0].resourcePool


    def get_datastore_name(self, datastore):
        datastores = self.get_obj(vim.Datastore, datastore)
        return datastores.name
        if len(datastores) == 1:
            datastore = datastores.keys()[0]

        if datastore is None or datastores[datastore] == None:
            print datastores
            print_fail("Invalid datastore " + datastore)
        return datastore


    def ssh(self, cmd):
        ssh = paramiko.SSHClient()
        ssh.load_system_host_keys()
        ssh.connect(self.host, username=self.username, password=self.password)
        print cmd
        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(cmd)
        print ssh_stderr.readlines()
        print ssh_stdout.readlines()


    def get_ip(self, name):
        vm = self.find(name)
        if vm.guest != None:
            return vm.guest.ipAddress
        return None

    def get_host(self, name):
        return self.get_obj(vim.HostSystem, name)

    def get_network(self):
        container = self.esx.viewManager.CreateContainerView(
            self.esx.rootFolder, [vim.Network], True)
        obj = None
        for c in container.view:
            obj = c

        return obj

    def get_hosts(self):
        hosts = []
        container = self.esx.viewManager.CreateContainerView(
            self.esx.rootFolder, [vim.HostSystem], True)
        for c in container.view:
            hosts.append(c.name)
        return str(hosts)


    def get_datastore(self, name):
        return self.get_obj(vim.Datastore, name)


    def get_obj(self, vimtype, name):
        obj = None
        container = self.esx.viewManager.CreateContainerView(
            self.esx.rootFolder, [vimtype], True)
        for c in container.view:
            if name == None or c.name == name:
                obj = c
                break
        return obj

    def find(self, vm):
        if isinstance(vm, vim.VirtualMachine):
            return vm

        _vm = self.all(vm)
        _vm = sorted(_vm, reverse=False, key=lambda vm: vm.summary.config.name)
        for vm in _vm:
            if vm.summary.guest.ipAddress is not None:
                return vm
        if len(_vm) is 0:
            return None
        return _vm[0]


    def all(self, host=None):
        if isinstance(host, vim.VirtualMachine):
            return [host]

        list = []
        for content in self.get_esxi_hosts():
            children = content.rootFolder.childEntity
            for child in children:
                if hasattr(child, 'vmFolder'):
                    datacenter = child
                else:
                    # some other non-datacenter type object
                    continue

                self._appendChildren(list, datacenter.vmFolder.childEntity, host, content)

        return list

    def _appendChildren(self, list, vm_list, host, esxi):
        for virtual_machine in vm_list:
            if (not isinstance(virtual_machine, vim.Folder) and (
                        host is None or host is '' or virtual_machine.summary.config.name.startswith(host))):
                virtual_machine.__dict__["hostname"] = esxi.hostname
                list.append(virtual_machine)
            elif (isinstance(virtual_machine, vim.Folder)):
                self._appendChildren(list, virtual_machine.childEntity, host, esxi)


    def guest_exec(self, vm, cmd, args=None):
        content = self.esx
        pm = content.guestOperationsManager.processManager
        print password
        creds = vim.vm.guest.NamePasswordAuthentication(username="root", password=password)
        ps = vim.vm.guest.ProcessManager.ProgramSpec(programPath=cmd, arguments="args")
        res = pm.StartProgramInGuest(vm, creds, ps)
        print res


    def ghetto_clone(self, name, template='template', size=50, datastore=None):
        dc = self.get_datacenter()
        datastore = self.get_datastore_name(datastore)
        if datastore is None:
            return
        vm_folder = dc.vmFolder
        vmPathName = "[%s] %s" % (datastore, "")
        vmx_file = vim.vm.FileInfo(
            logDirectory=None, snapshotDirectory=None, suspendDirectory=None, vmPathName=vmPathName)

        config = vim.vm.ConfigSpec(
            name=name,
            memoryMB=1024,
            numCPUs=2,
            files=vmx_file,
            guestId="ubuntu64Guest",
            version='vmx-07'
        )

        print_ok("Creating %s on %s/%s" % (name, dc, datastore) + "\n")
        vm = wait_for(vm_folder.CreateVM_Task(
            config=config, pool=self.get_resource_pool()), breakOnError=True)
        print_ok("Created %s\n " % vm.summary.config.vmPathName)
        vmdk = "[%s] %s/%s.vmdk" % (datastore, name, name)
        print_ok("Attaching %s \n" % vmdk)
        spec = get_default_spec(size=size, name=vmdk, network=self.get_network())
        wait_for(vm.ReconfigVM_Task(spec=spec), breakOnError=True)
        path = "/vmfs/volumes/%s/%s" % (datastore, name)
        vmdk = get_vmdk(self.find(template))
        self.ssh("rm %s/*.vmdk" % path)
        self.ssh("vmkfstools -i %s %s -d thin" %
            (vmdk, path + "/" + name + ".vmdk"))
        wait_for(vm.PowerOn())

        if self.get_ip(name) is None:
            print "[%s] waiting for ip" % name
            wait(lambda: self.get_ip(name) is not None)
        print "[%s] started with ip: " % self.get_ip(name)
        return self.get_ip(name)

    def status(self):
        for content in self.get_esxi_hosts():
            host = get_host_view(content)[0]
            for health in host.runtime.healthSystemRuntime.systemHealthInfo.numericSensorInfo:
                print_status_info(health)

            print_status_info(host.runtime.healthSystemRuntime.hardwareStatusInfo.memoryStatusInfo[0])
            print_status_info(host.runtime.healthSystemRuntime.hardwareStatusInfo.cpuStatusInfo[0])

            print "%s (%s)\n\t%s\n\tCPU: %s\n\tRAM: %s" % (
            blue(host.name), content.about.fullName, get_tags(host), get_cpu_info(host), get_mem_info(host))

            datastores = content.viewManager.CreateContainerView(content.rootFolder, [vim.Datastore], True).view
            for datastore in datastores:
                summary = datastore.summary
                ds_capacity = summary.capacity
                ds_freespace = summary.freeSpace
                ds_uncommitted = summary.uncommitted if summary.uncommitted else 0
                ds_provisioned = ds_capacity - ds_freespace + ds_uncommitted
                ds_used = ds_capacity - ds_freespace
                ds_overp = ds_provisioned - ds_capacity
                ds_overp_pct = (ds_overp * 100) / ds_capacity \
                    if ds_capacity else 0
                desc = "\t{}: used {} of {}".format(summary.name, format_space(ds_used), format_space(ds_capacity))
                desc += get_colored_percent(float(ds_used) / float(ds_capacity) * 100)
                if ds_provisioned > ds_capacity:
                    desc += " %.0f%% over-provisioned" % ds_overp_pct
                print desc

    def extend_disk(self,name, size):
        size = int(size)
        vm = self.find(name)
        print "%s = %s " % (name, vm.summary.config.name)
        for d in vm.layout.disk:
            # if d.diskPath == '/boot':
            # continue
            total = vm.summary.storage.uncommitted + vm.summary.storage.committed
            new_capacity_in_kb = size * 1024 * 1024

            extend_by = new_capacity_in_kb * 1024 - total
            if extend_by < 1024:
                continue
            if (vm.runtime.powerState != 'poweredOff'):
                print "stopping " + vm.summary.config.name
                vm.PowerOff()
            vmdk = get_vm_path(vm)
            print "extending virtual disk %s from %s by %s to %s" % (
            vmdk, format_space(total), format_space(new_capacity_in_kb * 1024 - total),
            format_space(new_capacity_in_kb * 1024))
            wait_for(esx.content.virtualDiskManager.ExtendVirtualDisk(name=vmdk, datacenter=None,
                                                                  newCapacityKb=long(new_capacity_in_kb), eagerZero=False))
            print "reconfiguring %s from %s by %s to %s" % (
            vm.name, format_space(total), format_space(new_capacity_in_kb * 1024 - total),
            format_space(new_capacity_in_kb * 1024))
            virtual_disk_device = None
            for dev in vm.config.hardware.device:
                if isinstance(dev, vim.vm.device.VirtualDisk):
                    virtual_disk_device = dev
            disk_spec = vim.vm.device.VirtualDeviceSpec()
            disk_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.edit
            disk_spec.device = vim.vm.device.VirtualDisk()
            disk_spec.device.key = virtual_disk_device.key
            disk_spec.device.backing = virtual_disk_device.backing
            disk_spec.device.backing.fileName = virtual_disk_device.backing.fileName
            disk_spec.device.backing.diskMode = virtual_disk_device.backing.diskMode
            disk_spec.device.controllerKey = virtual_disk_device.controllerKey
            disk_spec.device.unitNumber = virtual_disk_device.unitNumber
            disk_spec.device.capacityInKB = long(new_capacity_in_kb)
            dev_changes = []
            dev_changes.append(disk_spec)
            spec = vim.vm.ConfigSpec()
            spec.deviceChange = dev_changes
            wait_for(vm.ReconfigVM_Task(spec=spec))

            print "stopping %s" % vm
            vm.PowerOff()
            self.ssh("vmkfstools -X %sG %s" % (size - 1, get_vmdk(find(vm))))
            vm.PowerOn()
            print """
        parted /dev/sda resizepart 2 100%
        parted /dev/sda resizepart 2 100%
        pvresize /dev/sda5
        lvresize /dev/template-vg/root -l 100%VG"
        resize2fs /dev/template-vg/root
            """

    def increase_mem(self,vm, size):
        size = int(size)
        vm = self.find(vm)
        print "extending %s from %sGB to %sGB" % (vm.summary.config.name, vm.summary.config.memorySizeMB / 1024, size)
        spec = vim.vm.ConfigSpec()
        spec.memoryMB = size * 1024
        wait_for(vm.ReconfigVM_Task(spec=spec))


    def list(self, filter, format):
        columns = [
            {"name": "host"},
            {"name": "name"},
            {"name": "ip"},
            {"name": "state"},
            {"name": "mem", "type": "size"},
            {"name": "mem_usage", "type": "size"},
            {"name": "storage", "type": "size"},
            {"name": "storage_thin", "type": "size"},
            {"name": "disk_path"},
            {"name": "disk_free", "type": "size"},
            {"name": "disk_capacity", "type": "size"}
        ]
        table = Table.new(format, columns)
        table.begin()
        for vm in self.list_vms(filter, table):
            table.append(vm)
            table.print_frame()
        table.end()



    def list_vms(self, filter, status):
        for virtual_machine in self.all(filter):
            try:
                summary = virtual_machine.summary
                details = {
                    "host": virtual_machine.hostname,
                    "name": virtual_machine.name,
                    "ip": summary.guest.ipAddress if summary.guest is not None else "",
                    "mem": summary.config.memorySizeMB * MB,
                    "mem_usage": summary.quickStats.guestMemoryUsage * MB if summary.quickStats.guestMemoryUsage is not None else "",
                    "storage":  summary.storage.committed if summary.storage is not None else "",
                    "storage_thin": summary.storage.uncommitted if summary.storage is not None else "",
                    "state": summary.runtime.powerState
                }
                if virtual_machine.guest.disk is not None:
                    for d in virtual_machine.guest.disk:
                        if d.diskPath == '/boot':
                            continue
                        if "disk_path" in details:
                            yield  {"disk_path": d.diskPath,
                                    "disk_capacity":  d.capacity,
                                    "disk_free": d.freeSpace}
                        else:
                            details["disk_path"] = d.diskPath
                            details["disk_capacity"] = d.capacity
                            details["disk_free"] = d.freeSpace
                            yield details
                else:
                    yield details
            except Exception, e:
                traceback.print_exc(file=sys.stdout)
                pass


    def info(self, host):
        vm = self.find(host)
        print vm.summary
        print vm.guest
        print get_vmdk(vm)

    def start(self,vm):
        for vm in self.all(vm):
            if (vm.runtime.powerState != 'poweredOn'):
                print "starting " + vm.summary.config.name
                vm.PowerOn()

    def stop(self, vm):
        for vm in self.all(vm):
            if (vm.runtime.powerState != 'poweredOff'):
                print "stopping " + vm.summary.config.name
                vm.PowerOff()


    def restart(self,vm):
        for vm in self.all(vm):
            if (vm.runtime.powerState == 'poweredOn'):
                print "stopping " + vm.summary.config.name
                wait_for(vm.PowerOff(), 'stop', True)
            print "starting " + vm.summary.config.name
            vm.PowerOn()


    def destroy(self,vm, count):
        vms = self.all(vm)
        for vm in vms:
                print vm.name

        if len(vms) != count:
            print_fail("%s vm's filtered for deletion, %s authorised" % (len(vms), count))
            return

        print "Deleting %s vm's" % len(vms)
        time.sleep(2)

        for vm in vms:
            if (vm.runtime.powerState == 'poweredOn'):
                wait_for(vm.PowerOff())
            print "destroying " + vm.summary.config.name
            vm.Destroy_Task()


    def prep_template(self, host):
        vm = self.find(host)
        vmdk = get_vmdk(vm)
        cmd = string.Template("""
    vmkfstools -i $vmdk $vmdk-thin -d thin
    rm $vmdk
    mv $vmdk-thin $vmdk
        """).substitute(vmdk=vmdk, vm=vm.summary.config.name, vmx=vm.summary.config.vmPathName)
        self.ssh(cmd)


def get_vm_path(vm):
    datastore = vm.storage.perDatastoreUsage[0].datastore.info.name
    return "[%s] %s" % (datastore, vm.layout.disk[0].diskFile[0].split(" ")[1])


def wait_for(task, actionName='job', hideResult=False, breakOnError=False):
    while task.info.state == vim.TaskInfo.State.running:
        time.sleep(2)

    if task.info.state == vim.TaskInfo.State.success:
        if task.info.result is not None and not hideResult:
            print_ok('%s completed successfully, result: %s' %
                     (actionName, task.info.result))
        else:
            print_ok('%s completed successfully.' % actionName)
        return task.info.result
    else:

        if breakOnError:
            raise task.info.error
        else:
            print_fail('%s did not complete successfully: %s' %
                       (actionName, task.info.error))
        return task.info.result

def get_vmdk(vm):
    return vm.storage.perDatastoreUsage[0].datastore.info.url + "/" + vm.layout.disk[0].diskFile[0].split(" ")[1]

def print_status_info(info):
    if not hasattr(info, 'name'):
        return
    color = 'grey'
    if (hasattr(info, 'healthState')):
        color = info.healthState.key
    if (hasattr(info, 'status')):
        color = info.status.key

    if 'unknown' in color:
        color = 'grey'
    desc = info.name
    color = color.lower()
    if 'green' in color or 'grey' in color:
        return
    if hasattr(info, 'currentReading') and info.currentReading > 0:
        desc += " %.0f %s" % (10 ** info.unitModifier * info.currentReading, info.baseUnits)
    print colored(desc, color)

def get_cpu_info(host):
    cpuName = host.hardware.cpuPkg[0].description
    cpuName = cpuName.replace('Intel(R) Xeon(R) CPU', '').replace(' ', '')

    stats = host.summary.quickStats
    if stats.overallCpuUsage is None:
        return colored(cpuName, 'red')
    hardware = host.hardware
    cpuTotal = host.hardware.cpuPkg[0].hz / 1024 / 1024 * len(host.hardware.cpuPkg[0].threadId)
    cpuUsage = 100 * stats.overallCpuUsage / cpuTotal
    return "%s %s" % (cpuName, get_colored_percent(cpuUsage, 2))


def get_mem_info(host):
    stats = host.summary.quickStats
    memoryCapacity = host.hardware.memorySize
    if stats.overallMemoryUsage is None:
        return None
    memoryUsage = stats.overallMemoryUsage * 1024 * 1024
    percentage = (
        (float(memoryUsage) / memoryCapacity) * 100
    )
    return "%s %s" % (format_space(memoryCapacity), get_colored_percent(percentage))


def get_tags(host):
    desc = ""
    for info in host.hardware.systemInfo.otherIdentifyingInfo:
        if 'OemSpecificString' in info.identifierType.key or 'unknown' in info.identifierValue:
            continue
        desc += info.identifierType.key + "=" + info.identifierValue + " "
    return desc


def get_host_view(content):
    esx = content.viewManager.CreateContainerView(content.rootFolder,
                                                  [vim.HostSystem],
                                                  True).view
    atexit.register(connect.Disconnect, esx)
    return esx




