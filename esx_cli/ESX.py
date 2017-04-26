#!/usr/bin/env python

import atexit
import os
import time
from optparse import OptionParser
import click
from datetime import datetime
from colors import red, green, blue

from colorama import init
from termcolor import colored

init()
import paramiko
import sys, traceback
import cli

from termcolor import colored, cprint


def white(s):
    return s


def orange(s):
    return color(s, fg=3)


def gray(s):
    return color(s, fg=243)


def print_ok(s):
    print s


def print_fail(s):
    print red(s)


def await(condition, sleep=1):
    result = condition()
    while not result:
        result = condition()
        time.sleep(sleep)


import requests

requests.packages.urllib3.disable_warnings()

import ssl

try:
    _create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
    # Legacy Python that doesn't verify HTTPS certificates by default
    pass
else:
    # Handle target environment that doesn't support HTTPS verification
    ssl._create_default_https_context = _create_unverified_https_context

from pyVim import connect
from pyVmomi import *

esx = None
_host = None
_user = None
_password = None


@click.group()
@click.option('--host', envvar='ESX_HOST', help='or use the ESX_HOST environment variable')
@click.option('--username', default='root', envvar=['ESX_USER'], help='or use the ESX_USER environment variable')
@click.option('--password', envvar=['ESX_PASS'], help='or use the ESX_PASS environment variable')
@click.pass_context
def cli(ctx, host, username, password):
    print "%s:%s@%s" % (username, '***', host)
    global _host
    _host = host
    global _user
    _user = username
    global _password
    _password = password


def get_datacenter():
    return esx.RetrieveContent().rootFolder.childEntity[0]


def get_resource_pool():
    hosts = get_datacenter().hostFolder.childEntity
    return hosts[0].resourcePool


def get_datastore_name(datastore):
    datastores = get_obj(vim.Datastore, datastore)
    return datastores.name
    if len(datastores) == 1:
        datastore = datastores.keys()[0]

    if datastore == None or datastores[datastore] == None:
        print datastores
        print_fail("Invalid datastore " + datastore)
    return datastore


def add_nic():
    nic_spec = vim.vm.device.VirtualDeviceSpec()
    nic_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
    nic_spec.device = vim.vm.device.VirtualVmxnet3()
    nic_spec.device.backing = vim.vm.device.VirtualEthernetCard.NetworkBackingInfo()
    nic_spec.device.backing.useAutoDetect = False
    nic_spec.device.backing.network = get_network()
    nic_spec.device.backing.deviceName = get_network().name
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


def get_default_spec(name, size=50):
    spec = vim.vm.ConfigSpec()
    dev_changes = []
    scsi = add_scsi_ctr()
    dev_changes.append(scsi)
    dev_changes.append(add_disk_spec(scsi, name, size))
    dev_changes.append(add_nic())
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


@cli.command()
def prep_template(name):
    ssh("vmkfstools -K %s" % get_vmdk(find(name)))


def get_vm_path(vm):
    datastore = vm.storage.perDatastoreUsage[0].datastore.info.name
    return "[%s] %s" % (datastore, vm.layout.disk[0].diskFile[0].split(" ")[1])


@cli.command()
@click.option('--name', help='name of the new vm')
@click.option('--template', default="template", help='vm hostname')
@click.option('--size', default=50, help='vm storage size in GB')
@click.option('--datastore', default=None, help='datastore to use')
def ghetto_clone(name, template, size, datastore):
    dc = get_datacenter()
    datastore = get_datastore_name(datastore)
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
    vm = wait(vm_folder.CreateVM_Task(
        config=config, pool=get_resource_pool()), breakOnError=True)
    print_ok("Created %s\n " % vm.summary.config.vmPathName)
    vmdk = "[%s] %s/%s.vmdk" % (datastore, name, name)
    print_ok("Attaching %s \n" % vmdk)
    spec = get_default_spec(size=size, name=vmdk)
    wait(vm.ReconfigVM_Task(spec=spec), breakOnError=True)
    path = "/vmfs/volumes/%s/%s" % (datastore, name)
    vmdk = get_vmdk(find(template))
    ssh("rm %s/*.vmdk" % path)
    ssh("vmkfstools -i %s %s -d thin" %
        (vmdk, path + "/" + name + ".vmdk"))
    wait(vm.PowerOn())

    if get_ip(name) is None:
        print "[%s] waiting for ip" % name
        await(lambda: get_ip(name) is not None)
    return get_ip(name)


@cli.command()
def clone(vm):
    count = 1
    if "count" in os.environ:
        count = int(os.environ['count'])
    for i in range(0, count):
        _clone(vm)


def _clone(vm, name=None):
    template_vm = find(vm)

    if "-slave" in template_vm.name:
        print_fail("Cannot clone a slave: " + template_vm.name + "\n")
        return

    if template_vm.snapshot is None:
        print "Creating snapshot"
        task = template_vm.CreateSnapshot(
            name='packer', memory=False, quiesce=True)
        wait(task)
        template_vm = find(vm)
    else:
        print template_vm.snapshot.currentSnapshot

    if name == None:
        name = '%s-slave-%s' % (vm, datetime.now().strftime('%U-%H%M%S'))
    print "[%s] cloning from :%s " % (name, template_vm.name)
    clonespec = vim.vm.CloneSpec()
    clonespec.snapshot = template_vm.snapshot.currentSnapshot
    clonespec.powerOn = True
    clonespec.template = False
    clonespec.location = vim.VirtualMachineRelocateSpec()
    clonespec.location.diskMoveType = vim.vm.RelocateSpec.DiskMoveOptions.createNewChildDiskBacking
    task = template_vm.Clone(
        folder=template_vm.parent, name=name, spec=clonespec)
    wait(task, name)


def clone_vm(vm):
    name = os.environ["VM_NAME"]
    template_vm = find(vm)
    print "[%s] cloning from :%s " % (name, template_vm.name)
    clonespec = vim.vm.CloneSpec()
    clonespec.snapshot = template_vm.snapshot.currentSnapshot
    clonespec.powerOn = True
    clonespec.template = False
    clonespec.location = vim.VirtualMachineRelocateSpec()
    task = template_vm.Clone(
        folder=template_vm.parent, name=name, spec=clonespec)
    wait(task, name)


def ssh(cmd, host=_host):
    ssh = paramiko.SSHClient()
    ssh.load_system_host_keys()
    ssh.connect(_host, username=_user, password=_password)
    print cmd
    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(cmd)
    print ssh_stderr.readlines()
    print ssh_stdout.readlines()


def get_ip(name):
    vm = find(name)
    if vm.guest != None:
        return vm.guest.ipAddress
    return None


def wait(task, actionName='job', hideResult=False, breakOnError=False):
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
    # print info
    color = 'grey'
    if (hasattr(info, 'healthState')):
        color = info.healthState.key
    if (hasattr(info, 'status')):
        color = info.status.key

    if 'unknown' in color:
        color = 'grey'
    desc = info.name
    color = color.lower()
    if 'green' in color:
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


def get_colored_percent(percentage, factor=1):
    if percentage > 90 / factor:
        percentage = colored("%.0f%%" % percentage, 'red')
    elif percentage > 70 / factor:
        percentage = colored("%.0f%%" % percentage, 'yellow')
    else:
        percentage = colored("%.0f%%" % percentage, 'green')
    return "@ %s" % (percentage)


def get_tags(host):
    desc = ""
    for info in host.hardware.systemInfo.otherIdentifyingInfo:
        if 'OemSpecificString' in info.identifierType.key or 'unknown' in info.identifierValue:
            continue
        desc += info.identifierType.key + "=" + info.identifierValue + " "
    return desc


def get_esxi_hosts():
    global esx
    esxi_hosts = []
    for host in _host.split(" "):
        esx = connect.SmartConnect(host=host,
                                   sslContext=_create_unverified_https_context(),
                                   user=_user,
                                   pwd=_password,
                                   port=443)

        content = esx.RetrieveContent()
        esxi_hosts.append(content)
    return esxi_hosts


def get_host_view(content):
    esx = content.viewManager.CreateContainerView(content.rootFolder,
                                                  [vim.HostSystem],
                                                  True).view
    atexit.register(connect.Disconnect, esx)
    return esx


@cli.command()
def status():
    for content in get_esxi_hosts():
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


def info(host):
    vm = find(host)
    print vm.summary
    print vm.guest
    print get_vmdk(vm)


@cli.command()
@click.argument('vm')
def start(vm):
    for vm in all(vm):
        if (vm.runtime.powerState != 'poweredOn'):
            print "starting " + vm.summary.config.name
            vm.PowerOn()


@cli.command()
@click.argument('vm')
def stop(vm):
    for vm in all(vm):
        if (vm.runtime.powerState != 'poweredOff'):
            print "stopping " + vm.summary.config.name
            vm.PowerOff()


@cli.command()
@click.argument('vm')
def restart(vm):
    for vm in all(vm):
        if (vm.runtime.powerState == 'poweredOn'):
            print "stopping " + vm.summary.config.name
            wait(vm.PowerOff(), 'stop', True)
        print "starting " + vm.summary.config.name
        vm.PowerOn()


@cli.command()
@click.argument('vm')
def destroy(vm):
    for vm in all(vm):
        if (vm.runtime.powerState == 'poweredOn'):
            wait(vm.PowerOff())
        print "destroying " + vm.summary.config.name
        vm.Destroy_Task()


def datastores(name=None):
    datastores = {}
    content = esx.RetrieveContent()
    esxi_hosts = content.viewManager.CreateContainerView(content.rootFolder,
                                                         [vim.HostSystem],
                                                         True).view
    for esxi_host in esxi_hosts:
        storage_system = esxi_host.configManager.storageSystem
        host_file_sys_vol_mount_info = \
            storage_system.fileSystemVolumeInfo.mountInfo

        for host_mount_info in host_file_sys_vol_mount_info:
            if host_mount_info.volume.type == "VMFS":
                datastores[
                    host_mount_info.volume.name] = host_mount_info.mountInfo.path
    return datastores


def get_host(name):
    return get_obj(vim.HostSystem, name)


def get_network():
    content = esx.RetrieveContent()
    container = content.viewManager.CreateContainerView(
        content.rootFolder, [vim.Network], True)
    obj = None
    for c in container.view:
        obj = c

    return obj


def get_hosts():
    hosts = []
    content = esx.RetrieveContent()
    container = content.viewManager.CreateContainerView(
        content.rootFolder, [vim.HostSystem], True)
    for c in container.view:
        hosts.append(c.name)
    return str(hosts)


def get_datastore(name):
    return get_obj(vim.Datastore, name)


def get_obj(vimtype, name):
    obj = None
    content = esx.RetrieveContent()
    container = content.viewManager.CreateContainerView(
        content.rootFolder, [vimtype], True)
    for c in container.view:
        if name == None or c.name == name:
            obj = c
            break
    return obj


def convert_to_thin(vm, dir):
    cmd = string.Template("""
	vmkfstools -i $dir/$vm/disk.vmdk $dir/$vm/disk-thin.vmdk -d thin
	rm disk-flat.vmdk 
	mv disk-thin-flat.vmdk disk-flat.vmdk
	vim-cmd vmsvc/unregister `vim-cmd vmsvc/getallvms | grep $vm | cut -d " " -f 1`
	vim-cmd solo/registervm $dir/$vm/$vm.vmx
	""").substitute(vm=vm, dir=dir)
    ssh(cmd)


def find(vm):
    if isinstance(vm, vim.VirtualMachine):
        return vm

    _vm = all(vm)
    _vm = sorted(_vm, reverse=False, key=lambda vm: vm.summary.config.name)
    for vm in _vm:
        if vm.summary.guest.ipAddress is not None:
            return vm
    if len(_vm) is 0:
        return None
    return _vm[0]


def all(host=None):
    if isinstance(host, vim.VirtualMachine):
        return [host]

    list = []
    for content in get_esxi_hosts():
        children = content.rootFolder.childEntity
        for child in children:
            if hasattr(child, 'vmFolder'):
                datacenter = child
            else:
                # some other non-datacenter type object
                continue

            _appendChildren(list, datacenter.vmFolder.childEntity, host)

    return list


def _appendChildren(list, vm_list, host):
    for virtual_machine in vm_list:
        if (not isinstance(virtual_machine, vim.Folder) and (
                    host is None or host is '' or virtual_machine.summary.config.name.startswith(host))):
            list.append(virtual_machine)
        elif (isinstance(virtual_machine, vim.Folder)):
            _appendChildren(list, virtual_machine.childEntity, host)


def format_mem(mem):
    if mem is None:
        return ""
    return '{0:.2f}GB'.format(float(mem) / 1024)


def format_space(space):
    if space is None:
        return ""
    return str(space / 1024 / 1024 / 1024) + "GB"


def guest_exec(vm, cmd, args=None):
    content = esx.RetrieveContent()
    pm = content.guestOperationsManager.processManager
    print password
    creds = vim.vm.guest.NamePasswordAuthentication(username="root", password=password)
    ps = vim.vm.guest.ProcessManager.ProgramSpec(programPath=cmd, arguments="args")
    res = pm.StartProgramInGuest(vm, creds, ps)
    print res


@cli.command()
@click.argument('name')
@click.option('--size', help='size in GB of the new disk')
def extend_disk(name, size):
    size = int(size)
    vm = find(name)
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
        wait(esx.content.virtualDiskManager.ExtendVirtualDisk(name=vmdk, datacenter=None,
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
        wait(vm.ReconfigVM_Task(spec=spec))

    print "stopping %s" % vm
    vm.PowerOff()
    ssh("vmkfstools -X %sG %s" % (size - 1, get_vmdk(find(vm))))
    vm.PowerOn()
    print """
parted /dev/sda resizepart 2 100%
parted /dev/sda resizepart 2 100%
pvresize /dev/sda5
lvresize /dev/template-vg/root -l 100%VG"
resize2fs /dev/template-vg/root
    """


@cli.command()
@click.argument('vm')
@click.option('--size', help='size in GB of the RAM to allocate')
def increase_mem(vm, size):
    size = int(size)
    vm = find(vm)
    print "extending %s from %sGB to %sGB" % (vm.summary.config.name, vm.summary.config.memorySizeMB / 1024, size)
    spec = vim.vm.ConfigSpec()
    spec.memoryMB = size * 1024
    wait(vm.ReconfigVM_Task(spec=spec))


@cli.command()
@click.argument('filter', required=False)
def list(filter):
    _format = "{:40s} {:15s} {:15s} {:10s} {:15s} {:20s} {:7s} {:7s}"
    print _format.format("Name", "IP", "Mem", "State", "Storage", "Path", "Free", "Capacity")
    for virtual_machine in all(filter):
        try:

            # extend_disk(virtual_machine)
            # if 1==1:
            # return
            summary = virtual_machine.summary
            ip = ""
            if (summary.guest != None):
                ip = summary.guest.ipAddress
            storage = ""
            if summary.storage != None:
                if summary.storage.uncommitted < 1024:
                    storage = format_space(summary.storage.committed)
                else:
                    storage = "%s, thin=%s" % (
                    format_space(summary.storage.committed), format_space(summary.storage.uncommitted))
            free = ""
            capacity = ""
            extra = "";
            mem = format_mem(summary.quickStats.guestMemoryUsage) + "/" + format_mem(summary.config.memorySizeMB)
            space = ""
            if virtual_machine.guest.disk != None:

                for d in virtual_machine.guest.disk:
                    if d.diskPath == '/boot':
                        continue
                    if free is not "":
                        extra += _format.format("", "", "", "", "", d.diskPath, str(free), str(capacity))

                    free = d.freeSpace / 1024 / 1024 / 1024
                    if free < 10:
                        free = red(str(free) + "GB")
                    elif free < 20:
                        free = blue(str(free) + "GB")
                    else:
                        free = white(str(free) + "GB")
                    capacity = format_space(d.capacity)

            print _format.format(summary.config.name, ip, mem, summary.runtime.powerState, storage, "/", free,
                                 str(capacity))
            if extra is not "":
                print extra

        except Exception, e:
            traceback.print_exc(file=sys.stdout)
            pass


def register(host):
    execute_ssh(host=host, username=user, password=password,
                cmd="vim-cmd solo/registervm  '%s'" % os.environ['vm_path'])


@cli.command()
@click.pass_context
def list_clusters(ctx):
    content = esx.RetrieveContent()
    # Search for all Datastore Clusters aka StoragePod
    obj_view = content.viewManager.CreateContainerView(content.rootFolder,
                                                       [vim.StoragePod],
                                                       False)
    ds_cluster_list = obj_view.view

    for ds_cluster in ds_cluster_list:
        print ds_cluster.name
        datastores = ds_cluster.childEntity
        print "Datastores: "
        for datastore in datastores:
            print datastore.name


def main():
    cli()
    pass


if __name__ == "__main__":
    # import cli
    # cli.main()
    cli()
