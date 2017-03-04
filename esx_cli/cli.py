#!/usr/bin/env python

import atexit
import os, sys
import time
from optparse import OptionParser
from datetime import datetime
from colors import red, green, blue
# import clicl
# from ESX import ESX
from termcolor import colored, cprint


def main():
    parser = OptionParser()

    parser.add_option("-e", "--esx", dest="esx")
    parser.add_option("-s", "--start", dest="start")
    parser.add_option("-t", "--stop", dest="stop")
    parser.add_option("-l", "--list", dest="list")
    parser.add_option("-i", "--info", dest="info")

    parser.add_option("-d", "--destroy", dest="destroy")

    parser.add_option("-c", "--clone", dest="clone")

    parser.add_option("-p", "--prep", dest="prep",
                      help="Prep a new template VM. i.e. cleanup DHCP, zero and punch free disk space")
    parser.add_option("-m", "--template", dest="template")

    parser.add_option(
        "-g", "--size", dest="size", help="Disk size in GB, defaults to 50GB")

    parser.add_option("-z", "--datastore", dest="datastore")

    parser.add_option(
        '-a', "--action", help="stop,start,list,destroy,clone,clone_vm,register,datastores", dest="action")

    (options, args) = parser.parse_args()

    if options.esx is None:
        print red("Missing esx host e.g. --esx esx-host.local")
        sys.exit(1)
    client = ESX(options.esx)

    if (options.list != None):
        client.list(options.list)

    if options.start != None:
        client.start(options.start)

    if options.stop != None:
        client.stop(options.stop)

    if options.destroy != None:
        client.destroy(options.destroy)

    if options.prep != None:
        client.prep_template(options.prep)

    if options.info != None:
        client.info(options.info)

    if options.clone != None:
        if options.template == None:
            print_fail("Must specify a --template")
        else:
            if options.size == None:
                options.size = 50
            else:
                options.size = int(options.size)
            client.ghetto_clone(
                options.clone, options.template, options.datastore, options.size)

    if options.action != None:
        print getattr(client, options.action)("")



if __name__ == "__main__":
    cli.main()
