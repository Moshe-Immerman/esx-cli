#!/usr/bin/env python

import click
from ESX import ESX


esx = None

@click.group()
@click.option('--host', envvar='ESX_HOST', help='or use the ESX_HOST environment variable')
@click.option('--username', default='root', envvar=['ESX_USER'], help='or use the ESX_USER environment variable')
@click.option('--password', envvar=['ESX_PASS'], help='or use the ESX_PASS environment variable')
@click.pass_context
def cli(ctx, host, username, password):
    global esx
    esx = ESX(host, username, password)

@cli.command()
@click.option('--name', help='name of the new vm')
@click.option('--template', default="template", help='vm hostname')
@click.option('--size', default=50, help='vm storage size in GB')
@click.option('--datastore', default=None, help='datastore to use')
def ghetto_clone(name, template, size, datastore):
    esx.ghetto_clone(name, template, size, datastore)

@cli.command()
def status():
    esx.status()


@cli.command()
@click.argument('name')
@click.option('--size', help='size in GB of the new disk')
def extend_disk(name, size):
    esx.extend_disk(name, size)


@cli.command()
@click.argument('vm')
@click.option('--size', help='size in GB of the RAM to allocate')
def increase_mem(vm, size):
    esx.increase_mem(vm, size)


@cli.command()
@click.argument('filter', required=False)
@click.option('--format', default="pretty", help="pretty, json or CSV")
def list(filter, format):
    print "listing"
    esx.list(filter, format)


@cli.command()
@click.argument('host')
def info(host):
    esx.info(host)


@cli.command()
@click.argument('vm')
def start(vm):
    esx.start(vm)


@cli.command()
@click.argument('vm')
def stop(vm):
    esx.stop(vm)


@cli.command()
@click.argument('vm')
def restart(vm):
    esx.restart(vm)


@cli.command()
@click.argument('vm')
@click.option('--count', default=1, help='the total number of vms delete')
def destroy(vm, count):
    esx.destroy(vm, count)


@cli.command()
@click.argument('host')
def prep_template(host):
    esx.prep_template(host)


def main():
    cli()
    pass


if __name__ == "__main__":
    cli()
