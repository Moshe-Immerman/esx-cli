from AWS import *
from AWS import IAM
from ESX import ESX
from Hosts import *
from Cloudflare import *


dns = Cloudflare()
iam = IAM()
hosts = Hosts()
# if ("ESX_HOST" in os.environ):
#     esx = ESX(os.environ["ESX_HOST"], "root", os.environ['ESX_PASS'])
# else:
#     esx = ESX("vcenter-park.papertrail.co.za", "root", os.environ['ESX_PASS'])
aws = EC2()

version = "nightly"
if "VERSION" in os.environ:
    version = os.environ["VERSION"]

def restore(instance, host, instance_type):    
    details = hosts.get(instance.dns)
    instance.license = details['license']
    instance.access_key = details['access_key']
    instance.secret_key = details['secret_key']
    instance.bucket = details['bucket']
    # instance.install_encryption_key()
    instance.deploy(version=version)
    instance.wait_for()
    instance.restore()
    instance.add_dns(dns)

def install(instance, host, instance_type):
    data = {}
    instance.generate_license()
    if instance_type == 'production' or instance_type == 'secure':
        instance.generate_keys(iam)
        data = {
                "host": instance.name,
                "access_key": instance.access_key,
                "secret_key": instance.secret_key,
                "bucket": instance.bucket,
                "license": instance.license
        }
        if instance_type == 'secure':
            instance.install_encryption_key()
            data['encrypt_key'] = instance.encrypt_key

        instance.deploy(version=version)
    instance.wait_for()
    instance.install()
    instance.add_dns(dns)
    if instance_type == 'production' or instance_type == 'secure':
        hosts.add(data)


def migrate(instance, host, options):
    instance.deploy(async=True)
    live = Client("http://%s.papertrail.co.za" % host)
    instance.license = live.get_properties()['license']
    cloud_store = live.get_store('Cloud Store')
    instance.access_key = cloud_store['properties']['accessKey']
    instance.secret_key = cloud_store['properties']['secretKey']
    instance.bucket = cloud_store['properties']['bucket']
    live.change_mode('Maintenance')
    live.db_backup()
    live.fs_backup()
    instance.wait_for()
    instance.restore()
    live.shutdown()
    instance.add_dns(dns)


if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option(
        "-d", "--deploy", dest="deploy",  action="store_true", help="Deploy a new papertrail instance")
    parser.add_option(
        "-o", "--host", dest="host",   help="The hostname of the current/new instance e.g. instance")
    parser.add_option(
        "-m", "--migrate", dest="migrate",  action="store_true", help="Migrate an instance from it's current location to another cloud without any data loss")
    parser.add_option(
        "-e", "--restore", dest="restore",  action="store_true", help="Migrate an instance from it's current location to another cloud from the last backup")
   
    parser.add_option("-a", "--aws", dest="aws", action="store_true" ,help="Deploy to AWS region e.g. eu-west-1")
    parser.add_option("-v", "--esx", dest="esx", help="Deploy to ESX hosted tier e.g. tier1,tier2,tier3")
    parser.add_option("-t", "--test", dest="test", action="store_true", help="Deploy a test instance only with no backups")
    parser.add_option("-b", "--bare", dest="bare", action="store_true", help="Deploy a bare instance with no papertrail installed")
    parser.add_option("-s", "--secure", dest="secure", action="store_true", help="Encrypt the file repository")
   
    (options, args) = parser.parse_args()

    instance_type = 'production'
    if options.test:
        instance_type = 'test'
    if options.bare:
        instance_type = 'bare'
    if options.secure:
        instance_type = 'secure'



    if options.aws:
        print "[AWS] deploying %s %s.papertrail.co.za" % (instance_type, options.host)
        instance = aws.deploy(options.host)
    else:
        print "[ESX] deploying %s %s.papertrail.co.za" % (instance_type, options.host)

        esx = ESX(options.esx, "root", os.environ['ESX_PASS'])
        vm = esx.find(options.host)
        ip = None
        if vm == None:
            ip = esx.ghetto_clone(options.host)
        else:
            ip = esx.get_ip(options.host)
        instance = Instance(options.host, ip)


    if instance_type == 'bare' or instance_type == 'check':
        instance.ansible.base()
        instance.add_dns(dns)
        exit(0)
        
    if options.migrate:
        migrate(instance, options.host, instance_type)
    elif options.restore:
        restore(instance, options.host, instance_type)
    else:
        install(instance, options.host, instance_type)
