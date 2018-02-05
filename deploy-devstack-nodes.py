#!/usr/bin/env python

import atexit
import argparse
import sys
import time
import ssl

from ssh_paramiko import RemoteServer

class CommandFailedException(Exception):
    def __init__(self, command):
        Exception.__init__(self, command)

def sles_only_command(command):
    platform_specific="if [ -f /etc/SuSE-release ]; then {}; fi".format(command)
    return platform_specific

def ubuntu_only_command(command):
    platform_specific="if [ -f /etc/lsb-release ]; then {}; fi".format(command)
    return platform_specific

def centos_or_redhat_only_command(command):
    platform_specific="if [ -f /etc/centos-release -o -f /etc/redhat-release ]; then {}; fi".format(command)
    return platform_specific

def centos_only_command(command):
    platform_specific="if [ -f /etc/centos-release ]; then {}; fi".format(command)
    return platform_specific

def redhat_only_command(command):
    platform_specific="if [ -f /etc/redhat-release ]; then {}; fi".format(command)
    return platform_specific

def setup_arguments():
    parser = argparse.ArgumentParser(description='Clone and configure a VM')

    # node settings
    parser.add_argument('--vm_ip', dest='VM_IP', action='store', nargs='*',
                        help='IP address to assign to the VM')
    parser.add_argument('--vm_username', dest='VM_USERNAME', action='store',
                        default='root', help='VM username, default is \"root\"')
    parser.add_argument('--vm_password', dest='VM_PASSWORD', action='store',
                        default='password', help='VM password, default is \"password\"')

    # setup options
    parser.add_argument('--devstack_tools_branch', dest='DEVSTACK_TOOLS_BRANCH', action='store',
                        default='master',
                        help='devstack-tools branch. Default is  \"master\"')

    # cinder and openstack arguments
    parser.add_argument('--openstack_release', dest='OPENSTACK_RELEASE', action='store',
                        default='master',
                        help='OpenStack Release. Default is  \"master\"')
    parser.add_argument('--cinder_repo', dest='CINDER_REPO', action='store',
                        default='http://git.openstack.org/openstack/cinder',
                        help='Cinder GIT repo, default is \"http://git.openstack.org/openstack/cinder\"')
    parser.add_argument('--cinder_branch', dest='CINDER_BRANCH', action='store',
                        help='Cinder branch, default is whatever branch is used for \"openstack_release\"')
    parser.add_argument('--tox', dest='TOX', action='store_true',
                        help='If provided, run tox [after starting Devstack, if applicable]')
    parser.add_argument('--tempest_cinder', dest='TEMPEST_CINDER', action='store_true',
                        help='If provided, run Cinder tempest tests [implies starting DevStack]')
    parser.add_argument('--tempest_nova', dest='TEMPEST_NOVA', action='store_true',
                        help='If provided, run Nova tempest tests [implies starting DevStack]')
    parser.add_argument('--devstack', dest='DEVSTACK', action='store_true',
                        help='If provided, start devstack')
    parser.add_argument('--nova_repo', dest='NOVA_REPO', action='store',
                        default='http://git.openstack.org/openstack/nova',
                        help='Nova GIT repo, default is \"http://git.openstack.org/openstack/nova\"')
    parser.add_argument('--nova_branch', dest='NOVA_BRANCH', action='store',
                        help='Nova branch, default is whatever branch is used for \"openstack_release\"')
    parser.add_argument('--ephemeral', dest='EPHEMERAL', action='store_true',
                        help='If provided, sets up Nova to use ephemeral disks on ScaleIO')

    # scaleio settings, used by cinder
    parser.add_argument('--sio_username', dest='SIO_USERNAME', action='store',
                        default='admin', help='SIO Username, default is \"admin\"')
    parser.add_argument('--sio_password', dest='SIO_PASSWORD', action='store',
                        default='Scaleio123', help='SIO Password, default is \"Scaleio123\"')
    parser.add_argument('--cinder_sio_gateway', dest='CINDER_SIO_GATEWAY', action='store', required=True,
                        help='SIO Gateway address')
    parser.add_argument('--cinder_sio_gatewayport', dest='CINDER_SIO_GATEWAYPORT', action='store',
                        default='443', help='SIO Gateway port, default is 443')
    parser.add_argument('--cinder_sio_pd', dest='CINDER_SIO_PD', action='store',
                        default='default', help='SIO Protection Domain, default is \"default\"')
    parser.add_argument('--cinder_sio_sp', dest='CINDER_SIO_SP', action='store',
                        default='default', help='SIO Storage Pool, default is \"default\"')
    parser.add_argument('--cinder_sio_mdm_ips', dest='CINDER_SIO_MDM_IPS', action='store', required=True,
                        help='SIO MDM IP addresses (comma delimited)')
    parser.add_argument('--cinder_sio_pools', dest='CINDER_SIO_POOLS', action='store',
                        help='SIO Storage Pools (comma delimited)')
    parser.add_argument('--sdc_location', dest='SDC_LOCATION', action='store',
                        help='URL to retrieve SDC installation from')

    # return the parser object
    return parser

def node_execute_command(ipaddr, username, password, command, numTries=5):
    """
    Execute a command via ssh
    """
    attempt=1
    connected = False


    while (attempt<=numTries and connected==False):
        ssh = RemoteServer(None,
                           username=username,
                           password=password,
                           log_folder='/tmp',
                           server_has_dns=False)
        print("Connecting to: %s" % (ipaddr))

        try:
            connected, err = ssh.connect_server(ipaddr, ping=False)
        except Exception as e:
            print("Unable to connect. Will try again.")
            connected = False

        if connected == False:
            time.sleep(5)
            attempt = attempt + 1

    if connected == False:
        raise UnableToConnectException(ipaddr)

    print("Executing Command: %s" % (command))
    rc, stdout, stderr = ssh.execute_cmd(command, timeout=None)
    ssh.close_connection()

    stdout = stdout.strip()
    stderr = stderr.strip()

    if rc is True:
        print("%s" % stdout)

    return rc, stdout

def node_execute_multiple(ipaddr, username, password, commands):
    for cmd in commands:
        rc, output = node_execute_command(ipaddr, username, password, cmd)

def setup_devstack(ipaddr, args):
    """
    Prepare a host to run devstack

    This includes installing some pre-reqs as well as
    cloning a git repo that configures devstack properly
    """

    # this is kind of ugly, but lets take all the provided arguments
    # and build them into environment variables that can be interpreted
    # remotely
    _all_env = ""
    for k in vars(args):
        if (getattr(args,k)) is not None:
            # print("export "+k+"=\""+str(getattr(args, k))+"\";")
            _all_env = _all_env + "export "+k+"=\""+str(getattr(args, k))+"\"\n"

    _commands = []
    _commands.append('uptime')
    _commands.append('cd /; mkdir git; chmod -R 777 /git')
    _commands.append("echo \'" + _all_env + "'\ | sort > /git/devstack.environment")
    _commands.append(ubuntu_only_command("apt-get update && apt-get install -y git"))
    _commands.append(centos_or_redhat_only_command("yum install -y git"))
    _commands.append("cd /git; git clone https://github.com/eric-young/devstack-tools.git "
                     "-b " + args.DEVSTACK_TOOLS_BRANCH)
    _commands.append("cd /git/devstack-tools; source /git/devstack.environment; "
                     "bin/setup-devstack " + ipaddr + " " + args.VM_IP[0])
    # configure the firewall so devstack can work with it
    _commands.append(centos_only_command('systemctl disable firewalld'))
    _commands.append(centos_only_command('systemctl stop firewalld'))
    # from https://docs.openstack.org/devstack/latest/guides/neutron.html
    """
    _commands.append(centos_only_command('yum install -y iptables'))
    _commands.append(centos_only_command('iptables-save'))
    _commands.append(centos_only_command('systemctl disable firewalld'))
    _commands.append(centos_only_command('systemctl enable iptables'))
    _commands.append(centos_only_command('systemctl stop firewalld'))
    _commands.append(centos_only_command('systemctl start iptables'))
    # open the ports in iptables for scaleio
    for p in [6611, 9011, 7072, 80, 443, 9099]:
        c = 'iptables -I INPUT 1 -p tcp --dport {} -j ACCEPT || true'.format(p)
        _commands.append(centos_only_command(c))
    _commands.append(centos_only_command('service iptables save'))
    """

    node_execute_multiple(ipaddr, args.VM_USERNAME, args.VM_PASSWORD, _commands)

def run_postinstall(ipaddr, args):
    """
    Perform any post-install functions

    This includes installing utilities and/or starting devstack
    """
    _commands = []
    _commands.append("cd /git; git clone https://github.com/tssgery/utilities.git")
    if args.DEVSTACK or args.TEMPEST_CINDER or args.TEMPEST_NOVA:
        _commands.append('cd /git/devstack; ./stack.sh')

    node_execute_multiple(ipaddr, 'stack', 'stack', _commands)


def run_postinstall_services_only(ipaddr, args):
    """
    Perform any post-install steps for the nodes running control plane
    """
    _commands = []
    if args.TOX:
        _commands.append('/git/devstack-tools/bin/run-tox')
    if args.TEMPEST_CINDER:
        _commands.append("source /git/devstack/openrc admin && "
                         "/git/devstack-tools/bin/run-tempest-cinder")
    if args.TEMPEST_NOVA:
        _commands.append("source /git/devstack/openrc admin && "
                         "/git/devstack-tools/bin/run-tempest-nova")

    node_execute_multiple(ipaddr, 'stack', 'stack', _commands)

def main():
    """
    Main logic
    """
    parser = setup_arguments()
    args = parser.parse_args()

    for ipaddress in args.VM_IP:
        # setup devstack on these VMs
        # note that the fist ip address will get the services
        # subsequent ip addresses will be compute only
        setup_devstack(ipaddress, args)

    # run anything that needs to be run on all hosts
    for ipaddress in args.VM_IP:
        run_postinstall(ipaddress, args)

    # run anything that gets run on first node only
    run_postinstall_services_only(args.VM_IP[0], args)

# Start program
if __name__ == "__main__":
    main()
