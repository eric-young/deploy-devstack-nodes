#!/usr/bin/env python

import atexit
import argparse
import sys
import time
import ssl
from ssh import ssh


def setup_arguments():
    parser = argparse.ArgumentParser(description='Clone and configure a VM')

    # node settings
    parser.add_argument('--vm_ip', dest='VM_IP', action='store', nargs='*',
                        help='IP address to assign to the VM')
    parser.add_argument('--vm_username', dest='VM_USERNAME', action='store',
                        default='root', help='VM username, default is \"root\"')
    parser.add_argument('--vm_password', dest='VM_PASSWORD', action='store',
                        default='password', help='VM password, default is \"password\"')

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
    parser.add_argument('--cinder_sio_pd', dest='CINDER_SIO_PD', action='store',
                        default='default', help='SIO Protection Domain, default is \"default\"')
    parser.add_argument('--cinder_sio_sp', dest='CINDER_SIO_SP', action='store',
                        default='default', help='SIO Storage Pool, default is \"default\"')
    parser.add_argument('--cinder_sio_mdm_ips', dest='CINDER_SIO_MDM_IPS', action='store', required=True,
                        help='SIO MDM IP addresses (comma delimted)')


    # return the parser object
    return parser

def node_execute_command(ipaddr, username, password, command, numTries=60):
    """
    Execute a command via ssh
    """
    print("Executing Command against %s: %s" % (ipaddr, command))
    connection = ssh(ipaddr, username, password, numTries=numTries)
    output = connection.sendCommand(command, showoutput=True)
    return

def node_execute_multiple(ipaddr, username, password, commands):
    for cmd in commands:
        node_execute_command(ipaddr, username, password, cmd)

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
    _commands.append("( apt-get update && apt-get install -y git ) || yum install -y git")
    _commands.append("cd /git; git clone https://github.com/eric-young/devstack-tools.git")
    _commands.append("cd /git/devstack-tools; source /git/devstack.environment; "
                     "bin/setup-devstack " + ipaddr + " " + args.VM_IP[0])

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

    node_execute_multiple(ipaddr, args.VM_USERNAME, args.VM_PASSWORD, _commands)


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

    node_execute_multiple(ipaddr, args.VM_USERNAME, args.VM_PASSWORD, _commands)

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
