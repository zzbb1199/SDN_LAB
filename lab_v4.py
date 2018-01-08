#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSKernelSwitch, UserSwitch
from mininet.node import IVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf
from subprocess import call

def myNetwork():

    net = Mininet( topo=None,
                   build=False,
                   ipBase='10.0.0.0/8')

    info( '*** Adding controller\n' )
    c0=net.addController(name='c0',
                      controller=RemoteController,
                      ip='127.0.0.1',
                      protocol='tcp',
                      port=6633)

    info( '*** Add switches\n')
    s4 = net.addSwitch('s4', cls=OVSKernelSwitch, dpid='0000000000000004')
    s1 = net.addSwitch('s1', cls=OVSKernelSwitch, dpid='0000000000000001')
    s2 = net.addSwitch('s2', cls=OVSKernelSwitch, dpid='0000000000000002')
    s6 = net.addSwitch('s6', cls=OVSKernelSwitch, dpid='0000000000000006')
    s5 = net.addSwitch('s5', cls=OVSKernelSwitch, dpid='0000000000000005')
    s7 = net.addSwitch('s7', cls=OVSKernelSwitch, dpid='0000000000000007')
    s8 = net.addSwitch('s8', cls=OVSKernelSwitch, dpid='0000000000000008')
    s3 = net.addSwitch('s3', cls=OVSKernelSwitch, dpid='0000000000000003')

    info( '*** Add hosts\n')
    h1 = net.addHost('h1', cls=Host, ip='10.0.0.1', defaultRoute=None)
    h2 = net.addHost('h2', cls=Host, ip='10.0.1.1', defaultRoute=None)

    info( '*** Add links\n')
    h1s1 = {'delay':'1'}
    net.addLink(h1, s1, cls=TCLink , **h1s1)
    h1s5 = {'delay':'2'}
    net.addLink(h1, s5, cls=TCLink , **h1s5)
    s4h2 = {'delay':'9'}
    net.addLink(s4, h2, cls=TCLink , **s4h2)
    s8h2 = {'delay':'10'}
    net.addLink(s8, h2, cls=TCLink , **s8h2)
    s1s2 = {'delay':'30000'}
    net.addLink(s1, s2, cls=TCLink , **s1s2)
    s2s3 = {'delay':'50000'}
    net.addLink(s2, s3, cls=TCLink , **s2s3)
    s3s4 = {'delay':'70000'}
    net.addLink(s3, s4, cls=TCLink , **s3s4)
    s5s6 = {'delay':'40000'}
    net.addLink(s5, s6, cls=TCLink , **s5s6)
    s6s7 = {'delay':'60000'}
    net.addLink(s6, s7, cls=TCLink , **s6s7)
    s7s8 = {'delay':'80000'}
    net.addLink(s7, s8, cls=TCLink , **s7s8)

    info( '*** Starting network\n')
    net.build()
    info( '*** Starting controllers\n')
    for controller in net.controllers:
        controller.start()

    info( '*** Starting switches\n')
    net.get('s4').start([c0])
    net.get('s1').start([c0])
    net.get('s2').start([c0])
    net.get('s6').start([c0])
    net.get('s5').start([c0])
    net.get('s7').start([c0])
    net.get('s8').start([c0])
    net.get('s3').start([c0])

    info( '*** Post configure switches and hosts\n')

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    myNetwork()

