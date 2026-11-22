#!/usr/bin/env python3
"""
Topologie Mininet du projet : firewall SDN dynamique avec Machine Learning.

La topologie est entierement decrite dans config/reseau.json (switches, DPID,
VLAN, liens, ports, hotes). Ce script ne fait que lire ce fichier et construire
le reseau. Les applications Ryu lisent le meme fichier : il n'y a qu'une seule
source de verite.

    S-Coeur (L3) ── nat0 ── Internet
     │   │   └── att1 (VLAN 99, attaquant externe)
     │   │
    DIST1 ══ DIST2          (double lien : EtherChannel po1, ou STP en repli)
     │        ├── srv1  (VLAN 50, web)
    S-ACC     └── srv2  (VLAN 50, DNS)
     ├── tel1, tel2  (VLAN 20, voix)
     ├── inv1, inv2  (VLAN 30, invites ; inv2 = malveillant)
     └── emp1, emp2  (VLAN 40, employes)

Utilisation :
    sudo python3 topologie.py                  # construit le reseau et ouvre la CLI
    sudo python3 topologie.py --sans-nat       # sans acces Internet
    sudo python3 topologie.py --sans-services  # sans demarrer le web et le DNS
    python3 topologie.py --verifier            # verifie la config, sans rien lancer

IMPORTANT : le double lien DIST1 = DIST2 et le triangle Coeur/DIST1/DIST2
forment des boucles. Lancer le controleur Ryu (STP) AVANT de faire des pings.
Sans controleur, les switches (fail-mode secure) ne transmettent rien, il n'y
a donc pas de tempete de broadcast.
"""

import argparse
import ipaddress
import json
import os
import sys

CONFIG_PAR_DEFAUT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 'reseau.json')


# ---------------------------------------------------------------------------
# Lecture et verification de la configuration
# ---------------------------------------------------------------------------

def charger_config(chemin):
    with open(chemin, encoding='utf-8') as f:
        return json.load(f)


def verifier_config(cfg):
    """Retourne la liste des erreurs trouvees dans la configuration."""
    erreurs = []
    switches = cfg['switches']
    vlans = cfg['vlans']
    ports_utilises = {nom: {} for nom in switches}

    def reserver(sw, port, usage):
        if sw not in switches:
            erreurs.append("%s : switch inconnu '%s'" % (usage, sw))
            return
        if port in ports_utilises[sw]:
            erreurs.append("%s : port %s de %s deja utilise par %s"
                           % (usage, port, sw, ports_utilises[sw][port]))
        else:
            ports_utilises[sw][port] = usage

    # DPID uniques et au bon format
    dpids = [s['dpid'] for s in switches.values()]
    if len(set(dpids)) != len(dpids):
        erreurs.append('Deux switches ont le meme DPID')
    for nom, s in switches.items():
        if len(s['dpid']) != 16:
            erreurs.append('%s : le DPID doit faire 16 caracteres hexadecimaux' % nom)

    # Liens entre switches
    for lien in cfg['liens']:
        usage = 'lien %s-%s' % (lien['a'], lien['b'])
        reserver(lien['a'], lien['port_a'], usage)
        reserver(lien['b'], lien['port_b'], usage)
        agg = lien.get('agregation')
        if agg and agg not in cfg.get('agregations', {}):
            erreurs.append("%s : agregation '%s' non declaree" % (usage, agg))

    # Coherence des agregations avec les liens
    for nom_agg, agg in cfg.get('agregations', {}).items():
        for sw, ports in agg['membres'].items():
            for p in ports:
                if not ports_utilises.get(sw, {}).get(p, '').startswith('lien'):
                    erreurs.append('%s : le port %s de %s ne correspond a aucun lien'
                                   % (nom_agg, p, sw))

    # Hotes
    for nom, h in cfg['hotes'].items():
        reserver(h['switch'], h['port'], 'hote %s' % nom)
        vlan = str(h['vlan'])
        if vlan not in vlans:
            erreurs.append('hote %s : VLAN %s non declare' % (nom, vlan))
            continue
        reseau = ipaddress.ip_network(vlans[vlan]['reseau'])
        if ipaddress.ip_address(h['ip']) not in reseau:
            erreurs.append('hote %s : %s hors du reseau %s du VLAN %s'
                           % (nom, h['ip'], reseau, vlan))
        if len(nom) > 8:
            erreurs.append('hote %s : nom trop long (8 caracteres max)' % nom)

    # Passerelles dans leur reseau
    for vid, v in vlans.items():
        if ipaddress.ip_address(v['passerelle']) not in ipaddress.ip_network(v['reseau']):
            erreurs.append('VLAN %s : passerelle hors du reseau' % vid)

    # NAT
    nat = cfg.get('nat', {})
    if nat.get('active'):
        reserver(nat['switch'], nat['port'], 'nat0')

    return erreurs


def mac_depuis_ip(ip):
    """10.1.20.1 -> 00:00:0a:01:14:01 (adresse MAC lisible et unique)."""
    return '00:00:' + ':'.join('%02x' % int(o) for o in ip.split('.'))


def prefixe(vlan_cfg):
    return ipaddress.ip_network(vlan_cfg['reseau']).prefixlen


# ---------------------------------------------------------------------------
# Construction du reseau
# ---------------------------------------------------------------------------

def construire_reseau(cfg, avec_nat=True):
    # Imports Mininet ici pour que --verifier fonctionne sans Mininet ni root
    from mininet.link import TCLink
    from mininet.net import Mininet
    from mininet.node import Host, OVSSwitch, RemoteController
    from mininet.nodelib import NAT
    from mininet.log import info

    class VLANHost(Host):
        """Hote dont l'interface est taguee 802.1Q (comme dans le RyuBook, ch. 10-11)."""

        def config(self, vlan=None, passerelle=None, **params):
            r = super(VLANHost, self).config(**params)
            if vlan is None:
                return r
            intf = self.defaultIntf()
            ip = params['ip']
            self.cmd('ip addr flush dev %s' % intf)
            sortie = self.cmd('ip link add link %s name %s.%d type vlan id %d'
                              % (intf, intf, vlan, vlan))
            if 'Error' in sortie or 'Unknown' in sortie:
                raise RuntimeError(
                    "%s : impossible de creer l'interface VLAN %d (%s). "
                    "Le module noyau 8021q est-il charge ? -> sudo modprobe 8021q"
                    % (self.name, vlan, sortie.strip()))
            self.cmd('ip addr add %s dev %s.%d' % (ip, intf, vlan))
            self.cmd('ip link set dev %s.%d up' % (intf, vlan))
            # Mininet doit desormais utiliser l'interface VLAN
            intf.name = '%s.%d' % (intf, vlan)
            self.nameToIntf[intf.name] = intf
            if passerelle:
                self.cmd('ip route add default via %s dev %s' % (passerelle, intf))
            return r

    net = Mininet(controller=None, switch=OVSSwitch, link=TCLink,
                  autoSetMacs=False, build=False)

    ctrl = cfg['controleur']
    net.addController('c0', controller=RemoteController,
                      ip=ctrl['ip'], port=ctrl['port'])

    # Switches (OpenFlow 1.3, DPID fixes pour que Ryu reconnaisse chaque role)
    sw = {}
    for nom, s in cfg['switches'].items():
        sw[nom] = net.addSwitch(nom, dpid=s['dpid'], protocols='OpenFlow13',
                                failMode='secure')

    # Liens entre switches (ports fixes : ils sont references dans la config)
    for lien in cfg['liens']:
        net.addLink(sw[lien['a']], sw[lien['b']],
                    port1=lien['port_a'], port2=lien['port_b'],
                    bw=lien.get('debit', 100))

    # Hotes tagues dans leur VLAN
    for nom, h in cfg['hotes'].items():
        v = cfg['vlans'][str(h['vlan'])]
        hote = net.addHost(nom, cls=VLANHost,
                           ip='%s/%d' % (h['ip'], prefixe(v)),
                           mac=mac_depuis_ip(h['ip']),
                           vlan=h['vlan'], passerelle=v['passerelle'])
        net.addLink(hote, sw[h['switch']], port2=h['port'], bw=100)

    # Passerelle NAT vers Internet (lien non tague vers S-Coeur)
    nat_node = None
    nat = cfg.get('nat', {})
    if avec_nat and nat.get('active'):
        info('*** Ajout de la passerelle NAT\n')
        nat_node = net.addHost('nat0', cls=NAT, inNamespace=False,
                               subnet=nat['reseau_global'], ip=nat['ip_nat'])
        net.addLink(nat_node, sw[nat['switch']], port2=nat['port'])

    net.build()
    net.start()

    # Retour vers les VLAN : nat0 passe par l'interface de transit de S-Coeur
    if nat_node:
        nat_node.cmd('ip route replace %s via %s dev %s'
                     % (nat['reseau_global'], nat['ip_coeur'],
                        nat_node.defaultIntf()))

    return net


def demarrer_services(net, cfg):
    from mininet.log import info
    for nom, h in cfg['hotes'].items():
        service = h.get('service')
        hote = net.get(nom)
        if service == 'web':
            info('*** %s : serveur web sur le port 80\n' % nom)
            hote.cmd('cd /tmp && python3 -m http.server 80 '
                     '> /tmp/%s-web.log 2>&1 &' % nom)
        elif service == 'dns':
            if hote.cmd('which dnsmasq').strip():
                info('*** %s : serveur DNS (dnsmasq -> 8.8.8.8)\n' % nom)
                hote.cmd('dnsmasq --conf-file=/dev/null --no-resolv '
                         '--server=8.8.8.8 --listen-address=%s --bind-interfaces '
                         '--pid-file=/tmp/%s-dns.pid --log-facility=/tmp/%s-dns.log'
                         % (h['ip'], nom, nom))
            else:
                info('*** %s : dnsmasq absent (sudo apt install dnsmasq-base), '
                     'DNS non demarre\n' % nom)


def arreter_services(net, cfg):
    for nom, h in cfg['hotes'].items():
        if h.get('service') == 'web':
            net.get(nom).cmd('pkill -f "http.server 80"')
        elif h.get('service') == 'dns':
            net.get(nom).cmd('[ -f /tmp/%s-dns.pid ] && kill $(cat /tmp/%s-dns.pid)'
                             % (nom, nom))


# ---------------------------------------------------------------------------
# Affichage
# ---------------------------------------------------------------------------

def afficher_resume(cfg, avec_nat=True):
    print('\n=== Switches ===')
    print('%-7s %-18s %-4s %-8s %s' % ('Nom', 'DPID', 'Role', 'Prio STP', 'Description'))
    for nom, s in cfg['switches'].items():
        print('%-7s %-18s %-4s %-8s %s' % (nom, s['dpid'], s['role'],
                                           s['priorite_stp'], s['description']))

    print('\n=== Liens entre switches ===')
    for l in cfg['liens']:
        agg = ('  [%s]' % l['agregation']) if l.get('agregation') else ''
        print('%s:%s <-> %s:%s  (%s Mbit/s)%s' % (l['a'], l['port_a'], l['b'],
                                                  l['port_b'], l.get('debit', 100), agg))

    print('\n=== Hotes ===')
    print('%-6s %-5s %-12s %-14s %-9s %s' % ('Nom', 'VLAN', 'IP', 'Passerelle',
                                             'Port', 'Role'))
    for nom, h in cfg['hotes'].items():
        v = cfg['vlans'][str(h['vlan'])]
        print('%-6s %-5s %-12s %-14s %-9s %s' % (nom, h['vlan'], h['ip'],
                                                 v['passerelle'],
                                                 '%s:%s' % (h['switch'], h['port']),
                                                 h['role']))
    nat = cfg.get('nat', {})
    if avec_nat and nat.get('active'):
        print('\nnat0 : %s sur %s:%s (transit %s, S-Coeur = %s)'
              % (nat['ip_nat'], nat['switch'], nat['port'],
                 nat['reseau_transit'], nat['ip_coeur']))
    print()


# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description='Topologie Mininet du projet')
    parser.add_argument('--config', default=CONFIG_PAR_DEFAUT,
                        help='fichier de configuration (defaut : config/reseau.json)')
    parser.add_argument('--sans-nat', action='store_true',
                        help="ne pas creer la passerelle Internet")
    parser.add_argument('--sans-services', action='store_true',
                        help='ne pas demarrer les serveurs web et DNS')
    parser.add_argument('--verifier', action='store_true',
                        help='verifier la configuration sans lancer Mininet')
    args = parser.parse_args()

    cfg = charger_config(args.config)
    erreurs = verifier_config(cfg)
    if erreurs:
        print('Configuration invalide :')
        for e in erreurs:
            print('  - ' + e)
        sys.exit(1)

    avec_nat = not args.sans_nat
    if args.verifier:
        print('Configuration valide : %s' % args.config)
        afficher_resume(cfg, avec_nat)
        return

    if os.geteuid() != 0:
        sys.exit('Ce script doit etre lance avec sudo.')

    from mininet.cli import CLI
    from mininet.log import setLogLevel
    setLogLevel('info')

    net = construire_reseau(cfg, avec_nat)
    try:
        if not args.sans_services:
            demarrer_services(net, cfg)
        afficher_resume(cfg, avec_nat)
        print('Rappel : lancer Ryu (STP) avant de tester la connectivite.\n')
        CLI(net)
    finally:
        if not args.sans_services:
            arreter_services(net, cfg)
        net.stop()


if __name__ == '__main__':
    main()
