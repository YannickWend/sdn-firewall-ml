"""
switch_l3.py - Switch de niveau 3 pour S-Coeur.

Un switch L3 = un switch L2 (STP, apprentissage MAC par VLAN) + des interfaces
de routage virtuelles, une par VLAN (comme les SVI d'un switch Cisco).
Cette classe herite donc de SwitchL2 et ajoute :
  - les passerelles 10.1.X.254 : reponse aux requetes ARP et aux pings ;
  - le routage inter-VLAN (changement de tag VLAN, reecriture des MAC, TTL - 1) ;
  - la route par defaut vers nat0 par le reseau de transit (non tague) ;
  - la resolution ARP des destinations, avec mise en attente des paquets.

Inspire de rest_router.py (RyuBook, chapitre 11), mais sans API REST : tout est
lu dans config/reseau.json, et integre au STP (stplib, chapitre 6).

Lancement (avec la partie L2 des autres switches) :
    ryu-manager apps/switch_l2.py apps/switch_l3.py

Pipeline sur S-Coeur :
    table 0  prio 0xffff  BPDU -> controleur                   (stplib)
    table 0  prio 0       defaut -> table 1                    (cookie 0x20)
    table 1  prio 1000    MAC passerelle + IP dst -> routage    (cookie 0x31)
    table 1  prio 100     (vlan, mac dst) -> port               (cookie 0x21)
    table 1  prio 0       inconnu -> controleur                (cookie 0x20)
"""

import ipaddress
import os
import time

from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.lib import stplib
from ryu.lib.packet import arp, ether_types, ethernet, icmp, ipv4, packet, vlan
from ryu.ofproto import ofproto_v1_3

from L2 import (COOKIE_MASQUE, SwitchL2, TABLE_ACHEMINEMENT)

COOKIE_ROUTE = 0x31
PRIORITE_ROUTE = 1000
IDLE_TIMEOUT_ROUTE = 60

ATTENTE_MAX = 20           # paquets gardes par IP en attente de resolution ARP
DELAI_ATTENTE = 3          # secondes avant d'abandonner un paquet en attente
MAC_DIFFUSION = 'ff:ff:ff:ff:ff:ff'


def mac_passerelle(vid):
    """MAC de l'interface de routage d'un VLAN : 00:00:0a:01:<vlan>:fe.
    VLAN 20 -> 00:00:0a:01:14:fe ; transit (vid 0) -> 00:00:0a:01:00:fe."""
    return '00:00:0a:01:%02x:fe' % vid


class SwitchL3(SwitchL2):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'stplib': stplib.Stp}

    def __init__(self, *args, **kwargs):
        super(SwitchL3, self).__init__(*args, **kwargs)
        self.roles = {'l3'}
        self.logger.info('[L3] Roles geres : l3 (S-Coeur)')
        if 'l3' in os.environ.get('SWITCH_L2_ROLES', ''):
            self.logger.warning('[L3] SWITCH_L2_ROLES contient "l3" : switch_l2 et '
                                'switch_l3 vont gerer S-Coeur en meme temps. '
                                'Relancer sans cette variable.')

        # Interfaces de routage : vid -> {ip, mac, reseau}
        self.interfaces = {}
        for vid, v in self.cfg.vlans.items():
            self.interfaces[vid] = {'ip': str(v['passerelle']), 'mac': mac_passerelle(vid),
                                    'reseau': v['reseau']}
        nat = self.cfg.nat
        self.nat_actif = bool(nat.get('active'))
        if self.nat_actif:
            self.interfaces[0] = {'ip': nat['ip_coeur'], 'mac': mac_passerelle(0),
                                  'reseau': ipaddress.ip_network(nat['reseau_transit'])}
            self.ip_nat = nat['ip_nat'].split('/')[0]
            self.port_nat = nat['port']
        self.ips_routeur = {itf['ip']: vid for vid, itf in self.interfaces.items()}
        self.macs_routeur = {itf['mac']: vid for vid, itf in self.interfaces.items()}

        self.arp = {}        # ip -> mac
        self.attente = {}    # ip -> [(horodatage, in_port, donnees)]

        for vid, itf in sorted(self.interfaces.items()):
            self.logger.info('[L3] Interface %-8s %-15s %s  reseau %s',
                             'VLAN %d' % vid if vid else 'transit', itf['ip'],
                             itf['mac'], itf['reseau'])
        if self.nat_actif:
            self.logger.info('[L3] Route par defaut : via %s (nat0, port %s)',
                             self.ip_nat, self.port_nat)

    # ------------------------------------------------------------------
    # Adaptations de la partie L2
    # ------------------------------------------------------------------
    def ports_inondation(self, dpid, in_port, vid):
        """Le reseau de transit (non tague) ne sort que par le port de nat0."""
        if vid == 0:
            if not self.nat_actif or self.port_nat == in_port:
                return []
            etat = self.etat_ports.get(dpid, {}).get(self.port_nat)
            return [self.port_nat] if etat == stplib.PORT_STATE_FORWARD else []
        return super(SwitchL3, self).ports_inondation(dpid, in_port, vid)

    def oublier_mac(self, dp, raison):
        """Changement STP : les ports de sortie des routes peuvent changer."""
        super(SwitchL3, self).oublier_mac(dp, raison)
        ofp, parser = dp.ofproto, dp.ofproto_parser
        dp.send_msg(parser.OFPFlowMod(datapath=dp, table_id=TABLE_ACHEMINEMENT,
                                      command=ofp.OFPFC_DELETE,
                                      cookie=COOKIE_ROUTE, cookie_mask=COOKIE_MASQUE,
                                      out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                                      match=parser.OFPMatch()))

    # ------------------------------------------------------------------
    # Outils
    # ------------------------------------------------------------------
    def interface_pour(self, ip):
        """(vid, ip du prochain saut) pour joindre ip, ou (None, None)."""
        adr = ipaddress.ip_address(ip)
        for vid, itf in self.interfaces.items():
            if adr in itf['reseau']:
                return vid, ip                      # reseau directement connecte
        if self.nat_actif:
            return 0, self.ip_nat                   # route par defaut
        return None, None

    @staticmethod
    def construire(vid, mac_src, mac_dst, ethertype, *protocoles):
        p = packet.Packet()
        if vid:
            p.add_protocol(ethernet.ethernet(mac_dst, mac_src, ether_types.ETH_TYPE_8021Q))
            p.add_protocol(vlan.vlan(vid=vid, ethertype=ethertype))
        else:
            p.add_protocol(ethernet.ethernet(mac_dst, mac_src, ethertype))
        for proto in protocoles:
            p.add_protocol(proto)
        p.serialize()
        return p.data

    def envoyer(self, dp, ports, donnees):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        if not ports:
            return
        actions = [parser.OFPActionOutput(p) for p in ports]
        dp.send_msg(parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER,
                                        in_port=ofp.OFPP_CONTROLLER,
                                        actions=actions, data=donnees))

    def demander_arp(self, dp, vid, ip_cible):
        itf = self.interfaces[vid]
        donnees = self.construire(
            vid, itf['mac'], MAC_DIFFUSION, ether_types.ETH_TYPE_ARP,
            arp.arp(opcode=arp.ARP_REQUEST, src_mac=itf['mac'], src_ip=itf['ip'],
                    dst_mac='00:00:00:00:00:00', dst_ip=ip_cible))
        self.envoyer(dp, self.ports_inondation(dp.id, None, vid), donnees)
        self.logger.info('[L3] ARP : qui a %s ? (VLAN %s)', ip_cible, vid)

    def apprendre_l2(self, dp, vid, mac, port):
        self.table_mac.setdefault(dp.id, {})[(vid, mac)] = port

    # ------------------------------------------------------------------
    # Point d'entree : paquets non BPDU transmis par stplib
    # ------------------------------------------------------------------
    @set_ev_cls(stplib.EventPacketIn, MAIN_DISPATCHER)
    def paquet_entrant(self, ev):
        msg = ev.msg
        dp = msg.datapath
        if not self.gere(dp.id):
            return
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return
        tag = pkt.get_protocol(vlan.vlan)
        vid = tag.vid if tag else 0

        pkt_arp = pkt.get_protocol(arp.arp)
        if pkt_arp is not None and self.traiter_arp(dp, in_port, vid, eth, pkt_arp):
            return
        pkt_ip = pkt.get_protocol(ipv4.ipv4)
        if pkt_ip is not None and eth.dst in self.macs_routeur:
            self.apprendre_l2(dp, vid, eth.src, in_port)
            self.router(dp, in_port, vid, eth, pkt_ip, pkt, msg.data)
            return
        # Tout le reste (trafic au sein d'un VLAN) : comportement L2 herite
        super(SwitchL3, self).paquet_entrant(ev)

    # ------------------------------------------------------------------
    # ARP
    # ------------------------------------------------------------------
    def traiter_arp(self, dp, in_port, vid, eth, pkt_arp):
        """Retourne True si le paquet ARP concerne le routeur (consomme)."""
        itf = self.interfaces.get(vid)
        # On profite de chaque ARP du bon reseau pour remplir le cache
        if itf and ipaddress.ip_address(pkt_arp.src_ip) in itf['reseau']:
            self.apprendre_l2(dp, vid, pkt_arp.src_mac, in_port)
            if self.arp.get(pkt_arp.src_ip) != pkt_arp.src_mac:
                self.arp[pkt_arp.src_ip] = pkt_arp.src_mac
                self.logger.info('[L3] ARP : %s est %s (VLAN %s, %s)', pkt_arp.src_ip,
                                 pkt_arp.src_mac, vid, self.cfg.nom_port(dp.id, in_port))
            self.liberer_attente(dp, pkt_arp.src_ip)

        if itf is None or pkt_arp.dst_ip != itf['ip']:
            return False      # ARP entre hotes : commutation L2 normale

        if pkt_arp.opcode == arp.ARP_REQUEST:
            reponse = self.construire(
                vid, itf['mac'], pkt_arp.src_mac, ether_types.ETH_TYPE_ARP,
                arp.arp(opcode=arp.ARP_REPLY, src_mac=itf['mac'], src_ip=itf['ip'],
                        dst_mac=pkt_arp.src_mac, dst_ip=pkt_arp.src_ip))
            self.envoyer(dp, [in_port], reponse)
            self.logger.debug('[L3] ARP : reponse %s -> %s', itf['ip'], pkt_arp.src_ip)
        return True

    # ------------------------------------------------------------------
    # Routage
    # ------------------------------------------------------------------
    def router(self, dp, in_port, vid_in, eth, pkt_ip, pkt, donnees):
        # Paquet destine au routeur lui-meme : on ne repond qu'aux pings
        if pkt_ip.dst in self.ips_routeur:
            self.repondre_ping(dp, in_port, vid_in, eth, pkt_ip, pkt)
            return
        if pkt_ip.ttl <= 1:
            return
        vid_out, prochain_saut = self.interface_pour(pkt_ip.dst)
        if vid_out is None:
            self.logger.debug('[L3] Pas de route vers %s', pkt_ip.dst)
            return

        mac_dst = self.arp.get(prochain_saut)
        port = self.table_mac.get(dp.id, {}).get((vid_out, mac_dst)) if mac_dst else None
        if port is None:
            # Destination pas encore resolue : on garde le paquet et on demande
            file = self.attente.setdefault(prochain_saut, [])
            if len(file) < ATTENTE_MAX:
                file.append((time.time(), in_port, donnees))
            self.demander_arp(dp, vid_out, prochain_saut)
            return

        self.installer_route(dp, in_port, vid_in, vid_out, eth.dst, pkt_ip.dst,
                             mac_dst, port, donnees)

    def installer_route(self, dp, in_port, vid_in, vid_out, mac_routeur_in, ip_dst,
                        mac_dst, port, donnees):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        actions = []
        if vid_in and not vid_out:
            actions.append(parser.OFPActionPopVlan())
        elif vid_out and not vid_in:
            actions.append(parser.OFPActionPushVlan(ether_types.ETH_TYPE_8021Q))
        if vid_out and vid_out != vid_in:
            actions.append(parser.OFPActionSetField(vlan_vid=ofp.OFPVID_PRESENT | vid_out))
        actions += [parser.OFPActionSetField(eth_src=self.interfaces[vid_out]['mac']),
                    parser.OFPActionSetField(eth_dst=mac_dst),
                    parser.OFPActionDecNwTtl()]
        # Sortie par le port d'entree (ex. VLAN 20 -> 40, tous deux derriere dist1)
        actions.append(parser.OFPActionOutput(ofp.OFPP_IN_PORT if port == in_port else port))

        match = self.match_vlan(parser, vid_in, in_port=in_port,
                                eth_type=ether_types.ETH_TYPE_IP,
                                eth_dst=mac_routeur_in, ipv4_dst=ip_dst)
        self.ajouter_regle(dp, TABLE_ACHEMINEMENT, PRIORITE_ROUTE, match,
                           [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)],
                           COOKIE_ROUTE, idle_timeout=IDLE_TIMEOUT_ROUTE)
        dp.send_msg(parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER,
                                        in_port=in_port, actions=actions, data=donnees))
        self.logger.info('[L3] Route : %-26s VLAN %-2s -> VLAN %-2s %s vers %s',
                         self.cfg.nom_port(dp.id, in_port), vid_in or '-', vid_out or '-',
                         ip_dst, self.cfg.nom_port(dp.id, port))

    def liberer_attente(self, dp, ip):
        """Une IP vient d'etre resolue : on route les paquets qui l'attendaient."""
        file = self.attente.pop(ip, [])
        maintenant = time.time()
        for horodatage, in_port, donnees in file:
            if maintenant - horodatage > DELAI_ATTENTE:
                continue
            pkt = packet.Packet(donnees)
            eth = pkt.get_protocol(ethernet.ethernet)
            tag = pkt.get_protocol(vlan.vlan)
            self.router(dp, in_port, tag.vid if tag else 0, eth,
                        pkt.get_protocol(ipv4.ipv4), pkt, donnees)

    def repondre_ping(self, dp, in_port, vid, eth, pkt_ip, pkt):
        echo = pkt.get_protocol(icmp.icmp)
        if echo is None or echo.type != icmp.ICMP_ECHO_REQUEST:
            return
        reponse = self.construire(
            vid, eth.dst, eth.src, ether_types.ETH_TYPE_IP,
            ipv4.ipv4(src=pkt_ip.dst, dst=pkt_ip.src, proto=pkt_ip.proto, ttl=64),
            icmp.icmp(type_=icmp.ICMP_ECHO_REPLY, code=0, csum=0, data=echo.data))
        self.envoyer(dp, [in_port], reponse)
