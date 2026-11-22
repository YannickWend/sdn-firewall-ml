"""
switch_l2.py - Switch L2 avec Spanning Tree et apprentissage MAC par VLAN.

Base : simple_switch_stp_13.py (RyuBook, chapitre 6), adapte pour le projet :
  - ecrit dans la TABLE 1 (acheminement) ; la table 0 est reservee au firewall ;
  - pose la regle par defaut "table 0 -> table 1", pour fonctionner sans firewall ;
  - apprentissage MAC par VLAN : la cle est (vlan, mac) et non mac seule ;
  - inondation limitee au VLAN : trunks + ports d'acces du meme VLAN ;
  - priorites STP, roles et ports lus dans topoly/reseau.json ;
  - n'agit que sur les switches de role "l2" (dist1, dist2, acc).

Lancement :
    ryu-manager control/L2.py

Test de l'etape 2 (avant switch_l3.py), pour que S-Coeur commute aussi en L2 :
    SWITCH_L2_ROLES=l2,l3 ryu-manager apps/switch_l2.py

Pipeline (voir README) :
    table 0  prio 0xffff  BPDU -> controleur              (stplib)
    table 0  prio 0       defaut -> table 1               (ce module, cookie 0x20)
    table 1  prio 100     (vlan, mac dst) -> port         (ce module, cookie 0x21)
    table 1  prio 0       inconnu -> controleur           (ce module, cookie 0x20)
"""

import os
import time

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib import dpid as dpid_lib
from ryu.lib import stplib
from ryu.lib.packet import ether_types, ethernet, packet, vlan
from ryu.ofproto import ofproto_v1_3

from config_reseau import ConfigReseau

TABLE_SECURITE = 0
TABLE_ACHEMINEMENT = 1

COOKIE_BASE = 0x20       # regles permanentes posees par ce module
COOKIE_MAC = 0x21        # regles apprises (supprimees a chaque changement STP)
COOKIE_MASQUE = 0xffffffffffffffff

PRIORITE_MAC = 100
IDLE_TIMEOUT_MAC = 60    # secondes sans trafic avant oubli d'une regle apprise

NOMS_ETATS = {stplib.PORT_STATE_DISABLE: 'DISABLE',
              stplib.PORT_STATE_BLOCK: 'BLOCK',
              stplib.PORT_STATE_LISTEN: 'LISTEN',
              stplib.PORT_STATE_LEARN: 'LEARN',
              stplib.PORT_STATE_FORWARD: 'FORWARD'}


class SwitchL2(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'stplib': stplib.Stp}

    def __init__(self, *args, **kwargs):
        super(SwitchL2, self).__init__(*args, **kwargs)
        self.cfg = ConfigReseau()
        roles = os.environ.get('SWITCH_L2_ROLES', 'l2')
        self.roles = set(r.strip() for r in roles.split(',') if r.strip())

        # (dpid) -> {(vlan, mac): port}
        self.table_mac = {}
        # (dpid) -> {port: etat STP}
        self.etat_ports = {}
        # (dpid) -> horodatage du dernier vidage de la table MAC
        self.dernier_oubli = {}

        # STP : priorites et temporisations depuis le JSON (tous les switches,
        # S-Coeur compris : il doit participer au STP meme s'il n'est pas gere ici)
        self.stp = kwargs['stplib']
        self.stp.set_config(self.cfg.config_stplib())

        self.logger.info('[L2] %s', self.cfg.resume().replace('\n', '\n[L2] '))
        self.logger.info('[L2] Roles geres : %s', ', '.join(sorted(self.roles)))

    # ------------------------------------------------------------------
    # Outils
    # ------------------------------------------------------------------
    def gere(self, dpid):
        return self.cfg.role(dpid) in self.roles

    @staticmethod
    def match_vlan(parser, vid, **champs):
        """vid > 0 : trame taguee ; vid = 0 : trame non taguee."""
        if vid:
            champs['vlan_vid'] = (ofproto_v1_3.OFPVID_PRESENT | vid)
        else:
            champs['vlan_vid'] = ofproto_v1_3.OFPVID_NONE
        return parser.OFPMatch(**champs)

    def ajouter_regle(self, dp, table, priorite, match, instructions,
                      cookie, idle_timeout=0):
        parser = dp.ofproto_parser
        dp.send_msg(parser.OFPFlowMod(datapath=dp, table_id=table, cookie=cookie,
                                      priority=priorite, match=match,
                                      instructions=instructions,
                                      idle_timeout=idle_timeout))

    def supprimer_regles_mac(self, dp):
        """Supprime uniquement les regles apprises (cookie 0x21) de la table 1."""
        ofp, parser = dp.ofproto, dp.ofproto_parser
        dp.send_msg(parser.OFPFlowMod(datapath=dp, table_id=TABLE_ACHEMINEMENT,
                                      command=ofp.OFPFC_DELETE,
                                      cookie=COOKIE_MAC, cookie_mask=COOKIE_MASQUE,
                                      out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                                      match=parser.OFPMatch()))

    def ports_inondation(self, dpid, in_port, vid):
        """Ports vers lesquels inonder une trame du VLAN vid.

        Trunks + ports d'acces du meme VLAN, sans le port d'entree et sans les
        ports que STP n'a pas mis en FORWARD."""
        candidats = set(self.cfg.ports_trunk(dpid))
        if vid:
            candidats |= set(self.cfg.ports_acces(dpid, vid))
        etats = self.etat_ports.get(dpid, {})
        return sorted(p for p in candidats
                      if p != in_port and etats.get(p) == stplib.PORT_STATE_FORWARD)

    # ------------------------------------------------------------------
    # Connexion d'un switch : regles de base
    # ------------------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def connexion_switch(self, ev):
        dp = ev.msg.datapath
        if not self.cfg.connu(dp.id):
            self.logger.warning('[L2] Switch inconnu dpid=%016x : absent de reseau.json', dp.id)
            return
        if not self.gere(dp.id):
            return
        ofp, parser = dp.ofproto, dp.ofproto_parser
        self.table_mac.setdefault(dp.id, {})
        self.etat_ports.setdefault(dp.id, {})

        # Table 0 : par defaut, tout passe en table 1 (le firewall ajoutera
        # des regles plus prioritaires par-dessus)
        self.ajouter_regle(dp, TABLE_SECURITE, 0, parser.OFPMatch(),
                           [parser.OFPInstructionGotoTable(TABLE_ACHEMINEMENT)],
                           COOKIE_BASE)
        # Table 1 : destination inconnue -> controleur
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.ajouter_regle(dp, TABLE_ACHEMINEMENT, 0, parser.OFPMatch(),
                           [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)],
                           COOKIE_BASE)
        self.logger.info('[L2] %s connecte (dpid=%s) : regles de base installees',
                         self.cfg.nom(dp.id), dpid_lib.dpid_to_str(dp.id))

    # ------------------------------------------------------------------
    # Paquets transmis par stplib (tout sauf les BPDU)
    # ------------------------------------------------------------------
    @set_ev_cls(stplib.EventPacketIn, MAIN_DISPATCHER)
    def paquet_entrant(self, ev):
        msg = ev.msg
        dp = msg.datapath
        if not self.gere(dp.id):
            return
        ofp, parser = dp.ofproto, dp.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None or eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        tag = pkt.get_protocol(vlan.vlan)
        vid = tag.vid if tag else 0

        # Apprentissage : (vlan, mac source) est joignable par in_port
        table = self.table_mac.setdefault(dp.id, {})
        if table.get((vid, eth.src)) != in_port:
            table[(vid, eth.src)] = in_port
            self.logger.debug('[L2] %s : appris VLAN %s %s -> %s', self.cfg.nom(dp.id),
                              vid, eth.src, self.cfg.nom_port(dp.id, in_port))

        out_port = table.get((vid, eth.dst))
        if out_port is not None and out_port != in_port:
            actions = [parser.OFPActionOutput(out_port)]
            # Regle apprise : les prochains paquets ne remontent plus au controleur
            match = self.match_vlan(parser, vid, eth_dst=eth.dst)
            self.ajouter_regle(dp, TABLE_ACHEMINEMENT, PRIORITE_MAC, match,
                               [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)],
                               COOKIE_MAC, idle_timeout=IDLE_TIMEOUT_MAC)
        elif out_port == in_port:
            return  # destination derriere le port d'entree : rien a faire
        else:
            ports = self.ports_inondation(dp.id, in_port, vid)
            if not ports:
                return
            actions = [parser.OFPActionOutput(p) for p in ports]

        dp.send_msg(parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER,
                                        in_port=in_port, actions=actions,
                                        data=msg.data))

    # ------------------------------------------------------------------
    # Evenements STP
    # ------------------------------------------------------------------
    def oublier_mac(self, dp, raison):
        self.table_mac[dp.id] = {}
        self.supprimer_regles_mac(dp)
        self.dernier_oubli[dp.id] = time.time()
        self.logger.info('[L2] %s : %s, oubli des adresses MAC', self.cfg.nom(dp.id), raison)

    @set_ev_cls(stplib.EventTopologyChange, MAIN_DISPATCHER)
    def changement_topologie(self, ev):
        """Pendant ~35 s apres un changement, chaque BPDU porte le drapeau TC et
        stplib emet cet evenement toutes les 2 s. Vider la table a chaque fois
        empecherait tout apprentissage (unicast inonde). On vide donc au plus
        une fois par periode fwd_delay (equivalent du vieillissement court
        de la norme 802.1D)."""
        dp = ev.dp
        if not self.gere(dp.id):
            return
        if time.time() - self.dernier_oubli.get(dp.id, 0) < self.cfg.stp['fwd_delay']:
            return
        self.oublier_mac(dp, 'changement de topologie')

    @set_ev_cls(stplib.EventPortStateChange, MAIN_DISPATCHER)
    def changement_etat_port(self, ev):
        dp = ev.dp
        ancien = self.etat_ports.setdefault(dp.id, {}).get(ev.port_no)
        self.etat_ports[dp.id][ev.port_no] = ev.port_state
        if not self.gere(dp.id):
            return
        self.logger.info('[L2] %-28s -> %s', self.cfg.nom_port(dp.id, ev.port_no),
                         NOMS_ETATS.get(ev.port_state, ev.port_state))
        # Un port local qui quitte ou rejoint l'etat FORWARD : les chemins
        # changent vraiment ici, on oublie tout de suite
        fwd = stplib.PORT_STATE_FORWARD
        if (ancien == fwd) != (ev.port_state == fwd) and ancien is not None:
            self.oublier_mac(dp, 'port %s' % self.cfg.nom_port(dp.id, ev.port_no))
