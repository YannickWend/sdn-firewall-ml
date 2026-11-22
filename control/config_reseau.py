"""
config_reseau.py - Lecture de config/reseau.json pour les applications Ryu.

Toutes les applications (switch_l2, switch_l3, firewall, moniteur...) passent
par cette classe : aucune adresse, aucun DPID, aucun numero de port n'est ecrit
en dur dans leur code.

Chemin du fichier :
    1. variable d'environnement RESEAU_CONFIG si elle existe ;
    2. sinon ../config/reseau.json par rapport au dossier apps/.

Test rapide (sans Ryu ni Mininet) :
    python3 apps/config_reseau.py
"""

import ipaddress
import json
import os

CHEMIN_PAR_DEFAUT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 '..', 'topology', 'reseau.json')

# Valeurs STP standard (IEEE 802.1D), modifiables dans la section "stp" du JSON
STP_PAR_DEFAUT = {'hello_time': 2, 'max_age': 20, 'fwd_delay': 15}


class ConfigReseau(object):

    def __init__(self, chemin=None):
        self.chemin = os.path.abspath(
            chemin or os.environ.get('RESEAU_CONFIG') or CHEMIN_PAR_DEFAUT)
        with open(self.chemin, encoding='utf-8') as f:
            self.brut = json.load(f)
        self._indexer()

    # ------------------------------------------------------------------
    # Construction des index (une seule fois au chargement)
    # ------------------------------------------------------------------
    def _indexer(self):
        b = self.brut
        self.switches = {}          # dpid (int) -> dict du switch + 'nom'
        self.dpid_par_nom = {}      # 'dist1' -> 2
        for nom, s in b['switches'].items():
            dpid = int(s['dpid'], 16)
            self.switches[dpid] = dict(s, nom=nom)
            self.dpid_par_nom[nom] = dpid

        # Ports d'acces : (dpid, port) -> {'hote', 'vlan', 'ip', ...}
        self.acces = {}
        for nom, h in b['hotes'].items():
            dpid = self.dpid_par_nom[h['switch']]
            self.acces[(dpid, h['port'])] = dict(h, hote=nom, vlan=int(h['vlan']))

        # Ports entre switches (trunks) : (dpid, port) -> (dpid voisin, port voisin)
        self.trunks = {}
        for l in b['liens']:
            a, pb = self.dpid_par_nom[l['a']], self.dpid_par_nom[l['b']]
            self.trunks[(a, l['port_a'])] = (pb, l['port_b'])
            self.trunks[(pb, l['port_b'])] = (a, l['port_a'])

        # Agregations : (dpid, port) -> nom ; dpid -> {nom: [ports]}
        self.agregation_par_port = {}
        self.agregations_par_dpid = {}
        for nom_agg, agg in b.get('agregations', {}).items():
            for nom_sw, ports in agg['membres'].items():
                dpid = self.dpid_par_nom[nom_sw]
                self.agregations_par_dpid.setdefault(dpid, {})[nom_agg] = sorted(ports)
                for p in ports:
                    self.agregation_par_port[(dpid, p)] = nom_agg

        # VLAN
        self.vlans = {}
        for vid, v in b['vlans'].items():
            self.vlans[int(vid)] = dict(v, reseau=ipaddress.ip_network(v['reseau']),
                                        passerelle=ipaddress.ip_address(v['passerelle']))

        self.nat = b.get('nat', {})
        self.stp = dict(STP_PAR_DEFAUT, **b.get('stp', {}))

    # ------------------------------------------------------------------
    # Switches
    # ------------------------------------------------------------------
    def connu(self, dpid):
        return dpid in self.switches

    def nom(self, dpid):
        s = self.switches.get(dpid)
        return s['nom'] if s else '%016x' % dpid

    def role(self, dpid):
        s = self.switches.get(dpid)
        return s['role'] if s else None

    def dpids_par_role(self, role):
        return sorted(d for d, s in self.switches.items() if s['role'] == role)

    def priorite_stp(self, dpid):
        return self.switches[dpid]['priorite_stp']

    def config_stplib(self):
        """Dictionnaire attendu par stplib.Stp.set_config() (RyuBook, ch. 6)."""
        return {dpid: {'bridge': {'priority': s['priorite_stp'],
                                  'hello_time': self.stp['hello_time'],
                                  'max_age': self.stp['max_age'],
                                  'fwd_delay': self.stp['fwd_delay']}}
                for dpid, s in self.switches.items()}

    # ------------------------------------------------------------------
    # Ports
    # ------------------------------------------------------------------
    def est_trunk(self, dpid, port):
        return (dpid, port) in self.trunks

    def voisin(self, dpid, port):
        """(dpid, port) a l'autre bout d'un lien entre switches, ou None."""
        return self.trunks.get((dpid, port))

    def vlan_du_port(self, dpid, port):
        """VLAN d'un port d'acces, ou None si ce n'est pas un port d'acces."""
        h = self.acces.get((dpid, port))
        return h['vlan'] if h else None

    def hote_du_port(self, dpid, port):
        h = self.acces.get((dpid, port))
        return h['hote'] if h else None

    def ports_trunk(self, dpid):
        return sorted(p for (d, p) in self.trunks if d == dpid)

    def ports_acces(self, dpid, vlan=None):
        """Ports d'acces d'un switch, eventuellement filtres sur un VLAN."""
        return sorted(p for (d, p), h in self.acces.items()
                      if d == dpid and (vlan is None or h['vlan'] == vlan))

    def nom_port(self, dpid, port):
        """Libelle lisible pour les logs : 'dist2:2 (po1)', 'acc:4 (inv1, VLAN 30)'."""
        base = '%s:%s' % (self.nom(dpid), port)
        if (dpid, port) in self.acces:
            h = self.acces[(dpid, port)]
            return '%s (%s, VLAN %s)' % (base, h['hote'], h['vlan'])
        if (dpid, port) in self.agregation_par_port:
            return '%s (%s)' % (base, self.agregation_par_port[(dpid, port)])
        v = self.trunks.get((dpid, port))
        if v:
            return '%s (vers %s)' % (base, self.nom(v[0]))
        if self.nat.get('active') and self.dpid_par_nom.get(self.nat['switch']) == dpid \
                and self.nat['port'] == port:
            return '%s (nat0)' % base
        return base

    # ------------------------------------------------------------------
    # Agregations (EtherChannel)
    # ------------------------------------------------------------------
    def agregation_du_port(self, dpid, port):
        return self.agregation_par_port.get((dpid, port))

    def agregations(self, dpid):
        """{'po1': [2, 3]} pour un switch, {} s'il n'en a pas."""
        return self.agregations_par_dpid.get(dpid, {})

    # ------------------------------------------------------------------
    # Adressage
    # ------------------------------------------------------------------
    def vlan_de_ip(self, ip):
        ip = ipaddress.ip_address(ip)
        for vid, v in self.vlans.items():
            if ip in v['reseau']:
                return vid
        return None

    def passerelle(self, vlan):
        return str(self.vlans[vlan]['passerelle'])

    def passerelles(self):
        """{ '10.1.20.254': 20, ... } : adresses auxquelles S-Coeur doit repondre."""
        return {str(v['passerelle']): vid for vid, v in self.vlans.items()}

    def resume(self):
        lignes = ['Configuration : %s' % self.chemin]
        for dpid, s in sorted(self.switches.items()):
            lignes.append('  %-6s dpid=%-3d role=%s prio_stp=%s trunks=%s acces=%s agreg=%s'
                          % (s['nom'], dpid, s['role'], s['priorite_stp'],
                             self.ports_trunk(dpid), self.ports_acces(dpid),
                             self.agregations(dpid)))
        return '\n'.join(lignes)


# ----------------------------------------------------------------------
# Test autonome : python3 apps/config_reseau.py
# ----------------------------------------------------------------------
if __name__ == '__main__':
    c = ConfigReseau()
    print(c.resume())
    print()
    tests = [
        ("dpid 2 est-il un switch L2 ?", c.role(2) == 'l2'),
        ("dpid 1 est le switch L3", c.dpids_par_role('l3') == [1]),
        ("VLAN du port acc:4 = 30 (inv1)", c.vlan_du_port(4, 4) == 30),
        ("acc:1 est un trunk vers dist1", c.voisin(4, 1) == (2, 4)),
        ("po1 sur dist1 = ports [2, 3]", c.agregations(2) == {'po1': [2, 3]}),
        ("dist2:3 appartient a po1", c.agregation_du_port(3, 3) == 'po1'),
        ("10.1.30.5 est dans le VLAN 30", c.vlan_de_ip('10.1.30.5') == 30),
        ("passerelle du VLAN 50 = 10.1.50.254", c.passerelle(50) == '10.1.50.254'),
        ("ports d'acces VLAN 40 sur acc = [6, 7]", c.ports_acces(4, 40) == [6, 7]),
        ("priorite STP de coeur = 4096", c.priorite_stp(1) == 4096),
    ]
    ok = True
    for libelle, resultat in tests:
        print('%s  %s' % ('OK ' if resultat else 'ECHEC', libelle))
        ok = ok and resultat
    print('\nLibelles : %s | %s | %s' % (c.nom_port(3, 2), c.nom_port(4, 4), c.nom_port(1, 4)))
    raise SystemExit(0 if ok else 1)
