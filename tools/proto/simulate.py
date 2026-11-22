"""MeshForest flood simulator + scenario battery (protocol-spec §15.2).

Discrete-event simulation of the managed-flooding protocol:
  * uniform per-link packet loss,
  * half-duplex radios (a node transmitting misses concurrent packets),
  * pairwise collision corruption at shared receivers,
  * randomized report jitter, relay backoff, gateway ACK delay (seeded).

Run:  python tools/proto/simulate.py
Exit code 0 = all scenarios passed.
"""

import heapq
import itertools
import math
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import protocol as P
from protocol import Node

KEY = bytes(range(16))
NET_ID = 0x1234
GW = P.GATEWAY_ID


class World:
    def __init__(self, seed):
        self.t = 0.0
        self.rng = random.Random(seed)
        self.q = []
        self.seq = itertools.count()
        self.nodes = {}
        self.neighbors = {}
        self.txlog = []          # (start, end, sender_id) pruned continuously

    def add_node(self, node):
        self.nodes[node.id] = node

    def set_links(self, links):
        """links: {(a, b): loss_p}, bidirectional."""
        self.neighbors = {nid: [] for nid in self.nodes}
        for (a, b), loss in links.items():
            self.neighbors[a].append((b, loss))
            self.neighbors[b].append((a, loss))

    def schedule(self, t, fn):
        heapq.heappush(self.q, (t, next(self.seq), fn))

    def send(self, node, pkt, t):
        ams = P.airtime_ms(len(pkt))
        end = t + ams / 1000.0
        self.txlog.append((t, end, node.id))
        self.schedule(end, lambda: self._deliver(node.id, pkt, t, end))

    def _deliver(self, sender, pkt, start, end):
        # prune transmissions that can no longer overlap anything in flight
        while self.txlog and self.txlog[0][1] <= self.t - 0.1:
            self.txlog.pop(0)
        for other, loss_p in self.neighbors.get(sender, []):
            recv = self.nodes[other]
            if recv.busy_until > start + 1e-9:        # half-duplex miss
                recv.stats["rx_half_duplex_miss"] += 1
                continue
            if self.rng.random() < loss_p:            # link loss
                recv.stats["rx_link_loss"] += 1
                continue
            ok = True
            for s2, e2, snd2 in self.txlog:            # collision corruption
                if snd2 == sender or s2 >= end or start >= e2:
                    continue
                if any(o == snd2 for o, _ in self.neighbors.get(other, [])):
                    ok = False
                    recv.stats["rx_collision"] += 1
                    break
            if ok:
                recv.receive(pkt, self.t)

    def run(self, until):
        self._wake_pending(until)
        while self.q and self.q[0][0] <= until:
            t, _, fn = heapq.heappop(self.q)
            self.t = t
            fn()
            for n in self.nodes.values():
                n.tick(self.t)
            if not self.q or self.q[0][0] > until:
                self._wake_pending(until)
        self.t = until
        for n in self.nodes.values():
            n.tick(self.t)

    def _wake_pending(self, until):
        """Schedule a no-op event at the earliest time any node has queued
        work, so TX queues/relays/retries get serviced even when no radio
        events are outstanding (mirrors the firmware main loop)."""
        due = [n.earliest_due() for n in self.nodes.values()]
        due = [d for d in due if d is not None and d > self.t and d <= until]
        if due:
            self.schedule(min(due), lambda: None)


def make_net(seed, n_nodes=6, loss=0.0, area=100.0):
    """Random geometric mesh: gateway centered, nodes uniform; guaranteed
    connected by growing the link radius as needed."""
    rng = random.Random(seed * 7919 + 13)
    ids = [GW] + list(range(2, 2 + n_nodes))
    pos = {GW: (50.0, 50.0)}
    for nid in ids[1:]:
        pos[nid] = (rng.uniform(0, area), rng.uniform(0, area))
    for radius in (45, 55, 65, 80, 100):
        links = {}
        for i, a in enumerate(ids):
            for b in ids[i + 1:]:
                if math.dist(pos[a], pos[b]) <= radius:
                    links[(a, b)] = loss
        world = World(seed)
        for nid in ids:
            world.add_node(Node(nid, KEY, NET_ID, world.rng, world,
                                is_gateway=(nid == GW)))
        world.set_links(links)
        if _connected(world, ids):
            return world, ids
    raise RuntimeError("could not build connected net")


def make_chain(seed, n_nodes=7, loss=0.0):
    """Linear chain: gateway at one end, nodes in a line."""
    ids = [GW] + list(range(2, 2 + n_nodes))
    links = {}
    for a, b in zip(ids, ids[1:]):
        links[(a, b)] = loss
    world = World(seed)
    for nid in ids:
        world.add_node(Node(nid, KEY, NET_ID, world.rng, world,
                            is_gateway=(nid == GW)))
    world.set_links(links)
    return world, ids


def _connected(world, ids):
    seen, stack = {GW}, [GW]
    while stack:
        cur = stack.pop()
        for other, _ in world.neighbors.get(cur, []):
            if other not in seen:
                seen.add(other)
                stack.append(other)
    return len(seen) == len(ids)


def schedule_reports(world, cadence_s, jitter_s, until):
    for nid, node in world.nodes.items():
        if node.is_gateway:
            continue

        def fire(n=node):
            n.originate_report(world.t)
        t = world.rng.uniform(0, cadence_s)
        while t <= until:
            world.schedule(t, fire)
            t += cadence_s + world.rng.uniform(-jitter_s, jitter_s)


def node_tx(node, ptype=None):
    if ptype is None:
        return node.stats["tx"]
    return node.stats.get("tx_type_%d" % ptype, 0)


# ---------------------------------------------------------------- scenarios

def s1_unit_tests():
    P._unit_tests()


def s2_mesh_delivery():
    for loss in (0.0, 0.1, 0.3, 0.5):
        delivered = acked = total = 0
        for trial in range(20):
            world, ids = make_net(seed=100 + trial, loss=loss)
            gw = world.nodes[GW]
            src = world.nodes[ids[1 + trial % len(ids[1:])]]
            mid = src.originate_alert(5.0)
            world.run(60.0)
            total += 1
            if (src.id, mid) in gw.gw_alerts:
                delivered += 1
            if (src.id, mid) in src.confirmed:
                acked += 1
        line = ("  loss %3d%%: delivered %2d/20, source-confirmed %2d/20"
                % (loss * 100, delivered, acked))
        if loss <= 0.3:
            assert delivered == total, \
                "delivery below target at loss %s: %s" % (loss, line)
        print("PASS s2 mesh delivery\n" + line)


def s3_duplicate_suppression():
    world, ids = make_net(seed=7, loss=0.0)
    src = world.nodes[ids[3]]
    gw = world.nodes[GW]
    mid = src.originate_alert(2.0)
    world.run(10.0)
    # §8: at most ONE relay per node per (src, msg_id), counting alert and
    # ACK floods separately (both are correct, distinct messages).
    alert_relays = {nid: n.stats.get("relay_tx_type_%d" % P.T_ALERT, 0)
                    for nid, n in world.nodes.items()}
    ack_relays = {nid: n.stats.get("relay_tx_type_%d" % P.T_ACK, 0)
                  for nid, n in world.nodes.items()}
    assert all(v <= 1 for v in alert_relays.values()), \
        "a node relayed the same alert more than once: %s" % alert_relays
    assert all(v <= 1 for v in ack_relays.values()), \
        "a node relayed the same ACK more than once: %s" % ack_relays
    assert (src.id, mid) in gw.gw_alerts, "alert not delivered at 0% loss"
    assert node_tx(src, P.T_ALERT) == 1, "source retransmitted despite ACK"
    assert src.stats.get("alert_retry_tx", 0) == 0, "retry fired despite ACK"
    print("PASS s3 duplicate suppression (alert relays %s, ACK relays %s)"
          % (alert_relays, ack_relays))


def s4_ack_cancellation():
    world, ids = make_net(seed=8, loss=0.0)
    src = world.nodes[ids[5]]
    gw = world.nodes[GW]
    mid = src.originate_alert(2.0)
    world.run(10.0)
    assert (src.id, mid) in src.confirmed, "source never marked confirmed"
    assert len(src.alert_retries) == 0, "retry state not cleared by ACK"
    assert gw.stats.get("ack_tx", 0) >= 1, "gateway did not ACK"
    print("PASS s4 ACK cancels retries and relays")


def s5_partition():
    world, ids = make_net(seed=9, loss=0.0)
    all_links = {k: v for k, v in
                 [(k, 0.0) for k in _all_pairs(world)]}
    # cut every gateway link at t=1
    cut = {k: v for k, v in all_links.items() if GW not in k}
    world.schedule(1.0, lambda: world.set_links(cut))
    src = world.nodes[ids[4]]
    mid = src.originate_alert(2.0)
    world.run(60.0)
    gw = world.nodes[GW]
    assert (src.id, mid) not in gw.gw_alerts, "alert crossed a full partition"
    assert node_tx(src, P.T_ALERT) == 4, \
        "source must stop after 4 transmissions (got %d)" % \
        node_tx(src, P.T_ALERT)
    assert src.stats.get("alert_unconfirmed", 0) == 1, "unconfirmed not marked"
    max_tx = max(node_tx(n) for n in world.nodes.values())
    assert max_tx <= 6, "unbounded TX during partition: %d" % max_tx
    print("PASS s5 partition: 4 bounded source TX, no storm "
          "(max per-node TX %d)" % max_tx)


def _all_pairs(world):
    pairs = []
    seen = set()
    for a, nbrs in world.neighbors.items():
        for b, _ in nbrs:
            if (b, a) not in seen:
                pairs.append((a, b))
                seen.add((a, b))
    return pairs


def s6_reboot_mid_flood():
    ok = 0
    for trial in range(10):
        world, ids = make_net(seed=200 + trial, loss=0.3)
        gw = world.nodes[GW]
        relay_id = world.neighbors[ids[3]][0][0]      # a neighbor of node 3
        src = world.nodes[ids[3]]
        mid = src.originate_alert(2.0)
        world.schedule(2.05, lambda: world.nodes[relay_id].reboot(0))
        world.run(60.0)
        max_tx = max(node_tx(n) for n in world.nodes.values())
        assert max_tx < 30, "TX exploded after reboot: %d" % max_tx
        if (src.id, mid) in gw.gw_alerts:
            ok += 1
    assert ok == 10, "delivery after mid-flood reboot too low: %d/10" % ok
    print("PASS s6 reboot mid-flood: 10/10 delivered, TX bounded")


def s7_simultaneous_alerters():
    world, ids = make_net(seed=11, loss=0.1)
    gw = world.nodes[GW]
    a = world.nodes[ids[2]]
    b = world.nodes[ids[5]]
    ma = a.originate_alert(3.0)
    mb = b.originate_alert(3.0)
    world.run(60.0)
    assert (a.id, ma) in gw.gw_alerts and (b.id, mb) in gw.gw_alerts, \
        "simultaneous alerts not both delivered"
    assert gw.siren_count == 2, "siren must fire once per unique alert"
    print("PASS s7 simultaneous alerters both delivered")


def s8_duty_budget():
    # bench profile: 60 s cadence for 6 h — 12x faster than the 300 s default
    world, ids = make_net(seed=12, loss=0.1, n_nodes=6)
    schedule_reports(world, cadence_s=60.0, jitter_s=5.0, until=6 * 3600.0)
    world.run(6 * 3600.0)
    worst = 0.0
    for n in world.nodes.values():
        air = sum(ms for t, ms in n.airtime if t > world.t - 3600.0)
        worst = max(worst, air)
        assert n.stats.get("duty_drop_p1", 0) == 0, "unexpected P1 duty drop"
    assert worst < 36000.0, "exceeds 10% legal limit: %.0f ms/h" % worst
    assert worst < 3600.0, "exceeds 1% engineering margin: %.0f ms/h" % worst
    print("PASS s8 duty budget: worst node %.0f ms TX per hour "
          "(<1%% of the hour, <10%% of legal 433 MHz limit)" % worst)


def s9_chain_observation():
    # informational worst case: 8-hop chain, 15% per-link loss
    delivered = 0
    trials = 20
    for trial in range(trials):
        world, ids = make_chain(seed=300 + trial, n_nodes=7, loss=0.15)
        far = world.nodes[ids[-1]]
        gw = world.nodes[GW]
        mid = far.originate_alert(2.0)
        world.run(60.0)
        if (far.id, mid) in gw.gw_alerts:
            delivered += 1
    print("OBS  s9 8-hop chain @ 15%%/link loss: delivered %d/%d "
          "(informational worst case, no pass threshold)" % (delivered, trials))


SCENARIOS = [s1_unit_tests, s2_mesh_delivery, s3_duplicate_suppression,
             s4_ack_cancellation, s5_partition, s6_reboot_mid_flood,
             s7_simultaneous_alerters, s8_duty_budget, s9_chain_observation]


def main():
    failures = 0
    for sc in SCENARIOS:
        try:
            sc()
        except AssertionError as e:
            failures += 1
            print("FAIL %s: %s" % (sc.__name__, e))
    print("-" * 60)
    if failures:
        print("RESULT: %d scenario(s) FAILED" % failures)
        sys.exit(1)
    print("RESULT: all scenarios passed")


if __name__ == "__main__":
    main()
