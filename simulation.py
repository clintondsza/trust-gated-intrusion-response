import random

# network topology: 3 partitioned zones, db_core_01 is the crown jewel
ZONES = {
    'dmz': ['dmz_gw', 'web_srv_01', 'web_srv_02'],
    'internal': ['app_srv_01', 'app_srv_02', 'ws_user_01', 'ws_user_02'],
    'core': ['db_core_01', 'db_backup_02', 'auth_srv_01'],
}
NODE_ZONE = {node: zone for zone, nodes in ZONES.items() for node in nodes}

ADJACENCY = {
    'dmz_gw': ['web_srv_01', 'web_srv_02', 'app_srv_01'],
    'web_srv_01': ['dmz_gw', 'app_srv_02'],
    'web_srv_02': ['dmz_gw'],
    'app_srv_01': ['dmz_gw', 'app_srv_02', 'ws_user_01', 'db_core_01'],
    'app_srv_02': ['web_srv_01', 'app_srv_01', 'ws_user_02', 'auth_srv_01'],
    'ws_user_01': ['app_srv_01'],
    'ws_user_02': ['app_srv_02'],
    'db_core_01': ['app_srv_01', 'db_backup_02', 'auth_srv_01'],
    'db_backup_02': ['db_core_01'],
    'auth_srv_01': ['app_srv_02', 'db_core_01'],
}

THRESHOLDS = {'monitor': 0.0, 'analyze': 0.30, 'remove': 0.50, 'restore': 0.70, 'block': 0.85}
AGENTS = ['agent_dmz', 'agent_internal', 'agent_core']
AGENT_ZONE = {'agent_dmz': 'dmz', 'agent_internal': 'internal', 'agent_core': 'core'}
ZONE_AGENT = {z: a for a, z in AGENT_ZONE.items()}


# asymmetric trust update: drops faster on bad evidence than it recovers on good
def update_trust(t, evidence, eta_minus=0.30, eta_plus=0.05, deadband=0.05):
    delta = evidence - t
    if abs(delta) <= deadband:
        return t
    if delta < -deadband:
        return max(0.0, t + eta_minus * (delta + deadband))
    return min(1.0, t + eta_plus * (delta - deadband))


def run_simulation(compromised=None, behavior='honest', use_gating=True, sleeper_switch=10, epochs=25, seed=42):
    rng = random.Random(seed)
    infected = set()
    isolated = set()
    # initial pairwise trust matrix
    trust = {(src, dst): 0.75 for src in AGENTS for dst in AGENTS if src != dst}

    gated_count = 0
    benign_hits = 0
    avail_history = []

    for t in range(epochs):
        # 1. attacker progression across adjacent unblocked nodes
        if not infected:
            if rng.random() <= 0.75:
                infected.add(rng.choice(ZONES['dmz']))
        else:
            for node in list(infected):
                if node in isolated:
                    continue
                uninfected = [n for n in ADJACENCY.get(node, []) if n not in infected and n not in isolated]
                if uninfected and rng.random() <= 0.75:
                    infected.add(rng.choice(uninfected))

        # 2. defender alert generation
        alerts = []
        for agent in AGENTS:
            zone = AGENT_ZONE[agent]
            mode = behavior if agent == compromised else 'honest'
            if mode == 'sleeper':
                mode = 'harmful' if t >= sleeper_switch else 'honest'

            if mode == 'honest':
                for n in ZONES[zone]:
                    if n in infected and rng.random() <= 0.95:
                        action = 'block' if n in ('dmz_gw', 'db_core_01') else 'remove'
                        alerts.append((agent, n, action))
            elif mode == 'harmful':
                # fabricate alert recommending block on benign peer hosts
                peer_nodes = [n for z, nodes in ZONES.items() if z != zone for n in nodes if n not in infected]
                if peer_nodes:
                    alerts.append((agent, rng.choice(peer_nodes), 'block'))

        # 3. action gating & response execution
        pending_evals = []
        for sender, target, action in alerts:
            receiver = ZONE_AGENT[NODE_ZONE[target]]
            local_detect = target in infected
            peer_trust = 1.0 if receiver == sender else trust.get((receiver, sender), 0.75)

            # trust-gating: high-impact action requires sufficient peer trust unless locally verified
            if use_gating:
                if local_detect or peer_trust >= THRESHOLDS.get(action, 0.0):
                    exec_action, was_gated = action, False
                else:
                    exec_action, was_gated = 'monitor', True  # fallback
            else:
                exec_action, was_gated = action, False

            if was_gated:
                gated_count += 1
            elif exec_action in ('block', 'restore') and target not in infected:
                benign_hits += 1

            if exec_action == 'block':
                isolated.add(target)
            elif exec_action == 'remove' and target in infected:
                infected.remove(target)

            pending_evals.append((receiver, sender, target, action))

        # local remediation by honest agents
        for agent in AGENTS:
            if agent == compromised and behavior == 'concealment':
                continue
            for n in ZONES[AGENT_ZONE[agent]]:
                if n in infected and n not in isolated:
                    infected.remove(n)

        # 4. update peer trust from observed outcomes
        if use_gating:
            for receiver, sender, target, action in pending_evals:
                if receiver != sender:
                    # false report on clean host yields bad evidence (0.0)
                    evidence = 1.0 if target in infected else 0.0
                    trust[(receiver, sender)] = update_trust(trust[(receiver, sender)], evidence)

        # compute legitimate service availability
        benign_nodes = [n for z in ZONES.values() for n in z if n not in infected and n != 'db_core_01']
        operational = sum(1 for n in benign_nodes if n not in isolated)
        avail_history.append(operational / len(benign_nodes) if benign_nodes else 1.0)

    jewel_safe = 'db_core_01' not in infected
    contained = jewel_safe and len(infected) <= 2
    avg_avail = sum(avail_history) / len(avail_history) if avail_history else 1.0

    return {
        'contained': contained,
        'jewel_safe': jewel_safe,
        'gated': gated_count,
        'benign_hits': benign_hits,
        'avg_avail': avg_avail,
    }


def main():
    scenarios = [
        ('1. Normal Collaboration', {}),
        ('2. Compromised (No Trust Gating)', {'compromised': 'agent_dmz', 'behavior': 'harmful', 'use_gating': False}),
        ('3. Compromised (With Trust Gating)', {'compromised': 'agent_dmz', 'behavior': 'harmful', 'use_gating': True}),
        ('4. Sleeper Agent (With Trust Gating)', {'compromised': 'agent_internal', 'behavior': 'sleeper', 'sleeper_switch': 10, 'use_gating': True}),
    ]

    print(f'{"Scenario":<38} | {"Contained":<9} | {"Jewel Safe":<10} | {"Gated":<5} | {"Benign Hits":<11} | {"Avg Avail":<9}')
    print('-' * 96)

    for name, kwargs in scenarios:
        res = run_simulation(**kwargs)
        print(f"{name:<38} | {str(res['contained']):<9} | {str(res['jewel_safe']):<10} | {res['gated']:<5} | {res['benign_hits']:<11} | {res['avg_avail']:.2%}")


if __name__ == '__main__':
    main()
