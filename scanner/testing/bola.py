def create_bola_test(endpoint, attacker, attacker_token, resource_owner):
    return {
        "type": "BOLA",
        "method": "GET",
        "endpoint": endpoint,
        "attacker": attacker,
        "attacker_token": attacker_token,
        "resource_owner": resource_owner,
        "expected_access": "DENY"
    }