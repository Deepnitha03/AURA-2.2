def create_bfla_test(endpoint, normal_user, user_token):
    return {
        "type": "BFLA",
        "method": "GET",
        "endpoint": endpoint,
        "attacker": normal_user,
        "attacker_token": user_token,
        "expected_access": "DENY"
    }