from xq import XQ

# init SDK (creds from ENV or input params)
xq = XQ()

# get user authentication token
email = input(f"Please provide the email address that will be used for authentication:")
xq.api.authorize_user(email)

# 2FA
pin = input(f"Please provide the PIN sent to the email address '{email}':")
xq.api.code_validate(pin)

# exchange for token
new_key = xq.api.exchange_key()

#get the first team or create one
teams = xq.api.get_teams()

if teams:
    teamId = teams[0]["id"]
else:
    teamId = xq.api.create_team("New team")

access_token = xq.api.switch(teamId)

print("\n--- Batch Database Encryption ---")

metadata = [
    {"title": "test 1", "labels": ["cui", "secret", "production"]},
    {"title": "test 2", "labels": ["team", "contact", "staging"]},
    {"title": "test 3", "labels": ["public", "dev"]}
]

batch_response = xq.generate_multiple_keys_and_store_packets_database(
    count=3,
    recipients=[email],
    metadata_list=metadata,
    expires_period=3,
    time_unit="d",
    type="Database"
)

database_messages = [
    "Sensitive database record for production system",
    "Team contact information - confidential",
    "Public development data"
]

for i, (key_data, message) in enumerate(zip(batch_response, database_messages), 1):
    key_str = list(key_data.keys())[0]
    token = key_data[key_str]

    encrypted = xq.encrypt_auto(text=message, key=key_str, locator_token=token)
    decrypted = xq.decrypt_auto(encrypted)

    print(f"\nRow {i}: {message[:30]}...")
    print(f"Encrypted: {len(encrypted)} bytes | Decrypted: {decrypted.decode('utf-8')[:30]}...")

