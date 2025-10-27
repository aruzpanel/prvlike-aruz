import json

data = []

with open('Pasted_Text_1742288849836.txt', 'r') as file:
    for line in file:
        line = line.strip()
        if line.startswith('{"guest_account_info":{'):
            try:
                # First attempt to parse as-is
                entry = json.loads(line)
            except json.JSONDecodeError:
                # Try adding missing closing braces if parse fails
                try:
                    entry = json.loads(line + '}}')
                except json.JSONDecodeError:
                    continue  # Skip if still invalid
            
            guest_info = entry.get('guest_account_info', {})
            uid = guest_info.get('com.garena.msdk.guest_uid')
            password = guest_info.get('com.garena.msdk.guest_password')
            
            if uid and password:
                data.append({
                    'uid': int(uid),
                    'password': password
                })

# Save to output.json
with open('input.json', 'w') as outfile:
    json.dump(data, outfile, indent=2)

print(f"Successfully converted {len(data)} entries")