import os
import json
import requests
from github import Github

def generate_token(uid, password):
    url = f"https://jwt-converter-black.vercel.app/token?uid={uid}&password={password}"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()

        # faqat uid va token
        if isinstance(data, dict) and "token" in data and "uid" in data:
            return {"uid": data["uid"], "token": data["token"]}
        else:
            raise ValueError(f"Unexpected API response format: {data}")
    except Exception as e:
        print(f"[!] Token generation failed for UID {uid}: {e}")
        return {"uid": uid, "error": "Failed to get token"}

def process_region(region, repo):
    input_file = f"input_{region}.json"
    output_file = f"token_{region}.json"

    try:
        contents = repo.get_contents(input_file)
        input_data = json.loads(contents.decoded_content.decode())
    except Exception as e:
        print(f"[!] Could not read {input_file}: {e}")
        return

    tokens = []
    for entry in input_data:
        uid = entry.get("uid")
        password = entry.get("password")
        if not uid or not password:
            print(f"[!] Skipping entry due to missing UID or password: {entry}")
            continue

        token_info = generate_token(uid, password)
        tokens.append(token_info)

    if not tokens:
        print(f"[!] No tokens generated for {region}")
        return

    try:
        output_content = json.dumps(tokens, indent=2)
        try:
            existing_file = repo.get_contents(output_file)
            repo.update_file(
                output_file,
                f"Update tokens for {region}",
                output_content,
                existing_file.sha
            )
            print(f"[+] Updated {output_file} on GitHub")
        except:
            repo.create_file(
                output_file,
                f"Add tokens for {region}",
                output_content
            )
            print(f"[+] Created {output_file} on GitHub")
    except Exception as e:
        print(f"[!] Failed to write {output_file}: {e}")

if __name__ == "__main__":
    # GitHub token olish (PAT token kerak)
    gh_token = os.getenv("GITHUB_TOKEN")
    g = Github(gh_token)

    # repo nomi
    repo = g.get_repo("makhsudjaan/fflikesforallserver")

    # bir nechta regionni ishlash
    regions = ["ind", "sg"]   # bu yerga kerakli regionlarni qo‘shib borasiz
    for region in regions:
        process_region(region, repo)
