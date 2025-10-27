from flask import Flask, request, jsonify
import asyncio
import re
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import binascii
import aiohttp
import requests
import json
import like_pb2
import like_count_pb2
import uid_generator_pb2
from google.protobuf.message import DecodeError
import os
from datetime import datetime, timedelta
import pytz

app = Flask(__name__)
API_KEYS_FILE = '/tmp/api_keys.json'
VALID_REGIONS = [
    "IND", "BR", "US", "SAC", "NA", "BD", "CIS", "Pk", "SG", "RU", "PH", "TH", "MY", "ID", "LA", "KH", "VN", "TW"
]


def load_api_keys():
    if not os.path.exists(API_KEYS_FILE):
        with open(API_KEYS_FILE, 'w') as f:
            json.dump({}, f)
    with open(API_KEYS_FILE, 'r') as f:
        return json.load(f)

def save_api_keys(data):
    with open(API_KEYS_FILE, 'w') as f:
        json.dump(data, f, indent=4)

def format_time_remaining(delta):
    days = delta.days
    hours, rem = divmod(delta.seconds, 3600)
    minutes, seconds = divmod(rem, 60)
    return f"{days}d {hours}h {minutes}m {seconds}s"


@app.route('/createapikey', methods=['GET'])
def create_apikey():
    name = request.args.get('name')
    daily_limits = request.args.get('daily_limits', 100, type=int)
    expiry_days = request.args.get('expiry_days', 30, type=int)
    
    if not name:
        return jsonify({'error': 'Name is required', 'Developed By': 'Aruz'}), 400

    api_key = name
    bd_time = pytz.timezone('Asia/Dhaka')
    created_at = datetime.now(bd_time)
    expires_at = created_at + timedelta(days=expiry_days)
    
    api_data = {
        'name': name,
        'daily_limit': daily_limits,
        'remaining': daily_limits,
        'created_at': created_at.isoformat(),
        'expires_at': expires_at.isoformat(),
        'last_reset': created_at.date().isoformat()
    }
    
    keys = load_api_keys()
    keys[api_key] = api_data
    save_api_keys(keys)
    
    return jsonify({
        'api_key': api_key,
        'name': name,
        'daily_limit': daily_limits,
        'remaining_today': daily_limits,
        'expires_at': expires_at.isoformat(),
        'expires_in': format_time_remaining(expires_at - created_at),
        'Developed By': 'Aruz'
    }), 201

@app.route('/extendexpiry', methods=['GET'])
def extend_expiry():
    api_key = request.args.get('api_key')
    days = request.args.get('days', 7, type=int)
    
    if not api_key:
        return jsonify({'error': 'API key is required', 'Developed By': 'Aruz'}), 400

    keys = load_api_keys()
    if api_key not in keys:
        return jsonify({'error': 'Invalid API key', 'Developed By': 'Aruz'}), 403

    bd_time = pytz.timezone('Asia/Dhaka')
    current_expiry = datetime.fromisoformat(keys[api_key]['expires_at']).astimezone(bd_time)
    new_expiry = current_expiry + timedelta(days=days)
    
    keys[api_key]['expires_at'] = new_expiry.isoformat()
    save_api_keys(keys)
    
    return jsonify({
        'api_key': api_key,
        'new_expiry': new_expiry.isoformat(),
        'expires_in': format_time_remaining(new_expiry - datetime.now(bd_time)),
        'Developed By': 'Aruz'
    })

@app.route('/removeapikey', methods=['GET'])
def remove_apikey():
    api_key = request.args.get('api_key')
    
    if not api_key:
        return jsonify({'error': 'API key is required', 'Developed By': 'Aruz'}), 400

    keys = load_api_keys()
    if api_key not in keys:
        return jsonify({'error': 'API key not found', 'Developed By': 'Aruz'}), 404

    del keys[api_key]
    save_api_keys(keys)
    
    return jsonify({
        'status': 'success',
        'message': f'API key {api_key} removed successfully',
        'Developed By': 'Aruz'
    })

@app.route('/updatedailylimit', methods=['GET'])
def update_daily_limit():
    api_key = request.args.get('api_key')
    new_limit = request.args.get('limit', type=int)
    
    if not api_key or new_limit is None:
        return jsonify({'error': 'API key and limit are required', 'Developed By': 'Aruz'}), 400

    keys = load_api_keys()
    if api_key not in keys:
        return jsonify({'error': 'Invalid API key', 'Developed By': 'Aruz'}), 403

    keys[api_key]['daily_limit'] = new_limit
    keys[api_key]['remaining'] = new_limit
    save_api_keys(keys)
    
    return jsonify({
        'api_key': api_key,
        'new_daily_limit': new_limit,
        'remaining_today': new_limit,
        'Developed By': 'Aruz'
    })


@app.route('/resetremaining', methods=['GET'])
def reset_remaining():
    api_key = request.args.get('api_key')
    
    if not api_key:
        return jsonify({'error': 'API key is required', 'Developed By': 'Aruz'}), 400

    keys = load_api_keys()
    if api_key not in keys:
        return jsonify({'error': 'Invalid API key', 'Developed By': 'Aruz'}), 403

    key_data = keys[api_key]
    key_data['remaining'] = key_data['daily_limit']
    save_api_keys(keys)
    
    bd_time = pytz.timezone('Asia/Dhaka')
    current_time = datetime.now(bd_time)
    next_reset = (current_time + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    time_until_reset = next_reset - current_time
    
    return jsonify({
        'status': 'success',
        'message': 'Remaining requests reset to daily limit',
        'api_key': api_key,
        'daily_limit': key_data['daily_limit'],
        'remaining_today': key_data['remaining'],
        'next_automatic_reset': next_reset.isoformat(),
        'time_until_reset': format_time_remaining(time_until_reset),
        'Developed By': 'Aruz'
    })


def load_tokens(region):
    try:
        if region == "IND":
            with open("token_ind.json", "r") as f:
                tokens = json.load(f)
        elif region in {"BR", "US", "SAC", "NA"}:
            with open("token_br.json", "r") as f:
                tokens = json.load(f)
        elif region == "BD":
            with open("token_bd.json", "r") as f:
                tokens = json.load(f)
        elif region in {"SG", "CIS"}:
            with open("token_sg.json", "r") as f:
                tokens = json.load(f)
        else:
            return None
        return tokens
    except Exception as e:
        app.logger.error(f"Error loading tokens for region {region}: {e}")
        return None

def encrypt_message(plaintext):
    try:
        key = b'Yg&tc%DEuh6%Zc^8'
        iv = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode('utf-8')
    except Exception as e:
        app.logger.error(f"Error encrypting message: {e}")
        return None

def create_protobuf_message(user_id, region):
    try:
        message = like_pb2.like()
        message.uid = int(user_id)
        message.region = region
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating protobuf message: {e}")
        return None

async def send_request(encrypted_uid, token, url):
    try:
        edata = bytes.fromhex(encrypted_uid)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-wingsoffire-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB50"
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=edata, headers=headers) as response:
                if response.status == 200:
                    return {"success": True, "data": await response.text()}
                elif response.status == 403:
                    return {"success": False, "error": "Forbidden: Invalid or expired token"}
                elif response.status == 404:
                    return {"success": False, "error": "Not Found: Resource unavailable"}
                elif response.status == 429:
                    return {"success": False, "error": "Too Many Requests: Rate limit exceeded"}
                else:
                    return {"success": False, "error": f"Request failed with status code {response.status}"}
    except Exception as e:
        app.logger.error(f"Exception in send_request: {e}")
        return {"success": False, "error": "Internal server error during request"}

async def send_multiple_requests(uid, region, url):
    try:
        protobuf_message = create_protobuf_message(uid, region)
        if protobuf_message is None:
            return {"success": False, "error": "Failed to create protobuf message"}
        encrypted_uid = encrypt_message(protobuf_message)
        if encrypted_uid is None:
            return {"success": False, "error": "Encryption failed"}
        tasks = []
        tokens = load_tokens(region)
        if tokens is None:
            return {"success": False, "error": "Failed to load tokens for region"}
        for i in range(100):
            token = tokens[i % len(tokens)]["token"]
            tasks.append(send_request(encrypted_uid, token, url))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        success_count = sum(1 for r in results if isinstance(r, dict) and r.get("success", False))
        failure_count = len(results) - success_count
        return {"success_count": success_count, "failure_count": failure_count}
    except Exception as e:
        app.logger.error(f"Exception in send_multiple_requests: {e}")
        return {"success": False, "error": "Internal server error in sending multiple requests"}

def create_protobuf(uid):
    try:
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating uid protobuf: {e}")
        return None

def enc(uid):
    protobuf_data = create_protobuf(uid)
    if protobuf_data is None:
        return None
    encrypted_uid = encrypt_message(protobuf_data)
    return encrypted_uid

def make_request(encrypt, region, token):
    try:
        if region == "IND":
            url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
        elif region in {"BR", "US", "SAC", "NA"}:
            url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
        elif region in {"BD", "SG", "CIS"}:
            url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
        else:
            return {"success": False, "error": "Unsupported region"}
        
        edata = bytes.fromhex(encrypt)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-wingsoffire-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB50"
        }
        response = requests.post(url, data=edata, headers=headers, verify=False)
        
        if response.status_code == 200:
            hex_data = response.content.hex()
            binary = bytes.fromhex(hex_data)
            decoded = decode_protobuf(binary)
            if decoded is None:
                return {"success": False, "error": "Failed to decode protobuf data"}
            return {"success": True, "data": decoded}
        elif response.status_code == 403:
            return {"success": False, "error": "Forbidden: Invalid or expired token"}
        elif response.status_code == 404:
            return {"success": False, "error": "Not Found: Player data unavailable"}
        elif response.status_code == 429:
            return {"success": False, "error": "Too Many Requests: Rate limit exceeded"}
        else:
            return {"success": False, "error": f"Request failed with status code {response.status_code}"}
    except Exception as e:
        app.logger.error(f"Error in make_request: {e}")
        return {"success": False, "error": "Internal server error during player info request"}

def decode_protobuf(binary):
    try:
        items = like_count_pb2.Info()
        items.ParseFromString(binary)
        return items
    except DecodeError as e:
        app.logger.error(f"Error decoding Protobuf data: {e}")
        return None
    except Exception as e:
        app.logger.error(f"Unexpected error during protobuf decoding: {e}")
        return None


@app.route('/aruzlike', methods=['GET'])
def handle_requests():
    api_key = request.args.get('api_key')
    uid = request.args.get("uid")
    region = request.args.get("region", "").upper()

   
    if not api_key:
        return jsonify({"error": "API key is required", "Developed By": "Aruz"}), 401

    keys = load_api_keys()
    if api_key not in keys:
        return jsonify({"error": "Invalid API key", "Developed By": "Aruz"}), 403

    key_data = keys[api_key]
    bd_time = pytz.timezone('Asia/Dhaka')
    current_time = datetime.now(bd_time)
    expires_at = datetime.fromisoformat(key_data['expires_at']).astimezone(bd_time)
    
    
    if current_time > expires_at:
        return jsonify({
            "error": "API key expired",
            "expired_at": expires_at.isoformat(),
            "Developed By": "Aruz"
        }), 403

    
    if current_time.date() > datetime.fromisoformat(key_data['last_reset']).date():
        key_data['remaining'] = key_data['daily_limit']
        key_data['last_reset'] = current_time.date().isoformat()
        save_api_keys(keys)

    
    if key_data['remaining'] <= 0:
        next_reset = (current_time + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
        time_remaining = next_reset - current_time
        return jsonify({
            "error": "Daily request limit exceeded",
            "next_reset": next_reset.isoformat(),
            "time_remaining": format_time_remaining(time_remaining),
            "Developed By": "Aruz"
        }), 429

    
    if not re.match(r'^\d{8,11}$', uid):
        return jsonify({
            "error": "Invalid UID format",
            "message": "UID must be 8-11 numeric digits",
            "example": "12345678",
            "Developed By": "Aruz"
        }), 400

    
    if region not in VALID_REGIONS:
        return jsonify({
            "error": "Invalid region",
            "valid_regions": VALID_REGIONS,
            "example": "IND",
            "Developed By": "Aruz"
        }), 400

    try:
        def process_request():
            tokens = load_tokens(region)
            if tokens is None:
                return {"success": False, "error": f"Region {region} is not supported or tokens not found"}, 400
            
            token = tokens[0]['token']
            encrypted_uid = enc(uid)
            if encrypted_uid is None:
                return {"success": False, "error": "Encryption of UID failed"}, 500

           
            before_result = make_request(encrypted_uid, region, token)
            if not before_result["success"]:
                return {"success": False, "error": before_result["error"]}, 500
            
            before = before_result["data"]
            try:
                jsone = MessageToJson(before)
                data_before = json.loads(jsone)
                before_like = data_before.get('AccountInfo', {}).get('Likes', 0)
                before_like = int(before_like)
            except Exception:
                before_like = 0

            
            if region == "IND":
                url = "https://client.ind.freefiremobile.com/LikeProfile"
            elif region in {"BR", "US", "SAC", "NA"}:
                url = "https://client.us.freefiremobile.com/LikeProfile"
            else:
                url = "https://clientbp.ggblueshark.com/LikeProfile"

            
            send_result = asyncio.run(send_multiple_requests(uid, region, url))
            if not isinstance(send_result, dict) or "success_count" not in send_result:
                return {"success": False, "error": send_result.get("error", "Failed to send like requests")}, 500

            
            after_result = make_request(encrypted_uid, region, token)
            if not after_result["success"]:
                return {"success": False, "error": after_result["error"]}, 500
            
            after = after_result["data"]
            try:
                jsone_after = MessageToJson(after)
                data_after = json.loads(jsone_after)
                after_like = int(data_after.get('AccountInfo', {}).get('Likes', 0))
                player_name = data_after.get('AccountInfo', {}).get('PlayerNickname', '')
            except Exception:
                after_like = 0
                player_name = ''

            like_given = after_like - before_like
            status = 1 if like_given > 0 else 2
            time_remaining = expires_at - current_time

            if status == 2:
                return {
                    "success": True,
                    "data": {
                        "UID": uid,
                        "message": f"UID already received max likes today. Try again after 3:00 AM Egyptian Time",
                        "key_expires": expires_at.isoformat(),
                        "key_expires_in": format_time_remaining(time_remaining),
                        "Developed By": "Aruz"
                    }
                }, 200

            result = {
                "success": True,
                "data": {
                    "LikesGivenByAPI": like_given,
                    "LikesafterCommand": after_like,
                    "LikesbeforeCommand": before_like,
                    "PlayerNickname": player_name,
                    "UID": uid,
                    "status": status,
                    "remaining_today": key_data['remaining'] - 1,
                    "key_expires": expires_at.isoformat(),
                    "key_expires_in": format_time_remaining(time_remaining),
                    "Developed By": "Aruz"
                }
            }
            return result, 200

        result, status_code = process_request()
        
        
        if result["success"] and result["data"].get('status') == 1:
            key_data['remaining'] -= 1
            save_api_keys(keys)
        
        if result["success"]:
            return jsonify(result["data"]), status_code
        else:
            return jsonify({"error": result["error"], "Developed By": "Aruz"}), status_code
    except Exception as e:
        app.logger.error(f"Error processing request: {e}")
        return jsonify({"error": "Internal server error", "Developed By": "Aruz"}), 500

@app.route('/public_aruzlike', methods=['GET'])
def public_aruzlike():
    uid = request.args.get("uid")
    region = request.args.get("region", "").upper()
    
    if not uid:
        return jsonify({"error": "UID is required", "Developed By": "Aruz"}), 400
    
    if not re.match(r'^\d{8,11}$', uid):
        return jsonify({
            "error": "Invalid UID format",
            "message": "UID must be 8-11 numeric digits",
            "example": "12345678",
            "Developed By": "Aruz"
        }), 400
    
    if region not in VALID_REGIONS:
        return jsonify({
            "error": "Invalid region",
            "valid_regions": VALID_REGIONS,
            "example": "IND",
            "Developed By": "Aruz"
        }), 400
    
    try:
        tokens = load_tokens(region)
        if tokens is None:
            return jsonify({"error": f"Region {region} is not supported or tokens not found", "Developed By": "Aruz"}), 400
        
        token = tokens[0]['token']
        encrypted_uid = enc(uid)
        if encrypted_uid is None:
            return jsonify({"error": "Encryption of UID failed", "Developed By": "Aruz"}), 500
        
        before_result = make_request(encrypted_uid, region, token)
        if not before_result["success"]:
            return jsonify({"error": before_result["error"], "Developed By": "Aruz"}), 500
        
        before = before_result["data"]
        try:
            jsone = MessageToJson(before)
            data_before = json.loads(jsone)
            before_like = data_before.get('AccountInfo', {}).get('Likes', 0)
            before_like = int(before_like)
        except Exception:
            before_like = 0
        
        if region == "IND":
            url = "https://client.ind.freefiremobile.com/LikeProfile"
        elif region in {"BR", "US", "SAC", "NA"}:
            url = "https://client.us.freefiremobile.com/LikeProfile"
        else:
            url = "https://clientbp.ggblueshark.com/LikeProfile"
        
        send_result = asyncio.run(send_multiple_requests(uid, region, url))
        if not isinstance(send_result, dict) or "success_count" not in send_result:
            return jsonify({"error": send_result.get("error", "Failed to send like requests"), "Developed By": "Aruz"}), 500
        
        after_result = make_request(encrypted_uid, region, token)
        if not after_result["success"]:
            return jsonify({"error": after_result["error"], "Developed By": "Aruz"}), 500
        
        after = after_result["data"]
        try:
            jsone_after = MessageToJson(after)
            data_after = json.loads(jsone_after)
            after_like = int(data_after.get('AccountInfo', {}).get('Likes', 0))
            player_name = data_after.get('AccountInfo', {}).get('PlayerNickname', '')
        except Exception:
            after_like = 0
            player_name = ''
        
        like_given = after_like - before_like
        status = 1 if like_given > 0 else 2
        
        if status == 2:
            return jsonify({
                "success": True,
                "data": {
                    "UID": uid,
                    "message": f"UID already received max likes today. Try again after 3:00 AM Egyptian Time",
                    "Developed By": "Aruz"
                }
            }), 200
        
        result = {
            "success": True,
            "data": {
                "LikesGivenByAPI": like_given,
                "LikesafterCommand": after_like,
                "LikesbeforeCommand": before_like,
                "PlayerNickname": player_name,
                "UID": uid,
                "status": status,
                "Developed By": "Aruz"
            }
        }
        return jsonify(result["data"]), 200
    except Exception as e:
        app.logger.error(f"Error processing request: {e}")
        return jsonify({"error": "Internal server error", "Developed By": "Aruz"}), 500

if __name__ == '__main__':
    app.run(threaded=True, use_reloader=False)
