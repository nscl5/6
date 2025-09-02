import time
import requests
from bs4 import BeautifulSoup
from telebot import TeleBot, types
import telebot
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
import concurrent.futures
import pytz
import json
import time
from datetime import datetime
import urllib.parse
import base64
import threading
from retrying import retry
import re
import pycountry
import requests
import json
import os

def stop_bot():
    bot.stop_polling()
    exit()
MAIN="@arshia_mod_fun"
CHAN="@v2ray_Extractor"
v2ray_configs=[]
v2ray_configs_for_sub=[]
v2ray_vless=[]
v2ray_vmess=[]
v2ray_ss=[]
v2ray_trojan=[]
v2ray_tuic=[]
v2ray_hy2=[]
count_vless=0
count_vmess=0
count_ss=0
count_mix=0
count_trojan= 0
count_tuic=0
count_hy2=0
count=1
check_chan=[]
chan_save=[]
conf_save=[]
conf_region={}
markup=types.InlineKeyboardMarkup(row_width=2)
button1=types.InlineKeyboardButton("Github",url="https://github.com/arshiacomplus")
button2=types.InlineKeyboardButton("Author",url="https://t.me/arshiacomplus")
button3=types.InlineKeyboardButton("MahsaNG",url="https://github.com/GFW-knocker/MahsaNG/releases")
button4=types.InlineKeyboardButton("Nikang",url="https://github.com/mahsanet/NikaNG/releases")
button5=types.InlineKeyboardButton("Hiddfy",url="https://github.com/hiddify/hiddify-next/releases")
markup.add(button1 , button2, button3 , button4,button5)
button=types.InlineKeyboardButton("channel",url="https://t.me/arshia_mod_fun")
markup2=types.InlineKeyboardMarkup(row_width=1)
markup2.add(button)
button11=types.InlineKeyboardButton("Stop",callback_data="/st")
markup3=types.InlineKeyboardMarkup(row_width=1)
markup3.add(button11)
REPOSITORY_OWNER = "arshiacomplus"
REPOSITORY_NAME = "V2rayExtractor"
GITHUB_ACCESS_TOKEN = "token"
CHECKER = "sub-checker"
CHECKER_OWNER = "arshiacomplus2"
CHECKER_GITHUB_ACCESS_TOKEN= "token-sub-checker"
CHECKER_WORKFLOW = "just-for-collector.yml"

stop_thread=threading.Event()
thread=threading.Thread(target=main, args=(stop_thread,))
thread.daemon=True
bot = telebot.TeleBot("bot-token")



def get_ip_location(ip):
  """
  Fetches location data for the given IP address from multiple APIs.
  Args:
    ip (str): The IP address to look up.
  Returns:
    list: A list of dictionaries containing location information and whether the ISP is Cloudflare.
    list: A list of error messages encountered.
  """
  token = os.getenv("FINDIP_TOKEN")
  urls = {
    "iplocation": f"https://api.iplocation.net/?ip={ip}",
    "country": f"https://api.country.is/{ip}",
    "findip": f"https://api.findip.net/{ip}/?token={token}",
    "ipapi": f"http://ip-api.com/json/{ip}",
    "ipwiki": f"https://ip.wiki/{ip}/json",
  }
  responses = {}
  errors = []
  for api_name, url in urls.items():
    try:
      response = requests.get(url, timeout=1) # 1 second timeout
      responses[api_name] = response.text
    except requests.exceptions.RequestException as e:
      errors.append(f"{api_name} API error: {e}")
  locs = []
  for api_name, api_response in responses.items():
    try:
      data = json.loads(api_response)
      if api_name == "iplocation":
        if "country_code2" in data:
          locs.append({
            "loc": data["country_code2"],
          })
        elif "response_code" in data and (data["response_code"] == "400" or data["response_code"] == "404"):
          errors.append(f"IP Location API error: {data['response_message'] if 'response_message' in data else 'Unknown error'}")
      elif api_name == "country":
        if "country" in data:
          locs.append({
            "loc": data["country"],
          })
        elif "error" in data:
          errors.append(f"Country API error: {data['error']['message']}")
      elif api_name == "findip":
        if "country" in data:
          locs.append({
            "loc": data["country"]["iso_code"],
          })
        elif "Message" in data or data is None:
          errors.append(f"FindIP API error: {data['Message'] if 'Message' in data else 'Unknown error'}")
      elif api_name == "ipapi":
        if "countryCode" in data:
          locs.append({
            "loc": data["countryCode"],
          })
        elif "message" in data or data is None:
          errors.append(f"IP-API error: {data['message'] if 'message' in data else 'Unknown error'}")
      elif api_name == "ipwiki":
        if "isp" in data:
         locs.append({
       "loc": data["country_code2"],})
        elif "error" in data:
          errors.append(f"IP Wiki API error: {data['error']}")
    except json.JSONDecodeError as e:
      errors.append(f"{api_name} API error: Invalid JSON response")
  return locs, errors
def check_last_github_action_status(
    token: str,
    owner: str,
    repo: str,
    workflow_id: str
):
    api_url = f"https://api.github.com/repos/{owner}/{repo}/actions/workflows/{workflow_id}/runs"
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "Authorization": f"token {token}"
    }
    params = {
        "per_page": 1
    }
    try:
        print(f"Fetching latest run for workflow '{workflow_id}' in '{owner}/{repo}'...")
        response = requests.get(api_url, headers=headers, params=params, timeout=15)
        response.raise_for_status()
        data = response.json()
        if not data or 'workflow_runs' not in data or not data['workflow_runs']:
            print(f"Warning: No workflow runs found for workflow '{workflow_id}' in '{owner}/{repo}'.")
            return False
        latest_run = data['workflow_runs'][0]
        run_id = latest_run.get('id')
        status = latest_run.get('status')
        conclusion = latest_run.get('conclusion')
        print(f"Latest run details: ID={run_id}, Status='{status}', Conclusion='{conclusion}'")
        if status == 'completed':
            if conclusion == 'success':
                print("Last run was successful.")
                return True
            else:
                print(f"Last run completed but was not successful (Conclusion: {conclusion}).")
                return False
        else:
            print(f"Last run is not yet completed (Status: {status}).")
            return "no"
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
        print(f"Response status code: {http_err.response.status_code}")
        print(f"Response text: {http_err.response.text}")
        return False
    except requests.exceptions.RequestException as req_err:
        print(f"Error during requests to {api_url}: {req_err}")
        return False
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return False
# Example usage
def update_sub_html(text,path,repository_owner,repository_name,token):
    FILE_PATH=path
    REPOSITORY_OWNER=repository_owner
    REPOSITORY_NAME=repository_name
    GITHUB_ACCESS_TOKEN=token
    headers = {"Authorization": f"token {GITHUB_ACCESS_TOKEN}"}
    response = requests.get(f"https://api.github.com/repos/{REPOSITORY_OWNER}/{REPOSITORY_NAME}/contents/{FILE_PATH}", headers=headers)
    if response.status_code == 404:
        new_content = text
        new_content = base64.b64encode(new_content.encode("utf-8")).decode("utf-8")
        payload = {
            "message": "Create sub.html",
            "content": new_content
        }
        response = requests.put(f"https://api.github.com/repos/{REPOSITORY_OWNER}/{REPOSITORY_NAME}/contents/{FILE_PATH}", headers=headers, data=json.dumps(payload))
        response.raise_for_status()  # Raise an exception if the request fails
        print("File created successfully!")
    else:
        response.raise_for_status()  # Raise an exception if the request fails
        file_data = response.json()
        new_content = text
        new_content=base64.b64encode(new_content.encode("utf-8")).decode("utf-8")
        # 3. Create the update payload
        payload = {
            "message": "Update sub.html",
            "content": new_content,
            "sha": file_data["sha"],
        }
        # 4. Send the update request
        response = requests.put(f"https://api.github.com/repos/{REPOSITORY_OWNER}/{REPOSITORY_NAME}/contents/{FILE_PATH}", headers=headers, data=json.dumps(payload))
        response.raise_for_status()  # Raise an exception if the request fails
        print("File updated successfully!")
def get_github_file_content(
    path: str,
    repository_owner: str,
    repository_name: str,
    token: str
):
    api_url = f"https://api.github.com/repos/{repository_owner}/{repository_name}/contents/{path}"
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "Authorization": f"token {token}"
    }
    print(f"Attempting to fetch content of '{path}' from '{repository_owner}/{repository_name}'...")
    try:
        response = requests.get(api_url, headers=headers, timeout=15)
        if response.status_code == 404:
            print(f"Error: File not found at path '{path}'.")
            return None
        response.raise_for_status()
        file_data = response.json()
        if 'content' not in file_data or not isinstance(file_data['content'], str):
             print(f"Error: 'content' field missing or not a string in API response for '{path}'. Response: {file_data}")
             return None
        encoded_content = file_data['content']
        decoded_bytes = base64.b64decode(encoded_content)
        try:
            content_str = decoded_bytes.decode('utf-8')
            print(f"Successfully fetched and decoded content for '{path}'.")
            return content_str
        except UnicodeDecodeError:
            print(f"Error: Could not decode content from '{path}' using UTF-8.")
            return None
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred while fetching '{path}': {http_err}")
        print(f"Response status code: {response.status_code}")
        print(f"Response text: {response.text}")
        return None
    except requests.exceptions.RequestException as req_err:
        print(f"Network or request error occurred while fetching '{path}': {req_err}")
        return None
    except base64.binascii.Error:
        print(f"Error: Could not decode base64 content from API response for '{path}'.")
        return None
    except KeyError as key_err:
         print(f"Error: Unexpected API response structure for '{path}'. Missing key: {key_err}")
         return None
    except Exception as e:
        print(f"An unexpected error occurred while fetching '{path}': {e}")
        return None
def delete_all_files_in_dir(owner, repo, directory_path, token):
    """
    Deletes all files within a specific directory in a GitHub repository sequentially.
    """
    api_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{directory_path}"
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "Authorization": f"token {token}"
    }
    try:
        print(f"Fetching contents of directory '{directory_path}' to delete...")
        response = requests.get(api_url, headers=headers, timeout=20)
        if response.status_code == 404:
            print(f"Directory '{directory_path}' not found. Nothing to delete.")
            return True
        response.raise_for_status()
        files = response.json()
        if not isinstance(files, list):
            print(f"Path '{directory_path}' is not a directory. Skipping deletion.")
            return False
        if not files:
            print(f"Directory '{directory_path}' is already empty.")
            return True
        print(f"Found {len(files)} files to delete. Deleting sequentially...")
        for file_info in files:
            if file_info.get('type') == 'file':
                file_path = file_info['path']
                sha = file_info['sha']
                delete_payload = {
                    "message": f"chore: delete file {file_path}",
                    "sha": sha
                }
                try:
                    del_response = requests.delete(
                        file_info['url'],
                        headers=headers,
                        json=delete_payload,
                        timeout=20
                    )
                    if del_response.status_code == 200:
                        print(f"Successfully deleted {file_path}")
                    else:
                        print(f"Failed to delete {file_path}. Status: {del_response.status_code}, Response: {del_response.text}")
                    time.sleep(0.5)
                except requests.exceptions.RequestException as req_err:
                    print(f"Request failed for deleting {file_path}: {req_err}")
        print(f"Finished cleaning directory '{directory_path}'.")
        return True
    except requests.exceptions.RequestException as e:
        print(f"An unexpected error occurred while processing directory '{directory_path}': {e}")
    return False
def clean_config_tag(config_line):
    """
    این تابع یک کانفیگ را می‌گیرد و اطلاعات موقعیت مکانی (مانند ::US) را از تگ آن حذف می‌کند.
    """
    config_line = config_line.strip()
    if '#' not in config_line:
        return config_line  # اگر تگ وجود نداشت، همان را برگردان

    parts = config_line.split('#', 1)
    base_uri = parts[0]
    tag = parts[1]

    # فقط قسمتی از تگ را نگه می‌دارد که قبل از :: قرار دارد
    clean_tag = tag.split('::')[0]

    return f"{base_uri}#{clean_tag}"
def main(dfd):
    def clear_p(configs_list: list) -> list:
        unique_configs = {}
        for config_line in configs_list:
            config_line = config_line.strip()
            if not config_line:
                continue
            unique_key = None
            if config_line.startswith("vmess://"):
                try:
                    encoded_part = config_line.split("://")[1]
                    missing_padding = len(encoded_part) % 4
                    if missing_padding:
                        encoded_part += '=' * (4 - missing_padding)
                    decoded_json = base64.b64decode(encoded_part).decode('utf-8')
                    data = json.loads(decoded_json)
                    unique_key = ("vmess", data.get('add'), data.get('port'), data.get('id'))
                except (json.JSONDecodeError, base64.binascii.Error, Exception):
                    unique_key = config_line
            else:
                unique_key = config_line.split('#', 1)[0]
            if unique_key not in unique_configs:
                unique_configs[unique_key] = config_line
        final_list = [f"{config}\n" for config in unique_configs.values()]
        return final_list
    global conf_save, chan_save,v2ray_configs,v2ray_configs_for_sub,check_chan,v2ray_vless,v2ray_vmess,v2ray_ss,v2ray_trojan,v2ray_tuic,v2ray_hy2,count_vless,count_vmess,count_ss,count_mix,count_trojan,count_tuic,count_hy2,conf_region,count_vless,count_vmess,count_ss,count_mix,count_trojan,count_tuic,count_hy2
    while True:
        print("start")
        telegram_urls = [
            "https://t.me/s/prrofile_purple",
            "https://t.me/s/v2line",
            "https://t.me/s/v2ray1_ng",
            "https://t.me/s/v2ray_swhil",
            "https://t.me/s/v2rayng_fast",
            "https://t.me/s/v2rayng_vpnrog",
            "https://t.me/s/v2raytz",
            "https://t.me/s/vmessorg",
            "https://t.me/s/ISVvpn",
            "https://t.me/s/v2line",
            "https://t.me/s/forwardv2ray",
            "https://t.me/s/PrivateVPNs",
            "https://t.me/s/VlessConfig",
            "https://t.me/s/V2pedia",
            "https://t.me/s/v2rayNG_Matsuri",
            "https://t.me/s/proxystore11",
            "https://t.me/s/DirectVPN",
            "https://t.me/s/OutlineVpnOfficial",
            "https://t.me/s/networknim",
            "https://t.me/s/beiten",
            "https://t.me/s/MsV2ray",
            "https://t.me/s/foxrayiran",
            "https://t.me/s/DailyV2RY",
            "https://t.me/s/yaney_01",
            "https://t.me/s/EliV2ray",
            "https://t.me/s/ServerNett",
            "https://t.me/s/proxystore11",
            "https://t.me/s/v2rayng_fa2",
            "https://t.me/s/v2rayng_org",
            "https://t.me/s/V2rayNGvpni",
            "https://t.me/s/v2rayNG_VPNN",
            "https://t.me/s/v2_vmess",
            "https://t.me/s/FreeVlessVpn",
            "https://t.me/s/vmess_vless_v2rayng",
            "https://t.me/s/freeland8",
            "https://t.me/s/vmessiran",
            "https://t.me/s/Outline_Vpn",
            "https://t.me/s/V2rayNG3",
            "https://t.me/s/ShadowsocksM",
            "https://t.me/s/ShadowSocks_s",
            "https://t.me/s/VmessProtocol",
            "https://t.me/s/Easy_Free_VPN",
            "https://t.me/s/V2Ray_FreedomIran",
            "https://t.me/s/V2RAY_VMESS_free",
            "https://t.me/s/v2ray_for_free",
            "https://t.me/s/V2rayN_Free",
            "https://t.me/s/free4allVPN",
            "https://t.me/s/configV2rayForFree",
            "https://t.me/s/FreeV2rays",
            "https://t.me/s/DigiV2ray",
            "https://t.me/s/v2rayNG_VPN",
            "https://t.me/s/freev2rayssr",
            "https://t.me/s/v2rayn_server",
            "https://t.me/s/iranvpnet",
            "https://t.me/s/vmess_iran",
            "https://t.me/s/configV2rayNG",
            "https://t.me/s/vpn_proxy_custom",
            "https://t.me/s/vpnmasi",
            "https://t.me/s/ViPVpn_v2ray",
            "https://t.me/s/vip_vpn_2022",
            "https://t.me/s/FOX_VPN66",
            "https://t.me/s/YtTe3la",
            "https://t.me/s/ultrasurf_12",
            "https://t.me/s/frev2rayng",
            "https://t.me/s/FreakConfig",
            "https://t.me/s/Awlix_ir",
            "https://t.me/s/arv2ray",
            "https://t.me/s/flyv2ray",
            "https://t.me/s/free_v2rayyy",
            "https://t.me/s/ip_cf",
            "https://t.me/s/lightning6",
            "https://t.me/s/mehrosaboran",
            "https://t.me/s/oneclickvpnkeys",
            "https://t.me/s/outline_vpn",
            "https://t.me/s/outlinev2rayng",
            "https://t.me/s/outlinevpnofficial",
            "https://t.me/s/v2rayngvpn",
            "https://t.me/s/V2raNG_DA",
            "https://t.me/s/V2rayNg_madam",
            "https://t.me/s/v2boxxv2rayng",
            "https://t.me/s/configshub2",
            "https://t.me/s/v2ray_configs_pool",
            "https://t.me/s/hope_net",
            "https://t.me/s/everydayvpn",
            "https://t.me/s/v2nodes",
            "https://t.me/s/shadowproxy66",
            "https://t.me/s/free_nettm"
        ]
        global v2ray_configs
        global v2ray_configs_for_sub
        all_v2ray_configs = []
        executor=ThreadPoolExecutor(max_workers=150)
        try :
                for url22 in telegram_urls:
                    executor.submit(get_v2ray_links, url22)
        except Exception as E:
            print("Error :",E)
        finally:
            executor.shutdown(wait=True)
        print("igo")
        all_individual_configs = [
            line.strip()
            for chunk in v2ray_configs_for_sub
            for line in chunk.splitlines()
            if line.strip()
        ]
        v2ray_configs_for_sub2 = clear_p(all_individual_configs)
        print("Fetching previous mix/sub.html content from main repo...")
        old_mix_content = get_github_file_content(
            path="mix/sub.html",
            repository_owner=REPOSITORY_OWNER,
            repository_name=REPOSITORY_NAME,
            token=GITHUB_ACCESS_TOKEN
        )
        if old_mix_content:
            cleaned_old_lines = [clean_config_tag(line) for line in old_mix_content.splitlines() if line.strip()]
            old_configs_list = [line + '\n' for line in cleaned_old_lines]
            print(f"Found {len(old_configs_list)} old configs. Merging with {len(v2ray_configs_for_sub2)} new configs.")
            combined_configs = v2ray_configs_for_sub2 + old_configs_list
            print(f"Total before deduplication: {len(combined_configs)}")
            v2ray_configs_for_sub2 = clear_p(combined_configs)
            print(f"Total unique configs to be tested: {len(v2ray_configs_for_sub2)}")
        else:
            print("No previous mix/sub.html found or it was empty. Proceeding with only new configs.")
        temp=""
        print("check loc")
        try:
            b = "".join(v2ray_configs_for_sub2)
            update_sub_html(b, "normal.txt", CHECKER_OWNER,CHECKER,CHECKER_GITHUB_ACCESS_TOKEN)
            while True:
                time.sleep(900)
                ch=check_last_github_action_status(CHECKER_GITHUB_ACCESS_TOKEN, CHECKER_OWNER, CHECKER , CHECKER_WORKFLOW)
                if ch==True:
                    print("chcekd , yes")
                    break
                elif ch!= "no":
                    break
                print("no again")
            v2ray_configs_content=get_github_file_content("final.txt", CHECKER_OWNER , CHECKER , CHECKER_GITHUB_ACCESS_TOKEN).splitlines()
            v2ray_configs=[]
            for i in v2ray_configs_content:
                v2ray_configs.append(i+"\n")
            v2ray_configs_for_sub2=clear_p(v2ray_configs)
            v2ray_configs_for_sub=clear_p(v2ray_configs)
            if not v2ray_configs :
                print("Error: final.txt is empty or could not be fetched. Exiting.")
                return
            else:
                min_len = len(v2ray_configs)
                print(f"Found {min_len} configs and corresponding locations.")
        except Exception as E:
            print(E)
        print("Cleaning up old location files before uploading new ones...")
        delete_all_files_in_dir(
            owner=REPOSITORY_OWNER,
            repo=REPOSITORY_NAME,
            directory_path="loc",
            token=GITHUB_ACCESS_TOKEN
        )
        print("Old location files cleaned up.")
        print("Grouping configs by location...")
        grouped_configs_by_location = {}
        for config_line_with_newline in v2ray_configs:
            config_stripped = config_line_with_newline.strip()
            if not config_stripped:
                continue
            location_code = "XX"
            if config_stripped.startswith("vmess://"):
                try:
                    main_part = config_stripped.split("://", 1)[1]
                    base64_encoded_part = main_part.split('#', 1)[0]
                    missing_padding = len(base64_encoded_part) % 4
                    if missing_padding:
                        base64_encoded_part += '=' * (4 - missing_padding)
                    decoded_bytes = base64.b64decode(base64_encoded_part)
                    decoded_json_str = decoded_bytes.decode('utf-8', errors='ignore')
                    vmess_data = json.loads(decoded_json_str)
                    ps_field_content = vmess_data.get("ps", "")
                    ps_match = re.search(r'::([A-Za-z]{2})$', ps_field_content)
                    if ps_match:
                        location_code = ps_match.group(1).upper()
                    elif '#' in main_part:
                        try:
                            external_tag_encoded = main_part.split("#", 1)[1]
                            external_tag_decoded = urllib.parse.unquote(external_tag_encoded)
                            external_match = re.search(r'::([A-Za-z]{2})$', external_tag_decoded)
                            if external_match:
                                location_code = external_match.group(1).upper()
                        except Exception:
                            pass
                except (base64.binascii.Error, UnicodeDecodeError, json.JSONDecodeError):
                    print(f"Warning: Could not decode vmess or parse JSON for location: {config_stripped[:60]}... Using XX.")
                except Exception as e:
                    print(f"Error processing vmess for location: '{config_stripped[:60]}': {e}. Using XX.")
            elif "#" in config_stripped:
                try:
                    tag_part_encoded = config_stripped.split("#", 1)[1]
                    tag_part_decoded = urllib.parse.unquote(tag_part_encoded)
                    match = re.search(r'::([A-Za-z]{2})$', tag_part_decoded)
                    if match:
                        location_code = match.group(1).upper()
                except IndexError:
                    pass
                except Exception as e:
                    print(f"Error processing tag for location in non-vmess: '{config_stripped[:60]}': {e}. Using XX.")
            if location_code not in grouped_configs_by_location:
                grouped_configs_by_location[location_code] = []
            grouped_configs_by_location[location_code].append(config_line_with_newline)
        owner = REPOSITORY_OWNER
        repo = REPOSITORY_NAME
        token = GITHUB_ACCESS_TOKEN
        for location_code, config_lines_list in grouped_configs_by_location.items():
            country_flag = "❓"
            try:
                country = pycountry.countries.get(alpha_2=location_code)
                if country and hasattr(country, 'flag'):
                    country_flag = country.flag
            except Exception as e:
                print(f"Could not find country/flag for code '{location_code}': {e}")
            final_content_for_region = "".join(config_lines_list)
            file_path = f"loc/{location_code} {country_flag}.txt"
            print(f"Preparing to write {len(config_lines_list)} configs to {file_path}")
            try:
                update_sub_html(final_content_for_region, file_path, owner, repo, token)
                print(f"Successfully submitted/updated {file_path}")
            except Exception as e:
                print(f"Error updating file {file_path}: {e}")
        def sep(all_unique_configs,protocol):
            list1=[]
            for config_line in all_unique_configs:
                cleaned_line = config_line.strip()
                if cleaned_line and  str(config_line).startswith(protocol):
                    list1.append(config_line)
            return list1
        v2ray_vmess2=sep(v2ray_configs_for_sub2,"vmess://")
        v2ray_vless2=sep(v2ray_configs_for_sub2,"vless://")
        v2ray_trojan2=sep(v2ray_configs_for_sub2,"trojan://")
        v2ray_ss2=sep(v2ray_configs_for_sub2,"ss://")
        v2ray_hy22=sep(v2ray_configs_for_sub2,"hy2://")
        try:
            save_configs_by_region(v2ray_configs_for_sub,v2ray_configs_for_sub2,v2ray_vmess2,v2ray_vless2,v2ray_trojan2,v2ray_ss2,v2ray_hy22)
        except Exception as e:
            print(e)
        mess=""
        print(len(conf_save))
        print(len(chan_save))
            # for i in range(len(chan_save)-1):
        #     mess+=f"{chan_save[i]} : {conf_save[i]} configs\n"
        # mess="send /get@id to  @V2RAY_Extractor_arshiaus_bot\n\n"+mess
        # if len(mess)>=4000:
        #     bot.send_message(chat_id=MAIN,text=mess[:4000])
        #     bot.send_message(chat_id=MAIN,text=mess[4000:])
        # else:
        #     bot.edit_message_text(chat_id=MAIN, message_id="432",text=mess)
        v2ray_configs=[]
        count_vless=0
        count_vmess=0
        count_ss=0
        count_mix=0
        count_trojan= 0
        count_tuic=0
        count_hy2=0
        time.sleep(3600*24)

def regroup_configs_from_subchecker_result(checked_configs_list: list) -> dict:
    regrouped = {}
    for config_line in checked_configs_list:
        config_line_stripped = config_line.strip()
        if not config_line_stripped:
            continue
        channel_id_in_tag = "unknown_source"
        if config_line_stripped.startswith("vmess://"):
            try:
                main_part = config_line_stripped[len("vmess://"):]
                b64_encoded_part = main_part.split('#', 1)[0]
                missing_padding = len(b64_encoded_part) % 4
                if missing_padding: b64_encoded_part += '=' * (4 - missing_padding)
                decoded_json_str = base64.b64decode(b64_encoded_part).decode('utf-8', errors='ignore')
                vmess_params = json.loads(decoded_json_str)
                ps_tag_content = vmess_params.get("ps", "")
                if ">>@" in ps_tag_content:
                    channel_part_match = re.search(r'>>@([\w\d_]+)(?:$|::)', ps_tag_content)
                    if channel_part_match:
                        channel_name = channel_part_match.group(1)
                        channel_id_in_tag = "@" + channel_name if not channel_name.startswith("@") else channel_name
            except Exception:
                pass
        if channel_id_in_tag == "unknown_source" and '#' in config_line_stripped:
             try:
                hash_tag_content_encoded = config_line_stripped.split('#', 1)[-1]
                hash_tag_content_decoded = urllib.parse.unquote(hash_tag_content_encoded)
                match = re.search(r'>>@([\w\d_]+)', hash_tag_content_decoded)
                if match:
                    channel_id_in_tag = "@" + match.group(1)
             except Exception:
                pass
        if channel_id_in_tag not in regrouped:
            regrouped[channel_id_in_tag] = []
        regrouped[channel_id_in_tag].append(config_line_stripped)
    return regrouped
def send_grouped_configs_to_telegram(source_channel_id: str, configs: list):
    if not configs:
        return
    from_C_display = source_channel_id
    messages_to_send = []
    current_message_batch = []
    for i, config_line in enumerate(configs):
        current_message_batch.append(config_line)
        if (i + 1) % 10 == 0 or (i + 1) == len(configs):
            messages_to_send.append("\n".join(current_message_batch))
            current_message_batch = []
    iran_tz = pytz.timezone("Asia/Tehran")
    iran_time = datetime.now(iran_tz)
    time_ir = iran_time.strftime("%Y-%m-%d %H:%M:%S")
    for config_batch_str in messages_to_send:
        if config_batch_str.strip():
            try:
                from_link_part = from_C_display[1:] if from_C_display.startswith("@") else from_C_display
                from_link = f"https://t.me/{from_link_part}"
                message_text = (
                    f"```\n{config_batch_str.strip()}\n```\n\n"
                    f"Time: {time_ir}\n\n"
                    f"From [{from_C_display}]({from_link})\n\n"
                    f"MainChannel= [@arshia_mod_fun](tg://user?id=2093246093) \U0001F977\n"
                    f"Channel= [@v2ray_Extractor](tg://user?id=2168955033) \U0001F977"
                )
                bot.send_message("@v2ray_Extractor", message_text, reply_markup=markup, parse_mode='Markdown', disable_web_page_preview=True)
                time.sleep(1)
            except Exception as e:
                print(f"Error sending message for {from_C_display}: {e}")
def get_v2ray_links(url):
    global v2ray_configs
    global check_chan
    global v2ray_configs_for_sub
    ad_url="@"+str(url).split("//")[1].split("/")[2]
    print(ad_url)
    response = requests.get(url)
    if response.status_code == 200:
        soup = BeautifulSoup(response.content, 'html.parser')
        divs = soup.find_all('div', class_='tgme_widget_message_text')
        divs2 = soup.find_all('div', class_='tgme_widget_message_text js-message_text before_footer')
        spans = soup.find_all('span', class_='tgme_widget_message_text')
        codes = soup.find_all('code')
        span = soup.find_all('span')
        main = soup.find_all('div')
        all_tags = divs + spans + codes + divs2 + span + main
        tag_nam="  @arshiacomplus [bot]"
        save_temp=""
        for tag in all_tags:
            text2 = tag.get_text()
            text2=str(text2)
            pattern = r'(vmess://|vless://|ss://|hy2://|trojan://|hysteria2://)'
            output_string1 = re.sub(pattern, r'\n\1', text2).lstrip().split("\n")
            for text in output_string1:
                if text.startswith('vless://') or text.startswith('vmess://') or text.startswith('ss://') or text.startswith('trojan://') or  text.startswith("hy2://") or text.startswith("hysteria2://"):
                    if text.startswith("vmess://"):
                        encoded_part = text.split("://")[1]
                        missing_padding = len(encoded_part) % 4
                        if missing_padding:
                            encoded_part += "=" * (4 - missing_padding)
                        decoded = base64.b64decode(encoded_part).decode("utf-8")
                        vmess_data = json.loads(decoded)
                        vmess_data["ps"]=f">>{ad_url}"
                        updated_json_str = json.dumps(vmess_data, separators=(',', ':'))
                        updated_b64_encoded_part = base64.b64encode(updated_json_str.encode('utf-8')).decode('utf-8')
                        text="vmess://" + updated_b64_encoded_part
                        save_temp+="\n"+text+"\n"
                    else:
                        save_temp+=f"\n{text.split('#')[0]+'#'}>>{ad_url}\n"
        v2ray_configs_for_sub.append(save_temp)
        print("finished")
        return
    return
def save_configs_by_region(configs_sub,configs_sub2,v2ray_vmess2,v2ray_vless2,v2ray_trojan2,v2ray_ss2,v2ray_hy22):
    global count, count_vless,count_vmess,count_ss,count_mix,count_trojan,count_tuic,count_hy2
    global chan_save
    len_configs=len(configs_sub)
    print("conf")
    print("configs : ",len_configs)
    b=""
    for ik in configs_sub2:
        if len(ik) >13:
            count_mix+=1
            b+=ik
    b=b.strip()
    update_sub_html(b,"mix/sub.html", REPOSITORY_OWNER, REPOSITORY_NAME,GITHUB_ACCESS_TOKEN)
    b=""
    for ik in v2ray_vmess2:
        if len(ik) >13:
            count_vmess+=1
            b+=ik
    b=b.strip()
    update_sub_html(b,"vmess.html", REPOSITORY_OWNER, REPOSITORY_NAME,GITHUB_ACCESS_TOKEN)
    b=""
    for ik in v2ray_vless2:
        if len(ik) >13:
            count_vless+=1
            b+=ik
    b=b.strip()
    update_sub_html(b,"vless.html", REPOSITORY_OWNER, REPOSITORY_NAME,GITHUB_ACCESS_TOKEN)
    b=""
    for ik in v2ray_trojan2:
        if len(ik) >13:
            count_trojan+=1
            b+=ik
    b=b.strip()
    update_sub_html(b,"trojan.html", REPOSITORY_OWNER, REPOSITORY_NAME,GITHUB_ACCESS_TOKEN)
    b=""
    for ik in v2ray_ss2:
        if len(ik) >13:
            count_ss+=1
            b+=ik
    b=b.strip()
    update_sub_html(b,"ss.html", REPOSITORY_OWNER, REPOSITORY_NAME,GITHUB_ACCESS_TOKEN)
    b=""
    for ik in v2ray_hy22:
        if len(ik) >13:
            count_hy2+=1
            b+=ik
    b=b.strip()
    update_sub_html(b,"hy2.html", REPOSITORY_OWNER, REPOSITORY_NAME,GITHUB_ACCESS_TOKEN)
    # b=""
    # for ik in v2ray_tuic2:
    #     if len(ik) >13:
    #         count_tuic+=1
    #         b+=ik
    # b=b.strip()
    # update_sub_html(b,"tuic.html", REPOSITORY_OWNER, REPOSITORY_NAME,GITHUB_ACCESS_TOKEN)
    time.sleep(1)
    try:
        bot.edit_message_text(chat_id=MAIN, message_id="581",text=f"mix sub configs: {count_mix}\n```mix\nhttps://raw.githubusercontent.com/arshiacomplus/v2rayExtractor/refs/heads/main/mix/sub.html```\n\nvless sub configs: {count_vless}\n```vless\nhttps://raw.githubusercontent.com/arshiacomplus/v2rayExtractor/refs/heads/main/vless.html```\n\nvmess sub configs: {count_vmess}\n```vmess\nhttps://raw.githubusercontent.com/arshiacomplus/v2rayExtractor/refs/heads/main/vmess.html```\n\nss sub configs: {count_ss}\n```shadowsocks\nhttps://raw.githubusercontent.com/arshiacomplus/v2rayExtractor/refs/heads/main/ss.html```\n\ntrojan sub configs: {count_trojan}\n```trojan\nhttps://raw.githubusercontent.com/arshiacomplus/v2rayExtractor/refs/heads/main/trojan.html``` \n\nhy2 sub configs: {count_hy2}\n```hy2\nhttps://raw.githubusercontent.com/arshiacomplus/v2rayExtractor/refs/heads/main/hy2.html```\n\ncreated by arshiacomplus's CollectorBot ",parse_mode='Markdown')
    except Exception:
        bot.edit_message_text(chat_id=MAIN, message_id="581",text=f"mix sub configs: {count_mix}\n```mix\nhttps://raw.githubusercontent.com/arshiacomplus/v2rayExtractor/refs/heads/main/mix/sub.html```\n\nvless sub configs: {count_vless}\n```vless\nhttps://raw.githubusercontent.com/arshiacomplus/v2rayExtractor/refs/heads/main/vless.html```\n\nvmess sub configs: {count_vmess}\n```vmess\nhttps://raw.githubusercontent.com/arshiacomplus/v2rayExtractor/refs/heads/main/vmess.html```\n\nss sub configs: {count_ss}\n```shadowsocks\nhttps://raw.githubusercontent.com/arshiacomplus/v2rayExtractor/refs/heads/main/ss.html```\n\ntrojan sub configs: {count_trojan}\n```trojan\nhttps://raw.githubusercontent.com/arshiacomplus/v2rayExtractor/refs/heads/main/trojan.html``` \n\nhy2 sub configs: {count_hy2}\n```hy2\nhttps://raw.githubusercontent.com/arshiacomplus/v2rayExtractor/refs/heads/main/hy2.html```\n\ncreated by arshiacomplus's CollectorBot ",parse_mode='Markdown')
    print("igo")
    regroupped_and_checked_configs = regroup_configs_from_subchecker_result(configs_sub)
    count=1
    executor=ThreadPoolExecutor(max_workers=150)
    try :
        for channel_id, list_of_configs_from_checker in regroupped_and_checked_configs.items():
                if list_of_configs_from_checker:
                    executor.submit(send_grouped_configs_to_telegram, channel_id, list_of_configs_from_checker)
                time.sleep(5)
    except Exception as E:
            print("Error :",E)
    finally:
            executor.shutdown(wait=True)
    print("i no")
    count=1
def upload_to_bashupload(config_data):
            @retry(stop_max_attempt_number=3, wait_fixed=2000, retry_on_exception=lambda x: isinstance(x, ConnectionError))
            def file_o():
                files = {'file': ('output.json', config_data)}
                try:
                    response = requests.post('https://bashupload.com/', files=files, timeout=30)
                except Exception:
                    response = requests.post('https://bashupload.com/', files=files, timeout=50)
                return response
            response = file_o()
            if response.ok:
                download_link = response.text.strip()
                download_link_with_query = download_link[59:len(download_link)-27] + "?download=1"
                true=""
                for i in download_link_with_query :
                    if true=="":
                        if i != "b":
                            pass
                        else:
                            true="https://"
                            true+=i
                    else:
                        true+=i
                return true
@bot.message_handler(commands=["get"], func=lambda message: message.chat.type== "private")
def get(message :str):
    def get_theard():
        ms=message
        user_id=ms.from_user.id
        mem=bot.get_chat_member(MAIN, user_id)
        if mem.status=="left":
            bot.send_message(ms.chat.id,"لطفا اول عضو کانال شوید",reply_markup=markup2)
            return
        chan=ms.text.split("/get")[1]
        print(chan)
        conf_30=[]
        temp=""
        if chan=="mix":
            bot.send_message(ms.chat.id, "https://raw.githubusercontent.com/arshiacomplus/v2rayExtractor/refs/heads/main/mix/sub.html#https://t.me/v2ray_Extractor_mix")
        else:
            bot.send_message(ms.chat.id, "This command did not found!")
    thread3=threading.Thread(target=get_theard)
    thread3.start()
def go_thread():
    thread.start()
@bot.message_handler(commands=["st"])
def stop_thread(ms):
    stop_bot()
@bot.message_handler(commands=["go"])
def start_thread(ms):
    try:
        go_thread()
    except Exception as e:
        bot.send_message("@arshiacomplus", f"Bot get Error: {e}",reply_markup=markup3)
bot.infinity_polling()
