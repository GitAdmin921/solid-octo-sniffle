import os, re, sqlite3, threading, secrets, base64, urllib.parse, urllib.request, urllib.error, json, time
from datetime import datetime, timezone
from functools import wraps
from urllib.parse import quote
from flask import Flask, request, jsonify, render_template, session, redirect, url_for, flash
import phonenumbers
from phonenumbers import geocoder, carrier

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.getenv('DATABASE_PATH', os.path.join(BASE_DIR, 'data.sqlite3'))
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY') or secrets.token_hex(32)
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', '')
BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN', '')
ALLOWED_TELEGRAM_USERS = {x.strip() for x in os.getenv('ALLOWED_TELEGRAM_USER_IDS', '').split(',') if x.strip()}
TWILIO_ACCOUNT_SID = os.getenv('TWILIO_ACCOUNT_SID', '')
TWILIO_AUTH_TOKEN = os.getenv('TWILIO_AUTH_TOKEN', '')
TWILIO_VERIFY_SERVICE_SID = os.getenv('TWILIO_VERIFY_SERVICE_SID', '')
OTP_CONFIGURED = all((TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_VERIFY_SERVICE_SID))

OFFICIAL_SUSPECT_URL = 'https://cybercrime.gov.in/Webform/suspect_search_repository.aspx'
CHAKSHU_URL = 'https://sancharsaathi.gov.in/'
CYBER_REPORT_URL = 'https://cybercrime.gov.in/Webform/cyber_suspect.aspx'


def db():
    # Render Free has no persistent disk mounted at /var/data. If the configured
    # path is unavailable, fall back to writable temporary storage so the app can
    # still start. This fallback is ephemeral; use a persistent disk or managed DB
    # when reports/notes must survive redeploys and restarts.
    global DB_PATH
    parent = os.path.dirname(DB_PATH)
    try:
        if parent:
            os.makedirs(parent, exist_ok=True)
        # Confirm the configured location is writable before SQLite opens it.
        probe = DB_PATH + '.write-test'
        with open(probe, 'a', encoding='utf-8'):
            pass
        os.remove(probe)
    except (PermissionError, OSError):
        DB_PATH = os.path.join('/tmp', 'bharat-number-osint.sqlite3')
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db() as con:
        con.execute('''CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            number TEXT NOT NULL,
            category TEXT NOT NULL,
            description TEXT NOT NULL,
            reporter_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            caller_label TEXT NOT NULL DEFAULT ''
        )''')
        # Safe migration for databases created by an earlier version.
        columns = {row['name'] for row in con.execute('PRAGMA table_info(reports)').fetchall()}
        if 'caller_label' not in columns:
            con.execute("ALTER TABLE reports ADD COLUMN caller_label TEXT NOT NULL DEFAULT ''")
        con.execute('CREATE INDEX IF NOT EXISTS idx_reports_number ON reports(number)')
        con.execute('''CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            number TEXT NOT NULL,
            note TEXT NOT NULL,
            owner_id TEXT NOT NULL,
            created_at TEXT NOT NULL
        )''')


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def normalize_number(raw):
    raw = (raw or '').strip()
    if not raw:
        raise ValueError('Enter a phone number.')
    try:
        parsed = phonenumbers.parse(raw, 'IN')
    except phonenumbers.NumberParseException:
        raise ValueError('Could not parse that number. Use an Indian number, e.g. 9876543210 or +919876543210.')
    if parsed.country_code != 91:
        raise ValueError('This tool currently accepts Indian (+91) numbers only.')
    if not phonenumbers.is_possible_number(parsed) or not phonenumbers.is_valid_number(parsed):
        raise ValueError('This does not look like a valid Indian phone number.')
    return phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164), parsed


def lookup_number(raw):
    e164, parsed = normalize_number(raw)
    with db() as con:
        rows = con.execute('SELECT category, description, created_at, caller_label FROM reports WHERE number=? ORDER BY id DESC LIMIT 50', (e164,)).fetchall()
        total = con.execute('SELECT COUNT(*) FROM reports WHERE number=?', (e164,)).fetchone()[0]
        category_counts = con.execute('SELECT category, COUNT(*) n FROM reports WHERE number=? GROUP BY category ORDER BY n DESC', (e164,)).fetchall()
        labels = con.execute("SELECT caller_label, COUNT(*) n FROM reports WHERE number=? AND TRIM(caller_label)<>'' GROUP BY caller_label ORDER BY n DESC LIMIT 10", (e164,)).fetchall()
    # Carrier and geographic metadata are library estimates, not subscriber identity or live location.
    area = geocoder.description_for_number(parsed, 'en') or 'Not available'
    carrier_name = carrier.name_for_number(parsed, 'en') or 'Not available'
    return {
        'number': e164,
        'valid': True,
        'country': 'India',
        'country_calling_code': '+91',
        'numbering_area_estimate': area,
        'carrier_estimate': carrier_name,
        'local_reports_count': total,
        'community_caller_labels': [{'label': r['caller_label'], 'reports': r['n']} for r in labels],
        'local_report_categories': [{'category': r['category'], 'count': r['n']} for r in category_counts],
        'local_reports': [dict(r) for r in rows],
        'official_suspect_check_url': OFFICIAL_SUSPECT_URL,
        'fraud_reporting_url': CHAKSHU_URL,
        'warning': 'No subscriber name or live location is provided. Numbering metadata may be unavailable or inaccurate, especially after number portability. Community reports are unverified allegations, not proof.'
    }


def admin_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get('admin_ok'):
            return redirect(url_for('login', next=request.path))
        return fn(*args, **kwargs)
    return wrapped


@app.get('/')
def index():
    return render_template('index.html', logged_in=bool(session.get('admin_ok')))

@app.get('/login')
def login():
    return render_template('login.html')

@app.post('/login')
def login_post():
    if not ADMIN_PASSWORD:
        flash('Set ADMIN_PASSWORD in your environment before using dashboard login.', 'error')
        return redirect(url_for('login'))
    if secrets.compare_digest(request.form.get('password', ''), ADMIN_PASSWORD):
        session['admin_ok'] = True
        return redirect(request.args.get('next') or url_for('index'))
    flash('Incorrect password.', 'error')
    return redirect(url_for('login'))

@app.post('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.post('/api/check')
def api_check():
    try:
        return jsonify(lookup_number(request.json.get('number', '') if request.is_json else request.form.get('number', '')))
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

@app.post('/api/reports')
def api_report():
    data = request.get_json(silent=True) or request.form
    try:
        number, _ = normalize_number(data.get('number', ''))
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    category = str(data.get('category', 'suspicious')).strip().lower()
    allowed = {'spam', 'scam', 'harassment', 'legitimate', 'other'}
    if category not in allowed:
        return jsonify({'error': 'Choose a valid category.'}), 400
    description = re.sub(r'\s+', ' ', str(data.get('description', '')).strip())[:500]
    caller_label = re.sub(r'\s+', ' ', str(data.get('caller_label', '')).strip())[:100]
    if len(description) < 3:
        return jsonify({'error': 'Add a short description (at least 3 characters).'}), 400
    reporter_id = 'web-admin' if session.get('admin_ok') else 'web-anonymous'
    with db() as con:
        con.execute('INSERT INTO reports(number, category, description, reporter_id, created_at, caller_label) VALUES(?,?,?,?,?,?)', (number, category, description, reporter_id, now_iso(), caller_label))
    return jsonify({'ok': True, 'message': 'Report saved to this tool only. Any caller label is community-submitted and unverified; it is not the registered SIM owner name.'})

@app.get('/api/dashboard')
@admin_required
def api_dashboard():
    with db() as con:
        total_reports = con.execute('SELECT COUNT(*) FROM reports').fetchone()[0]
        unique_numbers = con.execute('SELECT COUNT(DISTINCT number) FROM reports').fetchone()[0]
        reports = con.execute('SELECT number, category, description, reporter_id, created_at, caller_label FROM reports ORDER BY id DESC LIMIT 100').fetchall()
    return jsonify({'total_reports': total_reports, 'unique_numbers': unique_numbers, 'reports': [dict(r) for r in reports]})

def twilio_verify_request(path, fields):
    """Call Twilio Verify over HTTPS. Credentials stay server-side in environment variables."""
    if not OTP_CONFIGURED:
        raise RuntimeError('OTP verification is not configured. Add Twilio Verify credentials to .env.')
    url = f'https://verify.twilio.com/v2/Services/{TWILIO_VERIFY_SERVICE_SID}/{path}'
    body = urllib.parse.urlencode(fields).encode()
    token = base64.b64encode(f'{TWILIO_ACCOUNT_SID}:{TWILIO_AUTH_TOKEN}'.encode()).decode()
    req = urllib.request.Request(url, data=body, headers={
        'Authorization': 'Basic ' + token,
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json'
    }, method='POST')
    try:
        with urllib.request.urlopen(req, timeout=12) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as e:
        # Do not relay provider response details or credentials to the browser.
        if e.code in (400, 404):
            raise ValueError('The OTP request could not be completed. Check the number and your Verify service settings.')
        raise RuntimeError('OTP provider request failed. Check Twilio configuration and try again.')
    except Exception:
        raise RuntimeError('Could not contact the OTP provider. Try again later.')


@app.post('/api/otp/send')
def otp_send():
    data = request.get_json(silent=True) or request.form
    try:
        number, _ = normalize_number(data.get('number', ''))
        # Session-based cooldown reduces accidental repeated sends. Production deployments
        # should also apply server-side IP/account rate limits at the proxy or gateway.
        now = time.time()
        if now - float(session.get('otp_last_sent', 0)) < 30:
            return jsonify({'error': 'Please wait 30 seconds before requesting another code.'}), 429
        twilio_verify_request('Verifications', {'To': number, 'Channel': 'sms'})
        session['otp_number'] = number
        session['otp_last_sent'] = now
        session['otp_verified_number'] = None
        session['otp_attempts'] = 0
        return jsonify({'ok': True, 'message': 'If the number can receive a verification SMS, a code has been requested. Enter it only in this website.'})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except RuntimeError as e:
        return jsonify({'error': str(e)}), 503


@app.post('/api/otp/verify')
def otp_verify():
    data = request.get_json(silent=True) or request.form
    number = session.get('otp_number')
    code = str(data.get('code', '')).strip()
    if not number:
        return jsonify({'error': 'Request an OTP first.'}), 400
    if not code.isdigit() or not (4 <= len(code) <= 10):
        return jsonify({'error': 'Enter the numeric verification code.'}), 400
    attempts = int(session.get('otp_attempts', 0))
    if attempts >= 5:
        session.pop('otp_number', None)
        return jsonify({'error': 'Too many attempts. Request a new code after the cooldown.'}), 429
    session['otp_attempts'] = attempts + 1
    try:
        result = twilio_verify_request('VerificationCheck', {'To': number, 'Code': code})
        if result.get('status') != 'approved':
            return jsonify({'error': 'That code was not approved. Check it and try again.'}), 400
        session['otp_verified_number'] = number
        session.pop('otp_number', None)
        session.pop('otp_attempts', None)
        return jsonify({
            'ok': True,
            'number': number,
            'message': 'OTP verified: this confirms access to receive messages at this number only. It does not prove legal SIM ownership and does not reveal the registered subscriber name or KYC records.'
        })
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except RuntimeError as e:
        return jsonify({'error': str(e)}), 503


@app.get('/api/otp/status')
def otp_status():
    return jsonify({
        'configured': OTP_CONFIGURED,
        'verified_number': session.get('otp_verified_number'),
        'purpose': 'OTP verifies access to a number, not legal subscriber identity.'
    })


@app.errorhandler(404)
def not_found(error):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'API endpoint not found. Check the deployed app version and route URL.'}), 404
    return error

@app.errorhandler(500)
def internal_error(error):
    # Keep API failures JSON so the browser never tries to parse an HTML error page as JSON.
    if request.path.startswith('/api/'):
        app.logger.exception('API request failed: %s', request.path)
        return jsonify({'error': 'The server could not complete this request. Check the Render logs for the API error.'}), 500
    return error

@app.get('/health')
def health():
    return jsonify({'ok': True, 'otp_configured': OTP_CONFIGURED})


def tg_allowed(user_id):
    # Fail closed: bot commands are unavailable until explicit Telegram user IDs are configured.
    return str(user_id) in ALLOWED_TELEGRAM_USERS


def telegram_worker():
    try:
        from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
        from telegram.ext import Application, CommandHandler, ContextTypes
    except Exception as e:
        print('Telegram bot dependencies unavailable:', e)
        return

    async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not tg_allowed(update.effective_user.id):
            await update.message.reply_text('Access is restricted. Add your Telegram numeric user ID to ALLOWED_TELEGRAM_USER_IDS in .env, then restart the app.')
            return
        await update.message.reply_text('Bharat Number OSINT\n/check +919876543210 — validate and review local reports\n/report +919876543210 scam | short details — save a local report\n/notes +919876543210 — show your private notes\n/note +919876543210 | note text — save a private note\n\nThis bot cannot reveal private subscriber identity or live location.')

    async def check(update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not tg_allowed(update.effective_user.id):
            await update.message.reply_text('Access restricted. Configure ALLOWED_TELEGRAM_USER_IDS first.')
            return
        raw = ' '.join(context.args)
        try:
            d = lookup_number(raw)
        except ValueError as e:
            await update.message.reply_text(str(e))
            return
        cats = ', '.join(f"{x['category']}: {x['count']}" for x in d['local_report_categories']) or 'No local reports'
        text = (f"Number: {d['number']}\nValid Indian format: Yes\nArea estimate: {d['numbering_area_estimate']}\nCarrier estimate: {d['carrier_estimate']}\nReports in this tool: {d['local_reports_count']}\nReport categories: {cats}\n\nNames/live location are not available. Community reports are unverified.")
        keyboard = InlineKeyboardMarkup([[InlineKeyboardButton('Official suspect check', url=OFFICIAL_SUSPECT_URL), InlineKeyboardButton('Report fraud', url=CHAKSHU_URL)]])
        await update.message.reply_text(text, reply_markup=keyboard)

    async def report(update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not tg_allowed(update.effective_user.id):
            await update.message.reply_text('Access restricted. Configure ALLOWED_TELEGRAM_USER_IDS first.')
            return
        raw = ' '.join(context.args)
        # Format: /report +919876543210 scam | description
        parts = raw.split('|', 1)
        head = parts[0].strip().split(maxsplit=1)
        if len(head) < 2:
            await update.message.reply_text('Usage: /report +919876543210 scam | short details')
            return
        number_raw, category = head[0], head[1].lower().strip()
        desc = parts[1].strip() if len(parts) > 1 else ''
        if category not in {'spam','scam','harassment','legitimate','other'} or len(desc) < 3:
            await update.message.reply_text('Use a category (spam/scam/harassment/legitimate/other) and a short description separated by |.')
            return
        try:
            number, _ = normalize_number(number_raw)
        except ValueError as e:
            await update.message.reply_text(str(e)); return
        with db() as con:
            con.execute('INSERT INTO reports(number, category, description, reporter_id, created_at) VALUES(?,?,?,?,?)', (number, category, desc[:500], str(update.effective_user.id), now_iso()))
        await update.message.reply_text('Saved to your tool. This is a community report, not a verified accusation, and was not sent to any government database.')

    async def note(update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not tg_allowed(update.effective_user.id):
            await update.message.reply_text('Access restricted. Configure ALLOWED_TELEGRAM_USER_IDS first.'); return
        raw = ' '.join(context.args); parts = raw.split('|', 1)
        if len(parts) != 2 or len(parts[1].strip()) < 1:
            await update.message.reply_text('Usage: /note +919876543210 | your private note'); return
        try:
            number, _ = normalize_number(parts[0].strip())
        except ValueError as e:
            await update.message.reply_text(str(e)); return
        with db() as con:
            con.execute('INSERT INTO notes(number, note, owner_id, created_at) VALUES(?,?,?,?)', (number, parts[1].strip()[:500], str(update.effective_user.id), now_iso()))
        await update.message.reply_text('Private note saved. Only your Telegram account can retrieve it through this bot.')

    async def notes(update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not tg_allowed(update.effective_user.id):
            await update.message.reply_text('Access restricted. Configure ALLOWED_TELEGRAM_USER_IDS first.'); return
        try:
            number, _ = normalize_number(' '.join(context.args))
        except ValueError as e:
            await update.message.reply_text('Usage: /notes +919876543210\n' + str(e)); return
        with db() as con:
            rows = con.execute('SELECT note, created_at FROM notes WHERE number=? AND owner_id=? ORDER BY id DESC LIMIT 20', (number, str(update.effective_user.id))).fetchall()
        if not rows:
            await update.message.reply_text('No private notes saved by you for this number.'); return
        await update.message.reply_text('Your private notes for ' + number + ':\n' + '\n'.join('• ' + r['created_at'][:10] + ': ' + r['note'] for r in rows))

    async def myid(update: Update, context: ContextTypes.DEFAULT_TYPE):
        await update.message.reply_text(f'Your Telegram numeric user ID: {update.effective_user.id}\nKeep it private; use it to configure the bot allowlist.')

    async def run_bot():
        application = Application.builder().token(BOT_TOKEN).build()
        application.add_handler(CommandHandler('start', start))
        application.add_handler(CommandHandler('check', check))
        application.add_handler(CommandHandler('report', report))
        application.add_handler(CommandHandler('note', note))
        application.add_handler(CommandHandler('notes', notes))
        application.add_handler(CommandHandler('myid', myid))
        await application.initialize()
        await application.start()
        await application.updater.start_polling(drop_pending_updates=True)
        import asyncio
        while True:
            await asyncio.sleep(3600)

    import asyncio
    asyncio.run(run_bot())


# Initialize the database when imported by Gunicorn as well as when run directly.
init_db()

# Keep exactly one Gunicorn worker when using Telegram polling in this same process.
if BOT_TOKEN and os.getenv('DISABLE_TELEGRAM_BOT', '0') != '1':
    threading.Thread(target=telegram_worker, daemon=True, name='telegram-bot').start()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', '5000')), debug=False)
