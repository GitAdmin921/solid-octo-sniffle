# Bharat Number OSINT

A small Python website dashboard + optional Telegram bot for Indian phone-number format checks, local community reports, private caller notes, and optional OTP verification through Twilio Verify.

## Important limits

- Does not retrieve private SIM/KYC subscriber names, addresses, call records, or live GPS locations. OTP verifies access to receive SMS at a number only; it does not prove legal SIM ownership.
- Carrier/numbering area data is an estimate from `phonenumbers`; mobile number portability means carrier guesses can be wrong.
- Community reports are unverified and may be inaccurate. They are stored only in this app, not automatically sent to government systems.
- The official Cybercrime suspect repository uses a CAPTCHA and warns that its complaint-derived data can contain errors. The app links to it instead of scraping or bypassing it.
- The website report form is open to anyone who can reach the app. Put it behind a private deployment or add authentication/rate limiting before public exposure. Admin dashboard is password-protected. For best privacy, keep the deployment private.

## Local setup (Windows, macOS, Linux)

1. Install Python 3.11 or newer.
2. Extract this folder and open a terminal inside it.
3. Create a virtual environment:

   **Windows PowerShell**
   ```powershell
   py -m venv .venv
   .venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   Copy-Item .env.example .env
   ```

   **macOS/Linux**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   cp .env.example .env
   ```

4. Edit `.env` and set `FLASK_SECRET_KEY` and `ADMIN_PASSWORD`. Use a long random secret and a strong unique password. Do not commit `.env` to GitHub.
6. Optional SMS OTP: create a Twilio Verify service, then set `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, and `TWILIO_VERIFY_SERVICE_SID` in `.env`. If these are blank, the OTP section stays disabled. Never expose these credentials in frontend code or commit them to GitHub. SMS availability, pricing, and country restrictions depend on your provider/account.
7. Start the app:
   ```bash
   python app.py
   ```
8. Open `http://127.0.0.1:5000` in your browser. Admin login is at `/login`.

## Enable the Telegram bot

1. In Telegram, open the verified `@BotFather` account, send `/newbot`, follow the steps, and copy the bot token. Keep the token secret.
2. Add the token to `.env` as `TELEGRAM_BOT_TOKEN=...`.
3. Start the app once, open your bot, and send `/myid`. The bot returns your numeric Telegram user ID. `/myid` is intentionally available so you can find your ID before allowlisting.
4. Stop the app. Set `ALLOWED_TELEGRAM_USER_IDS` in `.env` to your numeric ID (or a comma-separated list of trusted IDs). Restart the app. All other bot users are denied access to lookup/report/note commands.
5. Commands:
   - `/start`
   - `/check +919876543210`
   - `/report +919876543210 scam | caller claimed to be bank staff and requested OTP`
   - `/note +919876543210 | called about delivery on Monday`
   - `/notes +919876543210`
   - `/myid`

Telegram polling and the website run in the same process for this starter version. Run only one instance with a given bot token; multiple instances can conflict with polling.

## Deploying

Use a Python host such as Render, Railway, or a VPS. Configure environment variables in the host dashboard rather than uploading `.env`. Set the start command to `python app.py` for this starter. Use HTTPS. Attach a persistent disk and set `DATABASE_PATH` to a path on that disk or the SQLite database may be lost on redeploy. For production, use a managed database, add rate limiting/CSRF protection and admin authentication to report management, and consider making reports accessible only to authenticated users. Do not expose debug mode.

If deploying the Telegram bot and website on multiple instances, split them into separate services and use webhook/polling architecture deliberately; do not run duplicate pollers.

## Official resources

- Suspect repository: https://cybercrime.gov.in/Webform/suspect_search_repository.aspx
- Report suspect identifier: https://cybercrime.gov.in/Webform/cyber_suspect.aspx
- Sanchar Saathi / Chakshu: https://sancharsaathi.gov.in/
- National Cyber Crime Reporting Portal: https://www.cybercrime.gov.in/

If money has been lost to cyber fraud, contact India's cybercrime helpline 1930 promptly and file a report through the official portal.


## OTP verification and registered owner data

The website has an OTP-gated section powered optionally by Twilio Verify. The OTP is sent to the number entered, and verification state is held in the signed Flask session. This is proof of control/access to receive SMS, not proof of the legal SIM subscriber. The app intentionally does not display a registered-owner name or KYC data because no authorized telecom/subscriber data source is integrated. Only add such a source if you have a documented lawful agreement and authorization to access and disclose its results.

For production, add edge-level IP rate limiting, CSRF protection, secure cookie settings, monitoring, and a privacy notice before exposing the app publicly. Do not treat OTP verification as proof of identity.
