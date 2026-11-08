import os
import base64
import hashlib
import smtplib
from email.message import EmailMessage
import mimetypes
import math
import requests
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet, InvalidToken

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'owj-media-change-this-to-a-long-random-secret-before-production')
# Keep users signed in across browser restarts for 30 days. The SECRET_KEY must
# remain unchanged in Render Environment or existing login cookies will be invalidated.
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)
app.config['SESSION_REFRESH_EACH_REQUEST'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('RENDER', '').lower() == 'true'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///owj_media.db').replace('postgres://', 'postgresql://')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024


def _api_cipher():
    raw = hashlib.sha256(app.config['SECRET_KEY'].encode('utf-8')).digest()
    return Fernet(base64.urlsafe_b64encode(raw))

def protect_api_key(value):
    value = (value or '').strip()
    return _api_cipher().encrypt(value.encode()).decode() if value else ''

def reveal_api_key(value):
    value = value or ''
    try:
        return _api_cipher().decrypt(value.encode()).decode()
    except (InvalidToken, ValueError):
        # Backward compatibility for API keys saved before encryption.
        return value

def format_money(value):
    try:
        number = float(value or 0)
    except (TypeError, ValueError):
        number = 0.0
    return f"{number:.2f}".rstrip('0').rstrip('.')


app.jinja_env.filters['money'] = format_money
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'uploads')
ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp', 'gif'}

def save_deposit_proof_image(field_name):
    """Store a small receipt image inside the database so Render deploys/restarts cannot erase it."""
    file = request.files.get(field_name)
    if not file or not file.filename:
        raise ValueError('ارفق صورة إشعار الحوالة قبل إرسال طلب الشحن.')
    filename = secure_filename(file.filename)
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    mime = {'png': 'image/png', 'jpg': 'image/jpeg', 'jpeg': 'image/jpeg', 'webp': 'image/webp', 'gif': 'image/gif'}.get(ext)
    if not mime:
        raise ValueError('صيغة الصورة غير مدعومة. استخدم PNG أو JPG أو WEBP أو GIF.')
    raw = file.read(1024 * 1024 + 1)
    if not raw:
        raise ValueError('الصورة المرفقة فارغة. اختر صورة صحيحة.')
    if len(raw) > 1024 * 1024:
        raise ValueError('حجم صورة الإشعار يجب ألا يتجاوز 1 ميغابايت.')
    # Basic file signature checks prevent renamed non-image files.
    signatures = {
        'png': raw.startswith(b'\x89PNG\r\n\x1a\n'),
        'jpg': raw.startswith(b'\xff\xd8\xff'), 'jpeg': raw.startswith(b'\xff\xd8\xff'),
        'gif': raw.startswith((b'GIF87a', b'GIF89a')),
        'webp': len(raw) >= 12 and raw[:4] == b'RIFF' and raw[8:12] == b'WEBP'
    }
    if not signatures.get(ext, False):
        raise ValueError('الملف المرفق ليس صورة صالحة من النوع المحدد.')
    return 'data:' + mime + ';base64,' + base64.b64encode(raw).decode('ascii')


def save_uploaded_image(field_name):
    file = request.files.get(field_name)
    if not file or not file.filename:
        return ''
    filename = secure_filename(file.filename)
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    if ext not in ALLOWED_IMAGE_EXTENSIONS:
        raise ValueError('صيغة الصورة غير مدعومة. استخدم PNG أو JPG أو WEBP أو GIF.')
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    filename = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}_{filename}"
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    return '/static/uploads/' + filename
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    full_name = db.Column(db.String(120), default='')
    email = db.Column(db.String(160), default='')
    phone = db.Column(db.String(40), default='')
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='user')
    balance_usd = db.Column(db.Float, default=0.0)
    currency = db.Column(db.String(3), default='USD', nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    is_trusted_merchant = db.Column(db.Boolean, default=False)
    is_banned = db.Column(db.Boolean, default=False)
    ban_reason = db.Column(db.String(500), default='')
    ban_appeal = db.Column(db.Text, default='')
    appeal_status = db.Column(db.String(30), default='')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    @property
    def is_authenticated(self): return True
    def set_password(self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password): return check_password_hash(self.password_hash, password)

class SiteSetting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(80), unique=True, nullable=False)
    value = db.Column(db.String(200), nullable=False, default='')


def get_exchange_rate():
    try:
        setting = SiteSetting.query.filter_by(key='usd_to_syp_rate').first()
        rate = float(setting.value) if setting and setting.value else 0
        return rate if rate > 0 else 1
    except Exception:
        return 1


def currency_symbol_for(currency):
    return 'ل.س' if currency == 'SYP' else '$'


def display_money(value):
    try:
        amount = float(value or 0)
    except (TypeError, ValueError):
        amount = 0.0
    try:
        user = db.session.get(User, session.get('user_id')) if session.get('user_id') else None
        currency = user.currency if user and user.currency in ('USD', 'SYP') else 'USD'
        if currency == 'SYP':
            amount *= get_exchange_rate()
        return format_money(amount)
    except Exception:
        return format_money(amount)

app.jinja_env.filters['money'] = display_money

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    image_url = db.Column(db.String(500), default='')
    parent_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=True)
    parent = db.relationship('Category', remote_side=[id], backref=db.backref('subcategories', lazy=True))

class Service(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(160), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    price = db.Column(db.Float, default=1.0) # price per 1000 for SMM, fixed price for manual
    price_per_1000 = db.Column(db.Float, default=1.0)
    min_quantity = db.Column(db.Integer, default=10)
    max_quantity = db.Column(db.Integer, default=10000)
    input_label = db.Column(db.String(180), default='الرابط أو الآيدي')
    service_type = db.Column(db.String(20), default='manual')
    api_provider_id = db.Column(db.Integer, db.ForeignKey('smm_provider.id'), nullable=True)
    api_service_id = db.Column(db.String(80), default='')
    image_url = db.Column(db.String(500), default='')
    description = db.Column(db.Text, default='')
    extra_details = db.Column(db.Text, default='')
    is_available = db.Column(db.Boolean, default=True)
    category = db.relationship('Category', backref=db.backref('services', lazy=True))

class SMMProvider(db.Model):
    __tablename__ = 'smm_provider'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    api_url = db.Column(db.String(500), nullable=False)
    api_key = db.Column(db.Text, nullable=False)  # encrypted live key (legacy field)
    test_api_key = db.Column(db.Text, default='')
    live_api_key = db.Column(db.Text, default='')
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class SMMCatalogService(db.Model):
    __tablename__ = 'smm_catalog_service'
    id = db.Column(db.Integer, primary_key=True)
    provider_id = db.Column(db.Integer, db.ForeignKey('smm_provider.id'), nullable=False, index=True)
    service_code = db.Column(db.String(80), nullable=False)
    name = db.Column(db.String(240), default='')
    category_name = db.Column(db.String(160), default='')
    rate = db.Column(db.Float, default=0)
    min_quantity = db.Column(db.Integer, default=1)
    max_quantity = db.Column(db.Integer, default=10000)
    provider = db.relationship('SMMProvider', backref=db.backref('catalog_services', cascade='all, delete-orphan'))

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    service_id = db.Column(db.Integer, db.ForeignKey('service.id'), nullable=True)
    service_name = db.Column(db.String(160), default='')
    link = db.Column(db.String(1000), default='')
    quantity = db.Column(db.Integer, default=1)
    total_price = db.Column(db.Float, default=0.0)
    status = db.Column(db.String(40), default='قيد المراجعة')
    failure_reason = db.Column(db.String(500), default='')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='orders')
    service = db.relationship('Service')

class VerificationRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    full_name = db.Column(db.String(120), default='')
    email = db.Column(db.String(160), default='')
    phone = db.Column(db.String(40), default='')
    gender = db.Column(db.String(30), default='')
    age = db.Column(db.Integer, default=0)
    rejection_reason = db.Column(db.String(500), default='')
    status = db.Column(db.String(20), default='pending')
    user = db.relationship('User')

class Agent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    city = db.Column(db.String(120), default='')
    phone = db.Column(db.String(60), default='')
    details = db.Column(db.Text, default='')

class PaymentMethod(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    qr_code_url = db.Column(db.String(500), default='')
    account_number = db.Column(db.String(180), default='')
    instructions = db.Column(db.Text, default='')

class SMSNumberProvider(db.Model):
    __tablename__ = 'sms_number_provider'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    api_url = db.Column(db.String(500), nullable=False)
    api_key = db.Column(db.Text, nullable=False)
    protocol = db.Column(db.String(40), default='generic')
    notes = db.Column(db.Text, default='')
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class DepositRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, default=0)
    proof = db.Column(db.String(500), default='')
    proof_image = db.Column(db.Text, default='')
    status = db.Column(db.String(30), default='قيد المراجعة')
    rejection_reason = db.Column(db.String(500), default='')
    payment_method_name = db.Column(db.String(120), default='')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User')


class SupportTicket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    subject = db.Column(db.String(160), nullable=False, default='استفسار دعم')
    status = db.Column(db.String(30), nullable=False, default='مفتوحة')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user = db.relationship('User', backref=db.backref('support_tickets', lazy=True))
    messages = db.relationship('SupportMessage', backref='ticket', lazy=True, cascade='all, delete-orphan', order_by='SupportMessage.created_at')


class SupportMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey('support_ticket.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    sender_role = db.Column(db.String(20), nullable=False, default='user')
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    sender = db.relationship('User')


class WalletTransaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    transaction_type = db.Column(db.String(30), nullable=False, default='withdrawal')
    amount = db.Column(db.Float, nullable=False)
    reason = db.Column(db.String(500), nullable=False, default='')
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    user = db.relationship('User', foreign_keys=[user_id])
    admin = db.relationship('User', foreign_keys=[admin_id])


class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    title = db.Column(db.String(160), nullable=False)
    message = db.Column(db.String(500), nullable=False)
    url = db.Column(db.String(500), default='/notifications')
    is_read = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    user = db.relationship('User', backref=db.backref('notifications', lazy=True, cascade='all, delete-orphan'))


class PushSubscription(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    endpoint = db.Column(db.Text, unique=True, nullable=False)
    p256dh = db.Column(db.String(255), nullable=False)
    auth = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    user = db.relationship('User', backref=db.backref('push_subscriptions', lazy=True, cascade='all, delete-orphan'))


def send_user_notification(user_id, title, message, url='/notifications'):
    # Save an in-site notification; send phone/browser push when VAPID is configured.
    db.session.add(Notification(user_id=user_id, title=title[:160], message=message[:500], url=url[:500]))
    db.session.flush()
    public_key = os.environ.get('VAPID_PUBLIC_KEY', '').strip()
    private_key = os.environ.get('VAPID_PRIVATE_KEY', '').strip()
    subject = os.environ.get('VAPID_SUBJECT', 'mailto:admin@example.com').strip()
    if public_key and private_key:
        try:
            from pywebpush import webpush
            import json
            for sub in PushSubscription.query.filter_by(user_id=user_id).all():
                try:
                    webpush(subscription_info={'endpoint': sub.endpoint, 'keys': {'p256dh': sub.p256dh, 'auth': sub.auth}}, data=json.dumps({'title': title, 'body': message, 'url': url}), vapid_private_key=private_key, vapid_claims={'sub': subject})
                except Exception as exc:
                    status = getattr(getattr(exc, 'response', None), 'status_code', None)
                    if status in (404, 410):
                        db.session.delete(sub)
        except ImportError:
            app.logger.warning('pywebpush is not installed; saved in-app notification only')
        except Exception:
            app.logger.exception('Unable to send push notification')


def send_admin_email_notification(title, message, url='/admin'):
    """Send admin event alerts by email when SMTP environment settings are configured."""
    recipient = os.environ.get('ADMIN_NOTIFICATION_EMAIL', 'yagha191@gmail.com').strip()
    smtp_host = os.environ.get('SMTP_HOST', 'smtp.gmail.com').strip()
    smtp_port = int(os.environ.get('SMTP_PORT', '587'))
    smtp_username = os.environ.get('SMTP_USERNAME', '').strip()
    smtp_password = os.environ.get('SMTP_PASSWORD', '').strip()
    from_email = os.environ.get('SMTP_FROM_EMAIL', smtp_username).strip()
    if not (recipient and smtp_username and smtp_password and from_email):
        app.logger.info('Admin email alerts are not configured; skipping email notification.')
        return False
    try:
        msg = EmailMessage()
        msg['Subject'] = f'أوج ميديا | {title}'
        msg['From'] = from_email
        msg['To'] = recipient
        msg.set_content(f'{title}\n\n{message}\n\nرابط لوحة الإدارة: {os.environ.get("SITE_URL", "").rstrip("/")}{url}')
        with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(smtp_username, smtp_password)
            server.send_message(msg)
        return True
    except Exception:
        app.logger.exception('Unable to send admin email notification')
        return False


def notify_admins(title, message, url='/admin'):
    """Send in-site, phone push, and configured email notifications to administrators."""
    for admin_user in User.query.filter_by(role='admin').all():
        send_user_notification(admin_user.id, title, message, url)
    send_admin_email_notification(title, message, url)


def get_or_create_single_support_ticket(user_id):
    # Merge legacy tickets into one ongoing customer-service conversation.
    tickets = SupportTicket.query.filter_by(user_id=user_id).order_by(SupportTicket.updated_at.desc(), SupportTicket.id.desc()).all()
    if not tickets:
        ticket = SupportTicket(user_id=user_id, subject='محادثة خدمة العملاء')
        db.session.add(ticket)
        db.session.flush()
        return ticket
    primary = tickets[0]
    primary.subject = 'محادثة خدمة العملاء'
    for old in tickets[1:]:
        for msg in old.messages:
            msg.ticket = primary
        db.session.delete(old)
    return primary

@app.context_processor
def inject_globals():
    user = db.session.get(User, session.get('user_id')) if session.get('user_id') else None
    unread_count = Notification.query.filter_by(user_id=user.id, is_read=False).count() if user else 0
    currency = user.currency if user and user.currency in ('USD', 'SYP') else 'USD'
    rate = get_exchange_rate()
    return {'current_user': user, 'site_name': 'أوج ميديا', 'unread_notification_count': unread_count, 'currency_symbol': currency_symbol_for(currency), 'currency_code': currency, 'usd_to_syp_rate': rate}

def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get('user_id'):
            flash('سجّل الدخول أولاً للمتابعة.', 'error')
            return redirect(url_for('login'))
        user = db.session.get(User, session.get('user_id'))
        if not user:
            session.clear()
            return redirect(url_for('login'))
        if user.is_banned:
            session.clear()
            return redirect(url_for('banned_account', user_id=user.id))
        return fn(*args, **kwargs)
    return wrapped

def admin_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        user = db.session.get(User, session.get('user_id')) if session.get('user_id') else None
        if not user or user.role != 'admin': abort(403)
        return fn(*args, **kwargs)
    return wrapped

def current_user():
    return db.session.get(User, session.get('user_id')) if session.get('user_id') else None

@app.before_request
def enforce_account_ban():
    user_id = session.get('user_id')
    if not user_id:
        return None
    user = db.session.get(User, user_id)
    if user and user.is_banned and request.endpoint not in {'banned_account', 'submit_ban_appeal', 'logout', 'static'}:
        session.clear()
        return redirect(url_for('banned_account', user_id=user.id))
    return None

@app.route('/')
def index():
    categories = Category.query.filter_by(parent_id=None).order_by(Category.id).all()
    services = Service.query.order_by(Service.id.desc()).all()
    return render_template('index.html', categories=categories, services=services)

@app.route('/accounts')
def accounts():
    services = Service.query.order_by(Service.id.desc()).all()
    return render_template('accounts.html', services=services)

@app.route('/category/<int:category_id>')
def category_services(category_id):
    category = Category.query.get_or_404(category_id)
    services = Service.query.filter_by(category_id=category_id).order_by(Service.id.desc()).all()
    subcategories = Category.query.filter_by(parent_id=category_id).order_by(Category.id).all()
    return render_template('category_services.html', category=category, services=services, subcategories=subcategories)

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form.get('username','').strip()).first()
        if user and user.check_password(request.form.get('password','')):
            if user.is_banned:
                return redirect(url_for('banned_account', user_id=user.id))
            session.clear(); session.permanent = True; session['user_id'] = user.id
            flash('تم تسجيل الدخول بنجاح.', 'success')
            return redirect(url_for('index'))
        flash('اسم المستخدم أو كلمة المرور غير صحيحة.', 'error')
    return render_template('login.html')

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','')
        if len(username) < 3 or len(password) < 8:
            flash('اسم المستخدم 3 أحرف على الأقل وكلمة المرور 8 أحرف على الأقل.', 'error')
        elif User.query.filter_by(username=username).first():
            flash('اسم المستخدم مستخدم بالفعل.', 'error')
        else:
            currency = request.form.get('currency', 'USD').upper()
            if currency not in ('USD', 'SYP'): currency = 'USD'
            user = User(username=username, full_name=request.form.get('full_name','').strip(), email=request.form.get('email','').strip(), phone=request.form.get('phone','').strip(), currency=currency)
            user.set_password(password); db.session.add(user); db.session.commit()
            notify_admins('تسجيل حساب جديد', f'تم إنشاء حساب جديد باسم {user.username} ومعرّفه #{user.id}.', url_for('admin_accounts', account_id=user.id))
            db.session.commit()
            session.permanent = True
            session['user_id'] = user.id
            flash('تم إنشاء الحساب بنجاح.', 'success')
            return redirect(url_for('index'))
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear(); return redirect(url_for('index'))

@app.route('/profile', methods=['GET','POST'])
@login_required
def profile():
    user = current_user()
    if request.method == 'POST':
        user.full_name = request.form.get('full_name', user.full_name).strip()
        user.email = request.form.get('email', user.email).strip()
        user.phone = request.form.get('phone', user.phone).strip()
        currency = request.form.get('currency', user.currency).upper()
        if currency in ('USD', 'SYP'): user.currency = currency
        db.session.commit(); flash('تم تحديث بياناتك.', 'success'); return redirect(url_for('profile'))
    return render_template('profile.html', user=user)

@app.route('/profile/change_password', methods=['POST'])
@login_required
def change_profile_password():
    user = current_user()
    current = request.form.get('current_password', '')
    new = request.form.get('new_password', '')
    confirm = request.form.get('confirm_password', '')
    if not user.check_password(current):
        flash('كلمة المرور الحالية غير صحيحة.', 'error')
    elif len(new) < 8:
        flash('كلمة المرور الجديدة يجب أن تكون 8 أحرف على الأقل.', 'error')
    elif new != confirm:
        flash('تأكيد كلمة المرور غير مطابق.', 'error')
    else:
        user.set_password(new); db.session.commit(); flash('تم تغيير كلمة المرور بنجاح.', 'success')
    return redirect(url_for('profile'))

@app.route('/verification', methods=['GET', 'POST'])
@login_required
def verification():
    user = current_user()
    latest = VerificationRequest.query.filter_by(user_id=user.id).order_by(VerificationRequest.id.desc()).first()
    if request.method == 'POST':
        if user.is_verified:
            flash('حسابك موثّق بالفعل.', 'success')
            return redirect(url_for('verification'))
        if latest and latest.status == 'pending':
            flash('لديك طلب توثيق قيد المراجعة بالفعل.', 'error')
            return redirect(url_for('verification'))
        email = request.form.get('email', '').strip()
        phone = request.form.get('phone', '').strip()
        gender = request.form.get('gender', '').strip()
        age = request.form.get('age', type=int)
        if not email or not phone or gender not in ('ذكر', 'أنثى', 'أفضل عدم الإجابة') or age is None or age < 13 or age > 120:
            flash('تحقق من البريد ورقم الهاتف والجنس والعمر (13 إلى 120).', 'error')
            return redirect(url_for('verification'))
        req = VerificationRequest(user_id=user.id, full_name=user.full_name or user.username, email=email, phone=phone, gender=gender, age=age, status='pending')
        db.session.add(req)
        user.email = email; user.phone = phone
        db.session.commit()
        notify_admins('طلب توثيق جديد', f'أرسل {user.username} طلب توثيق حساب للمراجعة.', url_for('admin'))
        db.session.commit()
        flash('تم إرسال طلب التوثيق للإدارة للمراجعة.', 'success')
        return redirect(url_for('verification'))
    return render_template('verification.html', user=user, latest=latest)

@app.route('/my_orders')
@login_required
def my_orders():
    orders = Order.query.filter_by(user_id=current_user().id).order_by(Order.id.desc()).all()
    return render_template('my_orders.html', orders=orders)

@app.route('/order/<int:service_id>', methods=['POST'])
@login_required
def place_order(service_id):
    service = Service.query.get_or_404(service_id)
    user = current_user()
    if not service.is_available:
        flash('هذه الخدمة غير متوفرة حالياً.', 'error'); return redirect(url_for('category_services', category_id=service.category_id))
    link = request.form.get('link','').strip()
    if service.service_type in ('manual', 'smm_fixed'):
        # manual أو API بسعر ثابت لكل طلب: لا توجد كمية يحددها العميل.
        quantity = 1
        if not link:
            flash('أدخل الآيدي أو البيانات المطلوبة.', 'error'); return redirect(url_for('category_services', category_id=service.category_id))
        total = service.price
    else:
        try: quantity = int(request.form.get('quantity', service.min_quantity or 1))
        except ValueError: quantity = 0
        minimum = service.min_quantity or 1
        maximum = service.max_quantity or 10000
        if not link:
            flash('أدخل الرابط أو البيانات المطلوبة.', 'error')
            return redirect(url_for('category_services', category_id=service.category_id))
        if quantity < minimum:
            flash(f'الكمية أقل من المطلوب. لازم تكون الكمية {minimum} على الأقل.', 'error')
            return redirect(url_for('category_services', category_id=service.category_id))
        if quantity > maximum:
            flash(f'الكمية أكبر من الحد المسموح. الحد الأقصى هو {maximum}.', 'error')
            return redirect(url_for('category_services', category_id=service.category_id))
        total = (service.price_per_1000 or service.price) * quantity / 1000
    if user.balance_usd < total:
        flash('رصيدك غير كافٍ. يرجى شحن المحفظة أولاً.', 'error'); return redirect(url_for('deposit'))
    provider_order_id = ''
    if service.service_type in ('smm', 'smm_fixed'):
        if service.service_type == 'smm_fixed':
            quantity = 1
        provider = SMMProvider.query.filter_by(id=service.api_provider_id, is_active=True).first() if service.api_provider_id else None
        if not provider or not service.api_service_id:
            flash('هذه الخدمة التلقائية غير مربوطة بمزوّد API بشكل صحيح. تواصل مع الإدارة.', 'error')
            return redirect(url_for('category_services', category_id=service.category_id))
        try:
            # SMM providers commonly expect application/x-www-form-urlencoded.
            # requests encodes the data dict accordingly; do not send JSON and form data together.
            response = requests.post(
                provider.api_url,
                data={
                    'key': reveal_api_key(provider.api_key),
                    'action': 'add',
                    'service': str(service.api_service_id),
                    'link': link,
                    'quantity': str(quantity),
                },
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                timeout=30,
            )
            response.raise_for_status()
            api_result = response.json()
            if not isinstance(api_result, dict):
                raise ValueError('استجابة غير متوقعة من مزوّد الخدمة.')
            if api_result.get('error') or api_result.get('order') in (None, ''):
                raise ValueError(str(api_result.get('error') or 'لم يؤكد مزود الخدمة قبول الطلب.'))
            provider_order_id = str(api_result['order'])
        except Exception as exc:
            app.logger.warning('SMM provider order failed: %s', exc)
            flash('الخدمة غير متاحة حاليا، حاول بعد 5 دقائق.', 'error')
            return redirect(url_for('category_services', category_id=service.category_id))
    user.balance_usd -= total
    order = Order(user_id=user.id, service_id=service.id, service_name=service.name, link=link, quantity=quantity, total_price=total, status=('قيد التنفيذ' if service.service_type in ('smm', 'smm_fixed') else 'قيد المراجعة'))
    db.session.add(order); db.session.commit()
    order_kind = 'تلقائي عبر API' if service.service_type in ('smm', 'smm_fixed') else ('يدوي' if service.service_type == 'manual' else 'طلب خدمة')
    notify_admins(f'طلب جديد {order_kind} #{order.id}', f'المستخدم {user.username} (#{user.id}) أرسل طلب {service.name} بقيمة ${format_money(total)}. الحالة: {order.status}.', url_for('admin'))
    db.session.commit()
    flash('تم إرسال طلبك بنجاح.', 'success'); return redirect(url_for('my_orders'))

@app.errorhandler(413)
def uploaded_file_too_large(error):
    flash('حجم الملف كبير جداً. الحد الأقصى لإرسال الطلب هو 2 ميغابايت، وحجم صورة الإشعار 1 ميغابايت.', 'error')
    return redirect(url_for('deposit'))


@app.route('/deposit', methods=['GET','POST'])
def deposit():
    payments = PaymentMethod.query.order_by(PaymentMethod.id.desc()).all()
    if request.method == 'POST':
        if not session.get('user_id'): return redirect(url_for('login'))
        try: amount = float(request.form.get('amount', '0'))
        except ValueError: amount = 0
        if amount <= 0:
            flash('أدخل مبلغاً صحيحاً.', 'error')
        else:
            payment_id = request.form.get('payment_method_id', type=int)
            selected_payment = PaymentMethod.query.get(payment_id) if payment_id else None
            if not selected_payment:
                flash('اختر طريقة الدفع المناسبة قبل إرسال الطلب.', 'error')
                return redirect(url_for('deposit'))
            try:
                proof_image = save_deposit_proof_image('proof_image')
            except ValueError as exc:
                flash(str(exc), 'error')
                return redirect(url_for('deposit'))
            deposit_request = DepositRequest(
                user_id=current_user().id,
                amount=amount,
                proof=request.form.get('proof', '').strip(),
                proof_image=proof_image,
                payment_method_name=selected_payment.name
            )
            db.session.add(deposit_request)
            db.session.commit()
            notify_admins(f'طلب شحن رصيد جديد #{deposit_request.id}', f'المستخدم {current_user().username} (#{current_user().id}) طلب شحن ${format_money(amount)} عبر {selected_payment.name}.', url_for('admin'))
            db.session.commit()
            flash('تم إرسال طلب الشحن للمراجعة.', 'success')
            return redirect(url_for('deposit'))
    user = current_user() if session.get('user_id') else None
    my_deposits = DepositRequest.query.filter_by(user_id=user.id).order_by(DepositRequest.id.desc()).all() if user else []
    return render_template('deposit.html', payments=payments, my_deposits=my_deposits, agents=Agent.query.order_by(Agent.id.desc()).all())

@app.route('/agents')
def agents(): return render_template('agents.html', agents=Agent.query.order_by(Agent.id.desc()).all())
@app.route('/about')
def about(): return render_template('about.html')
@app.route('/ai_bot')
@login_required
def ai_bot(): return render_template('ai_bot.html', user_name=current_user().full_name or current_user().username)

@app.route('/api/ai_chat', methods=['POST'])
def ai_chat():
    # API endpoints should return JSON errors, not redirect fetch() to an HTML login page.
    if not session.get('user_id') or not db.session.get(User, session.get('user_id')):
        return jsonify(reply='انتهت جلسة تسجيل الدخول. سجّل الدخول من جديد ثم جرّب المساعد.'), 401
    data = request.get_json(silent=True) or {}
    message = str(data.get('message','')).strip()[:1000]
    if not message: return jsonify(reply='اكتب سؤالك أولاً.'), 400
    m = message.lower().strip()
    if any(x in m for x in ['شحن','رصيد','دفع','تحويل','محفظة','باركود','كاش']):
        reply = 'لشحن رصيدك افتح قسم «الشحن» من الشريط السفلي، واختر طريقة الدفع المتاحة. إذا أرسلت طلب شحن فسيظهر للإدارة للمراجعة.'
    elif any(x in m for x in ['طلباتي','طلب','الطلبات','حالة الطلب','وين طلبي']):
        reply = 'يمكنك متابعة طلباتك من قسم «طلباتي» في الشريط السفلي. تظهر حالة كل طلب وتكلفته.'
    elif any(x in m for x in ['خدمة','سعر','متجر','انستغرام','انستا','تيك','تيك توك','متابع','لايك','مشاهد','يوتيوب','تلغرام','تليجرام']):
        reply = 'تصفح المتجر الرقمي لاختيار الخدمة. ستجد السعر وحالة التوفر، ويمكنك فتح القسم لمعرفة التفاصيل.'
    elif any(x in m for x in ['مرحبا','السلام','اهلا','أهلا','هاي','هلا']):
        reply = 'أهلاً وسهلاً بك في أوج ميديا 👋 كيف أقدر أساعدك؟ اسألني عن الخدمات أو الطلبات أو الشحن.'
    else:
        reply = 'أنا مساعد أوج ميديا التجريبي. أستطيع إرشادك إلى الخدمات والطلبات والشحن. للمساعدة الخاصة، تواصل مع فريق الدعم من خلال الوكلاء المعتمدين.'
    return jsonify(reply=reply)

@app.route('/support', methods=['GET', 'POST'])
@login_required
def support():
    user = current_user()
    ticket = get_or_create_single_support_ticket(user.id)
    db.session.commit()
    return redirect(url_for('support_ticket', ticket_id=ticket.id))


@app.route('/support/<int:ticket_id>', methods=['GET', 'POST'])
@login_required
def support_ticket(ticket_id):
    user = current_user()
    ticket = SupportTicket.query.get_or_404(ticket_id)
    if ticket.user_id != user.id and user.role != 'admin':
        abort(403)
    if request.method == 'POST':
        content = request.form.get('message', '').strip()
        if not content:
            flash('اكتب رسالتك أولاً.', 'error')
        elif len(content) > 5000:
            flash('الرسالة طويلة جداً؛ الحد الأقصى 5000 حرف.', 'error')
        else:
            role = 'admin' if user.role == 'admin' else 'user'
            db.session.add(SupportMessage(ticket_id=ticket.id, sender_id=user.id, sender_role=role, content=content))
            ticket.updated_at = datetime.utcnow()
            if role == 'user':
                ticket.status = 'بانتظار الدعم'
                notify_admins('رسالة دعم جديدة', f'أرسل {user.username} رسالة جديدة في محادثة الدعم #{ticket.id}.', url_for('admin_support_ticket', ticket_id=ticket.id))
            else:
                ticket.status = 'تم الرد'
                send_user_notification(ticket.user_id, 'تم الرد من الدعم', 'قام فريق أوج ميديا بالرد على محادثتك.', url_for('support_ticket', ticket_id=ticket.id))
            db.session.commit()
            flash('تم إرسال الرد.', 'success')
            return redirect(url_for('admin_support_ticket' if user.role == 'admin' else 'support_ticket', ticket_id=ticket.id))
    return render_template('support_ticket.html', ticket=ticket, is_admin=(user.role == 'admin'))


@app.route('/admin/support')
@admin_required
def admin_support():
    user_ids = [row[0] for row in db.session.query(SupportTicket.user_id).distinct().all()]
    for uid in user_ids:
        get_or_create_single_support_ticket(uid)
    db.session.commit()
    tickets = SupportTicket.query.order_by(SupportTicket.updated_at.desc()).all()
    return render_template('admin_support.html', tickets=tickets)


@app.route('/admin/support/<int:ticket_id>', methods=['GET', 'POST'])
@admin_required
def admin_support_ticket(ticket_id):
    ticket = SupportTicket.query.get_or_404(ticket_id)
    if request.method == 'POST':
        action = request.form.get('action', 'reply')
        if action == 'close':
            ticket.status = 'مغلقة'
            ticket.updated_at = datetime.utcnow()
            db.session.commit()
            flash('تم إغلاق الشكوى.', 'success')
            return redirect(url_for('admin_support_ticket', ticket_id=ticket.id))
        if action == 'reopen':
            ticket.status = 'مفتوحة'
            ticket.updated_at = datetime.utcnow()
            db.session.commit()
            flash('تم إعادة فتح الشكوى.', 'success')
            return redirect(url_for('admin_support_ticket', ticket_id=ticket.id))
        content = request.form.get('message', '').strip()
        if not content:
            flash('اكتب الرد قبل الإرسال.', 'error')
        elif len(content) > 5000:
            flash('الرسالة طويلة جداً؛ الحد الأقصى 5000 حرف.', 'error')
        else:
            admin_user = current_user()
            db.session.add(SupportMessage(ticket_id=ticket.id, sender_id=admin_user.id, sender_role='admin', content=content))
            ticket.status = 'تم الرد'
            ticket.updated_at = datetime.utcnow()
            send_user_notification(ticket.user_id, 'تم الرد من الدعم', 'قام فريق أوج ميديا بالرد على محادثتك.', url_for('support_ticket', ticket_id=ticket.id))
            db.session.commit()
            flash('تم إرسال الرد للمستخدم.', 'success')
            return redirect(url_for('admin_support_ticket', ticket_id=ticket.id))
    return render_template('support_ticket.html', ticket=ticket, is_admin=True)


@app.route('/notifications')
@login_required
def notifications_page():
    items = Notification.query.filter_by(user_id=current_user().id).order_by(Notification.created_at.desc()).limit(100).all()
    return render_template('notifications.html', notifications=items, vapid_public_key=os.environ.get('VAPID_PUBLIC_KEY', ''), is_admin=(current_user().role == 'admin'))


@app.route('/notifications/read/<int:notification_id>', methods=['POST'])
@login_required
def notification_read(notification_id):
    item = Notification.query.filter_by(id=notification_id, user_id=current_user().id).first_or_404()
    item.is_read = True
    db.session.commit()
    return redirect(item.url or url_for('notifications_page'))


@app.route('/api/push/subscribe', methods=['POST'])
@login_required
def push_subscribe():
    data = request.get_json(silent=True) or {}
    sub = data.get('subscription') or {}
    keys = sub.get('keys') or {}
    endpoint, p256dh, auth = sub.get('endpoint'), keys.get('p256dh'), keys.get('auth')
    if not all(isinstance(v, str) and v for v in (endpoint, p256dh, auth)):
        return jsonify(ok=False, error='بيانات الاشتراك غير مكتملة'), 400
    existing = PushSubscription.query.filter_by(endpoint=endpoint).first()
    if existing:
        existing.user_id, existing.p256dh, existing.auth = current_user().id, p256dh, auth
    else:
        db.session.add(PushSubscription(user_id=current_user().id, endpoint=endpoint, p256dh=p256dh, auth=auth))
    db.session.commit()
    return jsonify(ok=True)


@app.route('/sw.js')
def service_worker():
    from flask import Response
    js = "self.addEventListener('push', function(event) { let data = {}; try { data = event.data.json(); } catch (e) { data = {title: 'أوج ميديا', body: event.data ? event.data.text() : 'لديك إشعار جديد'}; } event.waitUntil(self.registration.showNotification(data.title || 'أوج ميديا', {body: data.body || '', data: {url: data.url || '/notifications'}})); }); self.addEventListener('notificationclick', function(event) { event.notification.close(); const url = event.notification.data && event.notification.data.url ? event.notification.data.url : '/notifications'; event.waitUntil(clients.matchAll({type: 'window', includeUncontrolled: true}).then(function(list) { for (const client of list) { if ('focus' in client) { client.navigate(url); return client.focus(); } } return clients.openWindow(url); })); });"
    return Response(js, mimetype='application/javascript', headers={'Service-Worker-Allowed': '/'})


@app.route('/admin/accounts')
@admin_required
def admin_accounts():
    account_lookup_id = request.args.get('account_id', type=int)
    account_lookup = db.session.get(User, account_lookup_id) if account_lookup_id else None
    return render_template('admin_accounts.html', account_lookup=account_lookup, account_lookup_id=account_lookup_id)


@app.route('/admin/exchange-rate', methods=['POST'])
@admin_required
def update_exchange_rate():
    raw = request.form.get('usd_to_syp_rate', '').strip().replace(',', '.')
    try:
        rate = float(raw)
        if rate <= 0 or rate > 100000000:
            raise ValueError()
    except (TypeError, ValueError):
        flash('أدخل سعر تصريف صحيحاً أكبر من صفر.', 'error')
        return redirect(url_for('admin'))
    setting = SiteSetting.query.filter_by(key='usd_to_syp_rate').first()
    if not setting:
        setting = SiteSetting(key='usd_to_syp_rate', value=str(rate))
        db.session.add(setting)
    else:
        setting.value = str(rate)
    db.session.commit()
    flash('تم تحديث سعر تصريف الدولار مقابل الليرة السورية بنجاح.', 'success')
    return redirect(url_for('admin'))


@app.route('/admin')
@admin_required
def admin():
    account_lookup_id = request.args.get('account_id', type=int)
    account_lookup = db.session.get(User, account_lookup_id) if account_lookup_id else None
    return render_template('admin.html', orders=Order.query.order_by(Order.id.desc()).all(), verification_requests=VerificationRequest.query.filter_by(status='pending').all(), categories=Category.query.all(), services=Service.query.all(), deposits=DepositRequest.query.filter_by(status='قيد المراجعة').order_by(DepositRequest.id.desc()).all(), payment_methods=PaymentMethod.query.order_by(PaymentMethod.id.desc()).all(), agents=Agent.query.order_by(Agent.id.desc()).all(), sms_number_providers=SMSNumberProvider.query.order_by(SMSNumberProvider.id.desc()).all(), smm_providers=SMMProvider.query.order_by(SMMProvider.id.desc()).all(), smm_catalog_services=SMMCatalogService.query.order_by(SMMCatalogService.name.asc()).all(), support_count=SupportTicket.query.filter(SupportTicket.status != 'مغلقة').count(), account_lookup=account_lookup, account_lookup_id=account_lookup_id)


@app.route('/account-banned/<int:user_id>', methods=['GET'])
def banned_account(user_id):
    user = db.session.get(User, user_id)
    if not user or not user.is_banned:
        return redirect(url_for('login'))
    return render_template('account_banned.html', user=user)

@app.route('/account-banned/<int:user_id>/appeal', methods=['POST'])
def submit_ban_appeal(user_id):
    user = db.session.get(User, user_id)
    if not user or not user.is_banned:
        return redirect(url_for('login'))
    appeal = request.form.get('appeal', '').strip()
    if len(appeal) < 10:
        flash('اكتب تفاصيل الاعتراض بشكل أوضح (10 أحرف على الأقل).', 'error')
    else:
        user.ban_appeal = appeal[:3000]
        user.appeal_status = 'قيد المراجعة'
        db.session.commit()
        flash('تم إرسال اعتراضك للإدارة بنجاح.', 'success')
    return redirect(url_for('banned_account', user_id=user.id))

@app.route('/admin/account_action', methods=['POST'])
@admin_required
def admin_account_action():
    user_id = request.form.get('user_id', type=int)
    user = db.session.get(User, user_id) if user_id else None
    if not user:
        flash('لم يتم العثور على حساب بهذا المعرف.', 'error')
        return redirect(url_for('admin'))
    action = request.form.get('action', '')
    if action == 'reset_password':
        new_password = request.form.get('new_password', '')
        if len(new_password) < 8:
            flash('كلمة المرور الجديدة يجب أن تكون 8 أحرف على الأقل.', 'error')
        else:
            user.set_password(new_password)
            db.session.commit()
            flash(f'تم تغيير كلمة مرور الحساب #{user.id}. أرسل كلمة المرور الجديدة لصاحب الحساب بشكل آمن.', 'success')
    elif action == 'ban':
        if user.role == 'admin':
            flash('لا يمكن حظر حساب مدير.', 'error')
        else:
            user.is_banned = True
            user.ban_reason = request.form.get('ban_reason', '').strip()[:500] or 'مخالفة شروط الاستخدام'
            user.ban_appeal = ''
            user.appeal_status = ''
            db.session.commit()
            flash(f'تم حظر الحساب #{user.id}.', 'success')
    elif action == 'unban':
        user.is_banned = False
        user.ban_reason = ''
        user.ban_appeal = ''
        user.appeal_status = ''
        db.session.commit()
        flash(f'تم رفع الحظر عن الحساب #{user.id}.', 'success')
    elif action == 'appeal_reviewed':
        user.appeal_status = 'تمت المراجعة'
        db.session.commit()
        flash('تم تحديث حالة الاعتراض.', 'success')
    elif action == 'make_trusted_merchant':
        if user.role == 'admin':
            flash('لا يمكن تغيير نوع حساب المدير.', 'error')
        else:
            user.role = 'merchant'
            user.is_trusted_merchant = True
            db.session.commit()
            flash(f'تم تحويل الحساب #{user.id} إلى تاجر موثوق.', 'success')
    elif action == 'remove_merchant':
        if user.role == 'merchant':
            user.role = 'user'
            user.is_trusted_merchant = False
            db.session.commit()
            flash(f'تم إلغاء صفة التاجر عن الحساب #{user.id}.', 'success')
    return redirect(url_for('admin_accounts', account_id=user.id))

@app.route('/admin/handle_deposit/<int:deposit_id>', methods=['POST'])
@admin_required
def handle_deposit(deposit_id):
    deposit = DepositRequest.query.get_or_404(deposit_id)
    action = request.form.get('action', '').strip()
    if deposit.status != 'قيد المراجعة':
        flash('تمت معالجة طلب التحويل هذا سابقاً.', 'error')
        return redirect(url_for('admin'))
    if action == 'approve':
        user = db.session.get(User, deposit.user_id)
        if not user:
            flash('تعذر العثور على حساب صاحب الطلب.', 'error')
            return redirect(url_for('admin'))
        user.balance_usd = (user.balance_usd or 0) + (deposit.amount or 0)
        deposit.status = 'مقبول'
        deposit.rejection_reason = ''
        send_user_notification(user.id, 'تم شحن محفظتك', f'تمت الموافقة على طلب الشحن وإضافة ${format_money(deposit.amount)} إلى حسابك.', url_for('deposit'))
        db.session.commit()
        flash(f'تم قبول طلب الشحن #{deposit.id} وإضافة ${format_money(deposit.amount)} إلى المحفظة.', 'success')
    elif action == 'reject':
        reason = request.form.get('reject_reason', '').strip()
        if not reason:
            flash('اكتب سبب رفض التحويل ليظهر للمستخدم.', 'error')
            return redirect(url_for('admin'))
        deposit.status = 'مرفوض'
        deposit.rejection_reason = reason[:500]
        send_user_notification(deposit.user_id, 'تم رفض طلب الشحن', f'سبب الرفض: {deposit.rejection_reason}', url_for('deposit'))
        db.session.commit()
        flash(f'تم رفض طلب الشحن #{deposit.id} مع حفظ سبب الرفض.', 'success')
    else:
        flash('الإجراء غير معروف.', 'error')
    return redirect(url_for('admin'))

@app.route('/admin/complete_order/<int:order_id>', methods=['POST'])
@admin_required
def complete_order(order_id):
    order = Order.query.get_or_404(order_id)
    if order.status == 'فشل':
        flash('لا يمكن إكمال طلب فاشل تم رد قيمته للزبون.', 'error')
        return redirect(url_for('admin'))
    order.status = 'مكتمل'
    order.failure_reason = ''
    send_user_notification(order.user_id, 'تم إكمال طلبك', f'تم إكمال الطلب #{order.id} لخدمة {order.service_name} بنجاح.', url_for('my_orders'))
    db.session.commit()
    flash(f'تم تعيين الطلب #{order.id} كمكتمل.', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/fail_order/<int:order_id>', methods=['POST'])
@admin_required
def fail_order(order_id):
    order = Order.query.filter_by(id=order_id).with_for_update().first_or_404()
    reason = request.form.get('failure_reason', '').strip()
    if not reason:
        flash('اكتب سبب فشل الطلب ليظهر للزبون.', 'error')
        return redirect(url_for('admin'))
    if order.status == 'فشل':
        flash('هذا الطلب فاشل مسبقاً وتم رد قيمته، لم يتم رد المبلغ مرة أخرى.', 'error')
        return redirect(url_for('admin'))
    if order.status == 'مكتمل':
        flash('لا يمكن تعيين طلب مكتمل كفاشل.', 'error')
        return redirect(url_for('admin'))
    # Refund exactly once: failed status is the idempotency guard.
    user = User.query.filter_by(id=order.user_id).with_for_update().first()
    if not user:
        flash('تعذر العثور على حساب الزبون.', 'error')
        return redirect(url_for('admin'))
    refund = float(order.total_price or 0)
    user.balance_usd = round(float(user.balance_usd or 0) + refund, 2)
    order.status = 'فشل'
    order.failure_reason = reason[:500]
    send_user_notification(
        order.user_id,
        'فشل الطلب وتم رد المبلغ',
        f'تعذر تنفيذ الطلب #{order.id} ({order.service_name}). السبب: {order.failure_reason}. تمت إعادة ${format_money(refund)} إلى رصيد محفظتك.',
        url_for('my_orders')
    )
    db.session.commit()
    flash(f'تم تسجيل فشل الطلب #{order.id} وإعادة ${format_money(refund)} إلى محفظة الزبون.', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/handle_verification/<int:req_id>', methods=['POST'])
@admin_required
def handle_verification(req_id):
    req = VerificationRequest.query.get_or_404(req_id); action=request.form.get('action')
    if action == 'approve':
        req.user.is_verified=True; req.status='approved'; req.rejection_reason=''
    else:
        reason=request.form.get('reject_reason','').strip()
        if not reason:
            flash('اكتب سبب الرفض ليظهر للمستخدم.', 'error'); return redirect(url_for('admin'))
        req.status='rejected'; req.rejection_reason=reason
    db.session.commit(); flash('تم تحديث طلب التوثيق.', 'success'); return redirect(url_for('admin'))

@app.route('/admin/withdraw_balance', methods=['POST'])
@admin_required
def withdraw_balance():
    user_id = request.form.get('user_id', type=int)
    amount = request.form.get('amount', type=float)
    reason = request.form.get('reason', '').strip()
    user = User.query.filter_by(id=user_id).with_for_update().first() if user_id else None
    if not user:
        flash('لم يتم العثور على حساب بهذا المعرف.', 'error')
    elif amount is None or not math.isfinite(amount) or amount <= 0 or round(amount, 2) != amount:
        flash('أدخل مبلغاً صحيحاً أكبر من صفر وبحد أقصى منزلتين عشريتين.', 'error')
    elif not reason:
        flash('اكتب سبب سحب الرصيد ليصل إلى إشعارات الزبون.', 'error')
    elif amount > (user.balance_usd or 0):
        flash(f'الرصيد غير كافٍ. الرصيد الحالي ${format_money(user.balance_usd)}.', 'error')
    else:
        # Keep a durable audit record and the balance change in one transaction.
        user.balance_usd = round((user.balance_usd or 0) - amount, 2)
        db.session.add(WalletTransaction(user_id=user.id, admin_id=current_user().id,
                                         transaction_type='withdrawal', amount=amount, reason=reason[:500]))
        send_user_notification(user.id, 'تم سحب مبلغ من محفظتك',
            f'تم سحب ${format_money(amount)} من رصيدك. السبب: {reason[:350]}', url_for('profile'))
        db.session.commit()
        flash(f'تم سحب ${format_money(amount)} من حساب #{user.id} وإرسال إشعار له.', 'success')
    return redirect(url_for('admin'))


@app.route('/admin/send_balance', methods=['POST'])
@admin_required
def send_balance():
    user=User.query.get(request.form.get('user_id',type=int)); amount=request.form.get('amount',type=float)
    if not user or amount is None or amount <= 0: flash('تحقق من ID والمبلغ.', 'error')
    else: user.balance_usd += amount; db.session.commit(); flash('تم إرسال الرصيد.', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/add_merchant', methods=['POST'])
@admin_required
def add_merchant():
    username=request.form.get('username','').strip(); password=request.form.get('password','')
    if not username or len(password)<8 or User.query.filter_by(username=username).first(): flash('تعذر إنشاء التاجر: تحقق من البيانات وكلمة المرور (8 أحرف على الأقل).', 'error')
    else:
        user=User(username=username, role='merchant', is_trusted_merchant=True, balance_usd=max(0, request.form.get('bonus',type=float) or 0)); user.set_password(password); db.session.add(user); db.session.commit(); flash('تم إنشاء حساب التاجر.', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/add_payment', methods=['POST'])
@admin_required
def add_payment():
    name = request.form.get('name','').strip()
    if not name:
        flash('اكتب اسم طريقة الدفع.', 'error')
    else:
        db.session.add(PaymentMethod(name=name, qr_code_url=request.form.get('qr_code_url','').strip(), account_number=request.form.get('account_number','').strip(), instructions=request.form.get('instructions','').strip()))
        db.session.commit(); flash('تمت إضافة طريقة الدفع.', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/delete_payment/<int:payment_id>', methods=['POST'])
@admin_required
def delete_payment(payment_id):
    payment = PaymentMethod.query.get_or_404(payment_id)
    db.session.delete(payment)
    db.session.commit()
    flash('تم حذف طريقة الدفع.', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/add_sms_number_provider', methods=['POST'])
@admin_required
def add_sms_number_provider():
    name = request.form.get('name', '').strip()
    api_url = request.form.get('api_url', '').strip()
    api_key = request.form.get('api_key', '').strip()
    protocol = request.form.get('protocol', 'generic').strip()
    if not name or not api_url.startswith(('https://', 'http://')) or not api_key:
        flash('أدخل اسم مزوّد الأرقام ورابط API ومفتاح API بشكل صحيح.', 'error')
    else:
        db.session.add(SMSNumberProvider(name=name, api_url=api_url, api_key=api_key, protocol=protocol, notes=request.form.get('notes', '').strip()))
        db.session.commit()
        flash('تم حفظ إعدادات مزوّد الأرقام. تفعيل الشراء واستلام SMS يتطلب ضبط توافق API الخاص بالمزوّد.', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/delete_sms_number_provider/<int:provider_id>', methods=['POST'])
@admin_required
def delete_sms_number_provider(provider_id):
    provider = SMSNumberProvider.query.get_or_404(provider_id)
    db.session.delete(provider)
    db.session.commit()
    flash('تم حذف إعدادات مزوّد الأرقام.', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/add_agent', methods=['POST'])
@admin_required
def add_agent():
    db.session.add(Agent(name=request.form.get('name','').strip(), city=request.form.get('city','').strip(), phone=request.form.get('phone','').strip(), details=request.form.get('address','').strip())); db.session.commit(); flash('تمت إضافة الوكيل.', 'success'); return redirect(url_for('admin'))

@app.route('/admin/delete_agent/<int:agent_id>', methods=['POST'])
@admin_required
def delete_agent(agent_id):
    agent = db.session.get(Agent, agent_id)
    if not agent:
        flash('الوكيل غير موجود أو تم حذفه مسبقاً.', 'error')
    else:
        db.session.delete(agent)
        db.session.commit()
        flash('تم حذف الوكيل بنجاح.', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/add_smm_provider', methods=['POST'])
@admin_required
def add_smm_provider():
    name = request.form.get('provider_name', '').strip()
    api_url = request.form.get('api_url', '').strip()
    test_key = request.form.get('test_api_key', '').strip()
    live_key = request.form.get('live_api_key', '').strip() or request.form.get('api_key', '').strip()
    if not name or not api_url.startswith(('https://', 'http://')) or not live_key:
        flash('أدخل اسم المزوّد ورابط API والمفتاح الفعلي.', 'error')
    else:
        db.session.add(SMMProvider(name=name, api_url=api_url, api_key=protect_api_key(live_key), test_api_key=protect_api_key(test_key), live_api_key=protect_api_key(live_key)))
        db.session.commit()
        flash('تم حفظ مزوّد API. احتفظ بالمفتاح سرياً.', 'success')
    return redirect(url_for('admin'))


@app.route('/admin/test_smm_provider/<int:provider_id>', methods=['POST'])
@admin_required
def test_smm_provider(provider_id):
    provider = SMMProvider.query.get_or_404(provider_id)
    try:
        response = requests.post(provider.api_url, data={'key': reveal_api_key(provider.test_api_key or provider.api_key), 'action': 'balance'}, timeout=15)
        response.raise_for_status()
        data = response.json()
        if data.get('error'):
            raise ValueError(str(data['error']))
        balance = data.get('balance', 'غير متاح')
        currency = data.get('currency', '')
        flash(f'نجح اختبار API للمزوّد {provider.name}. الرصيد: {balance} {currency}', 'success')
    except Exception as exc:
        flash(f'فشل اختبار API للمزوّد {provider.name}: {str(exc)[:220]}', 'error')
    return redirect(url_for('admin'))

@app.route('/admin/fetch_smm_services/<int:provider_id>', methods=['POST'])
@admin_required
def fetch_smm_services(provider_id):
    provider = SMMProvider.query.get_or_404(provider_id)
    try:
        response = requests.post(provider.api_url, data={'key': reveal_api_key(provider.api_key), 'action': 'services'}, timeout=20)
        response.raise_for_status()
        data = response.json()
        if isinstance(data, dict) and data.get('error'):
            raise ValueError(str(data['error']))
        if not isinstance(data, list):
            raise ValueError('استجابة API غير متوقعة؛ يجب أن تكون قائمة خدمات.')
        # Replace the catalog only after a valid list response. The delete and inserts
        # remain in one transaction, so a failure rolls the previous catalog back.
        imported_count = 0
        SMMCatalogService.query.filter_by(provider_id=provider.id).delete(synchronize_session=False)
        for item in data:
            if not isinstance(item, dict) or item.get('service') is None:
                continue
            try:
                rate = float(item.get('rate') or 0)
                min_q = max(1, int(item.get('min') or 1))
                max_q = max(min_q, int(item.get('max') or 10000))
            except (TypeError, ValueError):
                rate, min_q, max_q = 0, 1, 10000
            db.session.add(SMMCatalogService(provider_id=provider.id, service_code=str(item.get('service')),
                name=str(item.get('name') or item.get('service')), category_name=str(item.get('category') or ''),
                rate=rate, min_quantity=min_q, max_quantity=max_q))
            imported_count += 1
        if imported_count == 0:
            raise ValueError('لم تتضمن استجابة السيرفر أي خدمات صالحة؛ لم يتم تحديث الكتالوج.')
        db.session.commit()
        flash(f'تم تحديث وحفظ {imported_count} خدمة من {provider.name}. يمكنك اختيار رقمها عند إضافة المنتج.', 'success')
    except Exception as exc:
        db.session.rollback()
        flash(f'تعذر جلب خدمات API: {str(exc)[:220]}', 'error')
    return redirect(url_for('admin'))

@app.route('/admin/delete_smm_provider/<int:provider_id>', methods=['POST'])
@admin_required
def delete_smm_provider(provider_id):
    provider = SMMProvider.query.get_or_404(provider_id)
    for service in Service.query.filter_by(api_provider_id=provider.id).all():
        service.api_provider_id = None
    db.session.delete(provider); db.session.commit()
    flash('تم حذف مزوّد API وفصل الخدمات المرتبطة به.', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/add_category', methods=['POST'])
@admin_required
def add_category():
    name = request.form.get('category_name', '').strip()
    if not name:
        flash('أدخل اسم القسم الرئيسي.', 'error')
    elif Category.query.filter_by(name=name, parent_id=None).first():
        flash('القسم الرئيسي موجود مسبقاً.', 'error')
    else:
        try:
            image_url = save_uploaded_image('category_image_file') or request.form.get('category_image_url', '').strip()
        except ValueError as exc:
            flash(str(exc), 'error')
            return redirect(url_for('admin'))
        db.session.add(Category(name=name, parent_id=None, image_url=image_url))
        db.session.commit()
        flash('تم إنشاء القسم الرئيسي بنجاح' + (' مع الصورة.' if image_url else '.'), 'success')
    return redirect(url_for('admin'))


@app.route('/admin/update_category_image', methods=['POST'])
@admin_required
def update_category_image():
    category_id = request.form.get('category_id', type=int)
    category = Category.query.filter_by(id=category_id, parent_id=None).first() if category_id else None
    if not category:
        flash('اختر قسماً رئيسياً صحيحاً.', 'error')
        return redirect(url_for('admin'))
    try:
        image_url = save_uploaded_image('category_image_file') or request.form.get('category_image_url', '').strip()
    except ValueError as exc:
        flash(str(exc), 'error')
        return redirect(url_for('admin'))
    if not image_url:
        flash('اختر صورة من جهازك أو أدخل رابط الصورة.', 'error')
        return redirect(url_for('admin'))
    category.image_url = image_url
    db.session.commit()
    flash('تم حفظ صورة القسم الرئيسي بنجاح.', 'success')
    return redirect(url_for('admin'))


@app.route('/admin/add_subcategory', methods=['POST'])
@admin_required
def add_subcategory():
    name = request.form.get('subcategory_name', '').strip()
    parent_id = request.form.get('parent_id', type=int)
    parent = Category.query.filter_by(id=parent_id, parent_id=None).first() if parent_id else None
    if not name or not parent:
        flash('اختر قسماً رئيسياً وأدخل اسم القسم الفرعي.', 'error')
    elif Category.query.filter_by(name=name, parent_id=parent.id).first():
        flash('القسم الفرعي موجود مسبقاً.', 'error')
    else:
        try:
            image_url = save_uploaded_image('subcategory_image_file') or request.form.get('subcategory_image_url', '').strip()
        except ValueError as exc:
            flash(str(exc), 'error')
            return redirect(url_for('admin'))
        db.session.add(Category(name=name, parent_id=parent.id, image_url=image_url)); db.session.commit()
        flash('تم إنشاء القسم الفرعي بنجاح مع الصورة.', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/add_service', methods=['POST'])
@admin_required
def add_service():
    name=request.form.get('name','').strip(); category_id=request.form.get('category_id', type=int); category_name=request.form.get('category_name','').strip()
    if not name or (not category_id and not category_name): flash('أدخل اسم الخدمة واختر القسم الرئيسي أو الفرعي.', 'error'); return redirect(url_for('admin'))
    try:
        category_image = save_uploaded_image('category_image_file') or request.form.get('category_image_url','').strip()
        product_image = save_uploaded_image('image_file') or request.form.get('image_url','').strip()
    except ValueError as exc:
        flash(str(exc), 'error'); return redirect(url_for('admin'))
    cat=Category.query.get(category_id) if category_id else Category.query.filter_by(name=category_name).first()
    if not cat and category_name:
        cat=Category(name=category_name, image_url=category_image); db.session.add(cat); db.session.flush()
    if not cat:
        flash('القسم المحدد غير موجود.', 'error'); return redirect(url_for('admin'))
    if category_image: cat.image_url = category_image
    price=request.form.get('price_per_1000',type=float) or 0
    typ=request.form.get('service_type','manual')
    if typ not in ('manual', 'manual_quantity', 'smm', 'smm_fixed'): typ = 'manual'
    minimum = request.form.get('min_quantity',type=int) or 1
    maximum = request.form.get('max_quantity',type=int) or 10000
    if price < 0 or minimum < 1 or maximum < minimum:
        flash('تحقق من السعر والحد الأدنى والأقصى للكمية.', 'error')
        return redirect(url_for('admin'))
    provider_id = request.form.get('api_provider_id', type=int) if typ in ('smm', 'smm_fixed') else None
    api_service_id = request.form.get('api_service_id', '').strip() if typ in ('smm', 'smm_fixed') else ''
    if typ in ('smm', 'smm_fixed') and (not provider_id or not api_service_id):
        flash('لخدمة SMM تلقائية، اختر مزوّد API وأدخل رقم الخدمة لدى المزوّد.', 'error'); return redirect(url_for('admin'))
    service=Service(name=name, category_id=cat.id, price=price, price_per_1000=price, min_quantity=(minimum if typ in ('smm', 'manual_quantity') else 1), max_quantity=(maximum if typ in ('smm', 'manual_quantity') else 1), input_label=request.form.get('input_label','الرابط أو الآيدي').strip(), service_type=typ, api_provider_id=provider_id, api_service_id=api_service_id, image_url=product_image, description=request.form.get('description','').strip(), extra_details=request.form.get('extra_details','').strip(), is_available=(request.form.get('is_available', '1') == '1'))
    db.session.add(service); db.session.commit(); flash('تمت إضافة الخدمة.', 'success'); return redirect(url_for('admin'))

@app.route('/admin/update_service/<int:service_id>', methods=['POST'])
@admin_required
def update_service(service_id):
    service = Service.query.get_or_404(service_id)
    name = request.form.get('name', '').strip()
    category_id = request.form.get('category_id', type=int)
    category_name = request.form.get('category_name', '').strip()
    if not name or (not category_id and not category_name):
        flash('أدخل اسم المنتج واختر القسم.', 'error')
        return redirect(url_for('admin'))
    category = Category.query.get(category_id) if category_id else Category.query.filter_by(name=category_name).first()
    if not category and category_name:
        category = Category(name=category_name)
        db.session.add(category)
        db.session.flush()
    if not category:
        flash('القسم المحدد غير موجود.', 'error')
        return redirect(url_for('admin'))
    try:
        price = float(request.form.get('price_per_1000', '0'))
        minimum = int(request.form.get('min_quantity', '1'))
        maximum = int(request.form.get('max_quantity', '10000'))
    except (TypeError, ValueError):
        flash('تحقق من السعر والحد الأدنى والأقصى.', 'error')
        return redirect(url_for('admin'))
    typ = request.form.get('service_type', 'manual')
    if typ not in ('manual', 'manual_quantity', 'smm', 'smm_fixed'): typ = 'manual'
    if price < 0 or minimum < 1 or maximum < minimum:
        flash('السعر يجب أن يكون موجباً، والحد الأقصى أكبر من أو يساوي الحد الأدنى.', 'error')
        return redirect(url_for('admin'))
    provider_id = request.form.get('api_provider_id', type=int) if typ in ('smm', 'smm_fixed') else None
    api_service_id = request.form.get('api_service_id', '').strip() if typ in ('smm', 'smm_fixed') else ''
    if typ in ('smm', 'smm_fixed') and (not provider_id or not api_service_id):
        flash('اختر مزوّد API وأدخل رقم الخدمة للتلقائي SMM.', 'error')
        return redirect(url_for('admin'))
    service.name = name
    service.category_id = category.id
    service.price = price
    service.price_per_1000 = price
    service.min_quantity = minimum if typ in ('smm', 'manual_quantity') else 1
    service.max_quantity = maximum if typ in ('smm', 'manual_quantity') else 1
    service.input_label = request.form.get('input_label', 'الرابط أو الآيدي').strip()
    service.service_type = typ
    service.api_provider_id = provider_id
    service.api_service_id = api_service_id
    service.description = request.form.get('description', '').strip()
    service.extra_details = request.form.get('extra_details', '').strip()
    service.is_available = request.form.get('is_available', '0') == '1'
    try:
        image = save_uploaded_image('image_file')
        if image: service.image_url = image
        elif request.form.get('image_url', '').strip(): service.image_url = request.form.get('image_url', '').strip()
    except ValueError as exc:
        flash(str(exc), 'error')
        return redirect(url_for('admin'))
    db.session.commit()
    flash('تم تحديث المنتج وإعداداته.', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/toggle_service/<int:service_id>', methods=['POST'])
@admin_required
def toggle_service(service_id):
    service = Service.query.get_or_404(service_id)
    service.is_available = not service.is_available
    db.session.commit()
    flash('تم تحديث حالة توفر المنتج.', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/delete_category', methods=['POST'])
@admin_required
def delete_category():
    cat=Category.query.get(request.form.get('category_id',type=int))
    if cat:
        for s in list(cat.services): db.session.delete(s)
        db.session.delete(cat); db.session.commit(); flash('تم حذف القسم وخدماته.', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/delete_service', methods=['POST'])
@admin_required
def delete_service():
    service = Service.query.get(request.form.get('service_id', type=int))
    if not service:
        flash('الخدمة المحددة غير موجودة.', 'error')
        return redirect(url_for('admin'))
    try:
        # Keep historical orders intact while removing the service itself.
        Order.query.filter_by(service_id=service.id).update({Order.service_id: None}, synchronize_session=False)
        db.session.delete(service)
        db.session.commit()
        flash('تم حذف الخدمة بنجاح، مع الحفاظ على سجل الطلبات السابقة.', 'success')
    except Exception:
        db.session.rollback()
        app.logger.exception('Failed to delete service')
        flash('تعذر حذف الخدمة حالياً. تحقق من ارتباطاتها ثم حاول مجدداً.', 'error')
    return redirect(url_for('admin'))

@app.route('/admin/export_backup')
@admin_required
def export_backup():
    """Export all mapped application tables into a portable CSV backup."""
    import csv, io, json
    from flask import Response

    out = io.StringIO(newline='')
    writer = csv.writer(out)
    writer.writerow(['backup_format', 'owj_media_full_backup_v3'])
    writer.writerow(['table_name', 'row_json'])
    total = 0
    # Include a table marker even when the table is empty, so the restore can
    # distinguish a valid empty table from a backup that contains no records.
    for mapper in sorted(db.Model.registry.mappers, key=lambda item: item.local_table.name):
        model = mapper.class_
        writer.writerow(['__table__', model.__tablename__])
        query = model.query.order_by(model.id) if hasattr(model, 'id') else model.query
        for obj in query.all():
            data = {}
            for column in mapper.columns:
                value = getattr(obj, column.key)
                if isinstance(value, datetime):
                    value = value.isoformat()
                data[column.key] = value
            writer.writerow([model.__tablename__, json.dumps(data, ensure_ascii=False, separators=(',', ':'))])
            total += 1
    payload = '\ufeff' + out.getvalue()
    return Response(payload, mimetype='text/csv; charset=utf-8', headers={
        'Content-Disposition': 'attachment; filename=owj_media_full_backup_v3.csv',
        'Cache-Control': 'no-store'
    })


@app.route('/admin/import_backup', methods=['POST'])
@admin_required
def import_backup():
    """Validate and atomically restore a complete v2/v3 CSV database backup."""
    import csv, io, json
    from sqlalchemy import text
    from sqlalchemy.types import DateTime, Integer

    file = request.files.get('backup_file')
    if not file or not file.filename:
        flash('اختر ملف النسخة الاحتياطية CSV أولاً.', 'error')
        return redirect(url_for('admin'))
    if not file.filename.lower().endswith('.csv'):
        flash('الملف يجب أن يكون بصيغة CSV.', 'error')
        return redirect(url_for('admin'))

    try:
        raw = file.stream.read().decode('utf-8-sig')
        rows = list(csv.reader(io.StringIO(raw)))
        if not rows or len(rows[0]) != 2 or rows[0][0] != 'backup_format' or rows[0][1] not in ('owj_media_full_backup_v2', 'owj_media_full_backup_v3'):
            raise ValueError('صيغة النسخة غير مدعومة. نزّل نسخة جديدة من زر «تنزيل نسخة احتياطية كاملة (CSV)» ثم ارفعها.')
        backup_version = rows[0][1]
        if len(rows) < 2 or rows[1] != ['table_name', 'row_json']:
            raise ValueError('ملف CSV غير مكتمل أو تنسيقه غير صحيح.')

        models_by_table = {mapper.local_table.name: mapper.class_ for mapper in db.Model.registry.mappers}
        grouped = {table: [] for table in models_by_table}
        declared_tables = set()
        for line_no, row in enumerate(rows[2:], start=3):
            if not row or all(not cell for cell in row):
                continue
            if backup_version == 'owj_media_full_backup_v3' and len(row) == 2 and row[0] == '__table__':
                if row[1] not in models_by_table:
                    raise ValueError(f'النسخة تحتوي جدولًا غير معروف: {row[1]}')
                declared_tables.add(row[1])
                continue
            if len(row) != 2 or row[0] not in models_by_table:
                raise ValueError(f'بيانات غير صالحة في السطر {line_no}.')
            table_name, raw_json = row
            try:
                data = json.loads(raw_json)
            except Exception:
                raise ValueError(f'تعذر قراءة سجل CSV في السطر {line_no}.')
            if not isinstance(data, dict):
                raise ValueError(f'سجل غير صالح في السطر {line_no}.')
            model = models_by_table[table_name]
            allowed = {column.key for column in model.__table__.columns}
            if not set(data).issubset(allowed):
                raise ValueError(f'تحتوي النسخة أعمدة غير معروفة في جدول {table_name}.')
            for column in model.__table__.columns:
                value = data.get(column.key)
                if value is not None and isinstance(column.type, DateTime) and isinstance(value, str):
                    data[column.key] = datetime.fromisoformat(value)
            grouped[table_name].append(data)

        total_records = sum(len(items) for items in grouped.values())
        if total_records == 0:
            raise ValueError('الملف لا يحتوي أي سجلات لاستعادتها؛ لم يتم تغيير قاعدة البيانات.')
        if 'user' in models_by_table and not grouped.get('user'):
            raise ValueError('النسخة لا تحتوي حسابات مستخدمين؛ رفضت الاستعادة لحماية بيانات الموقع الحالية.')
        if backup_version == 'owj_media_full_backup_v3' and not declared_tables:
            raise ValueError('النسخة لا تحتوي تعريفات الجداول؛ لم يتم تغيير قاعدة البيانات.')

        # Parent tables are inserted before dependent tables. Delete in reverse order.
        ordered = []
        pending = set(models_by_table)
        while pending:
            ready = []
            for table in pending:
                deps = {fk.column.table.name for fk in models_by_table[table].__table__.foreign_keys
                        if fk.column.table.name in pending and fk.column.table.name != table}
                if not deps:
                    ready.append(table)
            if not ready:
                raise ValueError('تعذر تحديد ترتيب الجداول بسبب علاقة دائرية؛ لم يتم تغيير البيانات.')
            for table in sorted(ready):
                ordered.append(table)
                pending.remove(table)

        with db.engine.begin() as connection:
            # Deletion and insertion are in one transaction: any failure rolls back everything.
            for table in reversed(ordered):
                connection.execute(text(f'DELETE FROM "{table}"'))
            for table in ordered:
                model = models_by_table[table]
                if grouped[table]:
                    connection.execute(model.__table__.insert(), grouped[table])
            # Verify the restored row counts before committing the transaction.
            mismatches = []
            for table in ordered:
                actual = connection.execute(text(f'SELECT COUNT(*) FROM "{table}"')).scalar_one()
                expected = len(grouped[table])
                if actual != expected:
                    mismatches.append(f'{table}: المتوقع {expected} / الموجود {actual}')
            if mismatches:
                raise ValueError('فشل التحقق من بعض الجداول: ' + '، '.join(mismatches[:5]))
            if db.engine.dialect.name == 'postgresql':
                for table in ordered:
                    model = models_by_table[table]
                    pk = next(iter(model.__table__.primary_key.columns), None)
                    if pk is not None and isinstance(pk.type, Integer):
                        connection.execute(text(
                            "SELECT setval(pg_get_serial_sequence(:table_name, :column_name), "
                            "GREATEST(COALESCE((SELECT MAX(\"" + pk.name + "\") FROM \"" + table + "\"), 1), 1), true)"
                        ), {'table_name': table, 'column_name': pk.name})

        nonempty_tables = sum(1 for items in grouped.values() if items)
        details = '، '.join(f'{table}: {len(items)}' for table, items in grouped.items() if items)
        flash(f'تم التحقق من الاستعادة بنجاح: {total_records} سجلًا في {nonempty_tables} جداول. {details}', 'success')
    except Exception as exc:
        db.session.rollback()
        flash('فشلت الاستعادة ولم تُعتمد أي تغييرات. السبب: ' + str(exc), 'error')
    return redirect(url_for('admin'))

with app.app_context():
    db.create_all()
    # Add failure reason to existing order tables without losing existing orders.
    try:
        from sqlalchemy import inspect
        order_columns = {column['name'] for column in inspect(db.engine).get_columns('order')}
        if 'failure_reason' not in order_columns:
            db.session.execute(db.text("ALTER TABLE \"order\" ADD COLUMN failure_reason VARCHAR(500) DEFAULT ''"))
        db.session.commit()
    except Exception:
        db.session.rollback()
    try:
        if not SiteSetting.query.filter_by(key='usd_to_syp_rate').first():
            db.session.add(SiteSetting(key='usd_to_syp_rate', value='10000'))
            db.session.commit()
    except Exception:
        db.session.rollback()
    # Safe additive migration: separate customer-facing extra details from the red order notice.
    try:
        from sqlalchemy import inspect
        service_columns = {column['name'] for column in inspect(db.engine).get_columns('service')}
        if 'extra_details' not in service_columns:
            db.session.execute(db.text("ALTER TABLE service ADD COLUMN extra_details TEXT DEFAULT ''"))
        db.session.commit()
    except Exception:
        db.session.rollback()
    # Safe additive migration: preserve all existing user accounts and data.
    try:
        from sqlalchemy import inspect
        user_columns = {column['name'] for column in inspect(db.engine).get_columns('user')}
        additions = [('is_banned', 'BOOLEAN DEFAULT FALSE'), ('ban_reason', "VARCHAR(500) DEFAULT ''"), ('ban_appeal', "TEXT DEFAULT ''"), ('appeal_status', "VARCHAR(30) DEFAULT ''"), ('is_trusted_merchant', 'BOOLEAN DEFAULT FALSE'), ('currency', "VARCHAR(3) DEFAULT 'USD'")]
        for column_name, definition in additions:
            if column_name not in user_columns:
                db.session.execute(db.text(f'ALTER TABLE "user" ADD COLUMN {column_name} {definition}'))
        db.session.commit()
    except Exception:
        db.session.rollback()
    # Add fields to existing databases without deleting user data.
    try:
        from sqlalchemy import inspect
        deposit_columns = {column['name'] for column in inspect(db.engine).get_columns('deposit_request')}
        if 'rejection_reason' not in deposit_columns:
            db.session.execute(db.text("ALTER TABLE deposit_request ADD COLUMN rejection_reason VARCHAR(500) DEFAULT ''"))
        if 'proof_image' not in deposit_columns:
            db.session.execute(db.text("ALTER TABLE deposit_request ADD COLUMN proof_image TEXT DEFAULT ''"))
        elif db.engine.dialect.name == 'postgresql':
            db.session.execute(db.text("ALTER TABLE deposit_request ALTER COLUMN proof_image TYPE TEXT"))
        if 'payment_method_name' not in deposit_columns:
            db.session.execute(db.text("ALTER TABLE deposit_request ADD COLUMN payment_method_name VARCHAR(120) DEFAULT ''"))
        db.session.commit()
    except Exception:
        db.session.rollback()
    # Add fields to existing SQLite databases without deleting user data.
    try:
        columns = {row[1] for row in db.session.execute(db.text('PRAGMA table_info(verification_request)')).fetchall()}
        for col, definition in [('gender', "VARCHAR(30) DEFAULT ''"), ('age', 'INTEGER DEFAULT 0'), ('rejection_reason', "VARCHAR(500) DEFAULT ''")]:
            if col not in columns:
                db.session.execute(db.text(f'ALTER TABLE verification_request ADD COLUMN {col} {definition}'))
        db.session.commit()
    except Exception:
        db.session.rollback()
    try:
        from sqlalchemy import inspect
        service_columns = {column['name'] for column in inspect(db.engine).get_columns('service')}
        if 'api_provider_id' not in service_columns:
            db.session.execute(db.text('ALTER TABLE service ADD COLUMN api_provider_id INTEGER'))
        if 'api_service_id' not in service_columns:
            db.session.execute(db.text("ALTER TABLE service ADD COLUMN api_service_id VARCHAR(80) DEFAULT ''"))
        db.session.commit()
    except Exception:
        db.session.rollback()
    try:
        from sqlalchemy import inspect
        category_columns = {column['name'] for column in inspect(db.engine).get_columns('category')}
        if 'parent_id' not in category_columns:
            db.session.execute(db.text('ALTER TABLE category ADD COLUMN parent_id INTEGER'))
        db.session.commit()
    except Exception:
        db.session.rollback()
    try:
        from sqlalchemy import inspect
        provider_columns = {column['name'] for column in inspect(db.engine).get_columns('smm_provider')}
        for col in ('test_api_key', 'live_api_key'):
            if col not in provider_columns:
                db.session.execute(db.text(f"ALTER TABLE smm_provider ADD COLUMN {col} TEXT DEFAULT ''"))
        db.session.commit()
    except Exception:
        db.session.rollback()
    # Ensure the requested administrator credentials are always synchronized.
    admin_user = User.query.filter_by(username='yosf').first()
    if admin_user is None:
        admin_user = User.query.filter_by(role='admin').first()
    if admin_user is None:
        admin_user = User(username='yosf', full_name='مدير أوج ميديا', role='admin', balance_usd=0)
        db.session.add(admin_user)
    admin_user.username = 'yosf'
    admin_user.full_name = admin_user.full_name or 'مدير أوج ميديا'
    admin_user.role = 'admin'
    admin_user.set_password('2008rrnny')
    if Category.query.count() == 0:
        c1=Category(name='خدمات التواصل الاجتماعي'); c2=Category(name='شحن الألعاب'); db.session.add_all([c1,c2]); db.session.flush()
        db.session.add_all([
            Service(name='متابعون تجريبيون',category_id=c1.id,price=1.5,price_per_1000=1.5,min_quantity=10,max_quantity=10000,input_label='رابط الحساب أو المنشور',service_type='smm',description='خدمة تجريبية، عدّلها من لوحة الإدارة.'),
            Service(name='شحن ألعاب تجريبي',category_id=c2.id,price=2.0,price_per_1000=2.0,min_quantity=1,max_quantity=1,input_label='معرّف اللاعب ID',service_type='manual',description='خدمة تجريبية، عدّلها من لوحة الإدارة.')])
    db.session.commit()

if __name__ == '__main__':
    app.run(debug=os.environ.get('FLASK_DEBUG') == '1', host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
