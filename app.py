import os
import base64
import hashlib
import smtplib
from email.message import EmailMessage
import mimetypes
import math
import io
import csv
import json
import uuid
import zipfile
import tempfile
import shutil
import posixpath
import hashlib
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
# Backup archives may contain many product/category images.
app.config['MAX_CONTENT_LENGTH'] = 512 * 1024 * 1024


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

def encrypt_store_secret(value):
    return _api_cipher().encrypt((value or '').encode()).decode()
def decrypt_store_secret(value):
    try: return _api_cipher().decrypt((value or '').encode()).decode()
    except (InvalidToken, ValueError): return value or ''

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


class SiteLock(db.Model):
    __tablename__ = 'site_lock'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user = db.relationship('User')


class DigitalAccountProduct(db.Model):
    __tablename__ = 'digital_account_product'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(180), nullable=False)
    game = db.Column(db.String(100), default='')
    platform = db.Column(db.String(40), default='other')
    account_email = db.Column(db.String(240), nullable=False)
    encrypted_password = db.Column(db.Text, nullable=False)
    account_username = db.Column(db.String(240), default='')
    encrypted_username_password = db.Column(db.Text, default='')
    account_id = db.Column(db.String(160), default='')
    image_url = db.Column(db.String(500), default='')
    price = db.Column(db.Float, default=0.0)
    description = db.Column(db.Text, default='')
    is_available = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class DigitalAccountPurchase(db.Model):
    __tablename__ = 'digital_account_purchase'
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('digital_account_product.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    price_paid = db.Column(db.Float, default=0.0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    product = db.relationship('DigitalAccountProduct')
    user = db.relationship('User')


class MerchantApplication(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    user_id=db.Column(db.Integer,db.ForeignKey('user.id'),nullable=False)
    details=db.Column(db.Text,default='')
    facebook_url=db.Column(db.String(500),default='')
    instagram_url=db.Column(db.String(500),default='')
    status=db.Column(db.String(20),default='pending')
    weekly_bonus=db.Column(db.Float,default=0.0)
    last_bonus_at=db.Column(db.DateTime,default=None)
    created_at=db.Column(db.DateTime,default=datetime.utcnow)
    user=db.relationship('User')

class SocialLink(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    platform = db.Column(db.String(30), unique=True, nullable=False)
    url = db.Column(db.String(500), default='')
    username = db.Column(db.String(120), default='')


class ApiApplication(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    user_id=db.Column(db.Integer,db.ForeignKey('user.id'),nullable=False)
    website_url=db.Column(db.String(500),default='')
    details=db.Column(db.Text,default='')
    status=db.Column(db.String(20),default='pending')
    encrypted_key=db.Column(db.Text,default='')
    created_at=db.Column(db.DateTime,default=datetime.utcnow)
    user=db.relationship('User')

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    image_url = db.Column(db.String(500), default='')
    parent_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=True)
    sort_order = db.Column(db.Integer, default=0, nullable=False)
    parent = db.relationship('Category', remote_side=[id], backref=db.backref('subcategories', lazy=True))

class Service(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(160), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    price = db.Column(db.Float, default=1.0) # price per 1000 for SMM, fixed price for manual
    price_per_1000 = db.Column(db.Float, default=1.0)
    merchant_price = db.Column(db.Float, default=0.0)  # merchant-specific store price; 0 means use public price
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
    sort_order = db.Column(db.Integer, default=0, nullable=False)
    category = db.relationship('Category', backref=db.backref('services', lazy=True))

class SMMProvider(db.Model):
    __tablename__ = 'smm_provider'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    api_url = db.Column(db.String(500), nullable=False)
    api_key = db.Column(db.Text, nullable=False)  # encrypted live key (legacy field)
    test_api_key = db.Column(db.Text, default='')
    live_api_key = db.Column(db.Text, default='')
    api_protocol = db.Column(db.String(30), default='legacy')  # legacy or syria_market
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
    provider_order_id = db.Column(db.String(120), default='', index=True)
    # Additive order controls: prevent API polling from undoing admin decisions and make refunds idempotent.
    admin_status_override = db.Column(db.Boolean, default=False, nullable=False)
    refunded = db.Column(db.Boolean, default=False, nullable=False)
    status_note = db.Column(db.Text, default='')
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
        msg['Subject'] = f'NOVA STORE | {title}'
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
    return {'current_user': user, 'site_name': 'NOVA STORE', 'unread_notification_count': unread_count}

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

def employee_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        user = db.session.get(User, session.get('user_id')) if session.get('user_id') else None
        if not user or user.role not in ('admin', 'employee'):
            abort(403)
        return fn(*args, **kwargs)
    return wrapped

def current_user():
    return db.session.get(User, session.get('user_id')) if session.get('user_id') else None


def process_weekly_merchant_bonus(user):
    """Credit an approved merchant's weekly bonus at most once per 7 days."""
    application = (MerchantApplication.query
                   .filter_by(user_id=user.id, status='approved')
                   .order_by(MerchantApplication.id.desc())
                   .first())
    if not application:
        return
    try:
        bonus = max(0.0, float(application.weekly_bonus or 0))
    except (TypeError, ValueError):
        app.logger.exception('Invalid weekly merchant bonus for user %s', user.id)
        return
    if bonus <= 0:
        return
    now = datetime.utcnow()
    # Older approved requests may not have a timestamp; start their first cycle now.
    if not application.last_bonus_at:
        application.last_bonus_at = now
        db.session.commit()
        return
    if now - application.last_bonus_at >= timedelta(days=7):
        user.balance_usd = float(user.balance_usd or 0) + bonus
        application.last_bonus_at = now
        db.session.commit()

@app.before_request
def enforce_account_ban():
    user_id = session.get('user_id')
    if not user_id:
        return None
    user = db.session.get(User, user_id)
    if user and user.is_trusted_merchant and not user.is_banned and request.endpoint not in {'static'}:
        process_weekly_merchant_bonus(user)
    if user and user.is_banned and request.endpoint not in {'banned_account', 'submit_ban_appeal', 'logout', 'static'}:
        session.clear()
        return redirect(url_for('banned_account', user_id=user.id))
    # Optional per-account site lock. All pages stay inaccessible until unlocked.
    if user and request.endpoint not in {'static', 'site_lock', 'site_lock_unlock', 'logout'}:
        lock = SiteLock.query.filter_by(user_id=user.id).first()
        if lock and session.get('site_unlocked_user_id') != user.id:
            return redirect(url_for('site_lock'))
    return None


@app.route('/store/accounts')
def digital_accounts_store():
    products=DigitalAccountProduct.query.filter_by(is_available=True).order_by(DigitalAccountProduct.id.desc()).all()
    return render_template('digital_accounts_store.html', products=products)

@app.route('/store/accounts/<int:product_id>/buy', methods=['POST'])
@login_required
def buy_digital_account(product_id):
    product=DigitalAccountProduct.query.filter_by(id=product_id,is_available=True).first_or_404()
    user=current_user()
    if user.balance_usd < product.price:
        flash('رصيدك غير كافٍ. اشحن محفظتك ثم أعد المحاولة.','error')
        return redirect(url_for('digital_accounts_store'))
    user.balance_usd-=product.price
    product.is_available=False
    purchase=DigitalAccountPurchase(product_id=product.id,user_id=user.id,price_paid=product.price)
    db.session.add(purchase); db.session.commit()
    send_user_notification(user.id,'تم شراء الحساب',f'بيانات حساب {product.title} جاهزة للعرض.',url_for('my_digital_account',purchase_id=purchase.id))
    return redirect(url_for('my_digital_account',purchase_id=purchase.id))

@app.route('/store/accounts/my')
@login_required
def my_digital_accounts():
    purchases=DigitalAccountPurchase.query.filter_by(user_id=current_user().id).order_by(DigitalAccountPurchase.id.desc()).all()
    return render_template('my_digital_accounts.html',purchases=purchases)

@app.route('/store/accounts/purchase/<int:purchase_id>')
@login_required
def my_digital_account(purchase_id):
    purchase=DigitalAccountPurchase.query.filter_by(id=purchase_id,user_id=current_user().id).first_or_404()
    return render_template('digital_account_purchase.html',purchase=purchase,account_password=decrypt_store_secret(purchase.product.encrypted_password),username_password=decrypt_store_secret(purchase.product.encrypted_username_password))

@app.route('/admin/digital-accounts',methods=['GET','POST'])
@admin_required
def admin_digital_accounts():
    if request.method=='POST':
        try:
            title=request.form.get('title','').strip()
            email=request.form.get('account_email','').strip()
            password=request.form.get('account_password','').strip()
            account_username=request.form.get('account_username','').strip()
            username_password=request.form.get('username_password','').strip()
            platform=request.form.get('platform','other').strip().lower()
            if platform not in ('instagram','facebook','other'): platform='other'
            price=float(request.form.get('price','0'))
            if not title or not email or not password or price<0: raise ValueError('أدخل بيانات الحساب والسعر بشكل صحيح.')
            if (account_username and not username_password) or (username_password and not account_username): raise ValueError('أدخل يوزر الحساب وكلمة مروره معاً.')
            image=save_uploaded_image('image_file') or request.form.get('image_url','').strip()
            product=DigitalAccountProduct(title=title,game=request.form.get('game','').strip(),platform=platform,account_email=email,
                encrypted_password=encrypt_store_secret(password),account_username=account_username,
                encrypted_username_password=encrypt_store_secret(username_password) if username_password else '',account_id=request.form.get('account_id','').strip(),
                image_url=image,price=price,description=request.form.get('description','').strip())
            db.session.add(product); db.session.commit(); flash('تم إضافة الحساب للمتجر.','success')
        except Exception as exc:
            flash(str(exc) or 'تعذر الإضافة.','error')
        return redirect(url_for('admin_digital_accounts'))
    return render_template('admin_digital_accounts.html',products=DigitalAccountProduct.query.order_by(DigitalAccountProduct.id.desc()).all())

@app.route('/admin/digital-accounts/<int:product_id>/toggle',methods=['POST'])
@admin_required
def toggle_digital_account(product_id):
    item=DigitalAccountProduct.query.get_or_404(product_id)
    item.is_available=not item.is_available; db.session.commit()
    return redirect(url_for('admin_digital_accounts'))

@app.route('/admin/digital-accounts/<int:product_id>/delete',methods=['POST'])
@admin_required
def delete_digital_account(product_id):
    item=DigitalAccountProduct.query.get_or_404(product_id)
    if DigitalAccountPurchase.query.filter_by(product_id=item.id).count():
        flash('الحساب له عملية شراء سابقة. أوقف عرضه بدلاً من حذفه.','warning')
    else:
        db.session.delete(item); db.session.commit(); flash('تم حذف الحساب.','success')
    return redirect(url_for('admin_digital_accounts'))

@app.route('/robots.txt')
def robots_txt():
    from flask import Response
    site = os.environ.get('SITE_URL', request.url_root).rstrip('/')
    body = f"User-agent: *\nAllow: /\nDisallow: /admin\nDisallow: /profile\nDisallow: /notifications\nDisallow: /support\nDisallow: /api/\nSitemap: {site}/sitemap.xml\n"
    return Response(body, mimetype='text/plain')

@app.route('/sitemap.xml')
def sitemap_xml():
    from flask import Response
    site = os.environ.get('SITE_URL', request.url_root).rstrip('/')
    urls = ['/', '/about', '/login', '/register']
    xml = '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">' + ''.join(f'<url><loc>{site}{u}</loc></url>' for u in urls) + '</urlset>'
    return Response(xml, mimetype='application/xml')

@app.route('/')
def index():
    categories = Category.query.filter_by(parent_id=None).order_by(Category.sort_order.asc(), Category.id.asc()).all()
    services = Service.query.order_by(Service.sort_order.asc(), Service.id.desc()).all()
    return render_template('index.html', categories=categories, services=services)

@app.route('/accounts')
def accounts():
    services = Service.query.order_by(Service.sort_order.asc(), Service.id.desc()).all()
    return render_template('accounts.html', services=services)

@app.route('/category/<int:category_id>')
def category_services(category_id):
    category = Category.query.get_or_404(category_id)
    services = Service.query.filter_by(category_id=category_id).order_by(Service.sort_order.asc(), Service.id.desc()).all()
    subcategories = Category.query.filter_by(parent_id=category_id).order_by(Category.sort_order.asc(), Category.id.asc()).all()
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
            user = User(username=username, full_name=request.form.get('full_name','').strip(), email=request.form.get('email','').strip(), phone=request.form.get('phone','').strip())
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

@app.route('/site-lock', methods=['GET'])
def site_lock():
    user = current_user()
    if not user:
        return redirect(url_for('login'))
    lock = SiteLock.query.filter_by(user_id=user.id).first()
    if not lock:
        session['site_unlocked_user_id'] = user.id
        return redirect(url_for('index'))
    if session.get('site_unlocked_user_id') == user.id:
        return redirect(url_for('index'))
    return render_template('site_lock.html', user=user)


@app.route('/site-lock/unlock', methods=['POST'])
def site_lock_unlock():
    user = current_user()
    if not user:
        return redirect(url_for('login'))
    lock = SiteLock.query.filter_by(user_id=user.id).first()
    if not lock:
        session['site_unlocked_user_id'] = user.id
        return redirect(url_for('index'))
    now = datetime.utcnow().timestamp()
    blocked_until = float(session.get('site_lock_blocked_until', 0) or 0)
    if now < blocked_until:
        flash('محاولات كثيرة. انتظر دقيقة ثم حاول مجدداً.', 'error')
        return redirect(url_for('site_lock'))
    if check_password_hash(lock.password_hash, request.form.get('site_password', '')):
        session['site_unlocked_user_id'] = user.id
        session.pop('site_lock_attempts', None)
        session.pop('site_lock_blocked_until', None)
        return redirect(url_for('index'))
    attempts = int(session.get('site_lock_attempts', 0) or 0) + 1
    session['site_lock_attempts'] = attempts
    if attempts >= 5:
        session['site_lock_attempts'] = 0
        session['site_lock_blocked_until'] = now + 60
    flash('كلمة مرور قفل الموقع غير صحيحة.', 'error')
    return redirect(url_for('site_lock'))


@app.route('/site-lock/recover', methods=['POST'])
def recover_site_lock():
    user = current_user()
    if not user:
        return redirect(url_for('login'))
    if not user.check_password(request.form.get('account_password', '')):
        flash('كلمة مرور حسابك غير صحيحة.', 'error')
        return redirect(url_for('site_lock'))
    lock = SiteLock.query.filter_by(user_id=user.id).first()
    if lock:
        db.session.delete(lock)
        db.session.commit()
    session['site_unlocked_user_id'] = user.id
    session.pop('site_lock_attempts', None)
    session.pop('site_lock_blocked_until', None)
    flash('تم إلغاء قفل الموقع بعد التحقق من كلمة مرور حسابك.', 'success')
    return redirect(url_for('index'))


@app.route('/profile/site-lock', methods=['POST'])
@login_required
def configure_site_lock():
    user = current_user()
    if not user.check_password(request.form.get('account_password', '')):
        flash('كلمة مرور حسابك غير صحيحة، لم يتم تغيير إعداد القفل.', 'error')
        return redirect(url_for('profile'))
    lock = SiteLock.query.filter_by(user_id=user.id).first()
    action = request.form.get('action', 'enable')
    if action == 'disable':
        if lock:
            db.session.delete(lock)
            db.session.commit()
        session['site_unlocked_user_id'] = user.id
        flash('تم إيقاف قفل الموقع.', 'success')
        return redirect(url_for('profile'))
    password = request.form.get('site_password', '')
    confirm = request.form.get('confirm_site_password', '')
    if len(password) < 8:
        flash('اجعل كلمة مرور قفل الموقع 8 أحرف على الأقل.', 'error')
    elif password != confirm:
        flash('تأكيد كلمة المرور غير مطابق.', 'error')
    else:
        if not lock:
            lock = SiteLock(user_id=user.id, password_hash=generate_password_hash(password))
            db.session.add(lock)
        else:
            lock.password_hash = generate_password_hash(password)
        db.session.commit()
        session.pop('site_unlocked_user_id', None)
        flash('تم تفعيل قفل الموقع. أدخل كلمة مرور القفل للمتابعة.', 'success')
    return redirect(url_for('profile'))


@app.route('/profile', methods=['GET','POST'])
@login_required
def profile():
    user = current_user()
    if request.method == 'POST':
        user.full_name = request.form.get('full_name', user.full_name).strip()
        user.email = request.form.get('email', user.email).strip()
        user.phone = request.form.get('phone', user.phone).strip()
        db.session.commit(); flash('تم تحديث بياناتك.', 'success'); return redirect(url_for('profile'))
    return render_template('profile.html', user=user, site_lock_enabled=SiteLock.query.filter_by(user_id=user.id).first() is not None,
        merchant_application=MerchantApplication.query.filter_by(user_id=user.id).order_by(MerchantApplication.id.desc()).first(),
        api_application=ApiApplication.query.filter_by(user_id=user.id).order_by(ApiApplication.id.desc()).first(),
        api_key=decrypt_store_secret(ApiApplication.query.filter_by(user_id=user.id,status='approved').order_by(ApiApplication.id.desc()).first().encrypted_key) if ApiApplication.query.filter_by(user_id=user.id,status='approved').order_by(ApiApplication.id.desc()).first() else '')


@app.route('/profile/merchant-request',methods=['POST'])
@login_required
def merchant_request():
    if current_user().is_trusted_merchant:
        flash('حسابك تاجر بالفعل.','info')
    elif MerchantApplication.query.filter_by(user_id=current_user().id,status='pending').first():
        flash('لديك طلب تاجر قيد المراجعة.','warning')
    else:
        user = current_user()
        if float(user.balance_usd or 0) < 1.0:
            flash('يشترط شحن المحفظة بمبلغ دولار واحد على الأقل قبل طلب صفة تاجر.', 'error')
            return redirect(url_for('profile'))
        facebook_url = request.form.get('facebook_url', '').strip()
        instagram_url = request.form.get('instagram_url', '').strip()
        def valid_social_url(value):
            return not value or (value.startswith('https://') and len(value) <= 500)
        if not facebook_url or not instagram_url or not valid_social_url(facebook_url) or not valid_social_url(instagram_url):
            flash('أدخل رابط صفحتك على فيسبوك ورابط حسابك على إنستغرام بصيغة https:// صحيحة.', 'error')
            return redirect(url_for('profile'))
        req=MerchantApplication(user_id=user.id,details=request.form.get('details','').strip(),
                                facebook_url=facebook_url, instagram_url=instagram_url)
        db.session.add(req); db.session.commit()
        notify_admins('طلب حساب تاجر',f'{user.username} طلب حساب تاجر. فيسبوك: {facebook_url} | إنستغرام: {instagram_url}',url_for('admin_requests_extra'))
        db.session.commit(); flash('تم إرسال طلب التاجر للمراجعة.','success')
    return redirect(url_for('profile'))

@app.route('/profile/api-request',methods=['POST'])
@login_required
def api_request():
    pending=ApiApplication.query.filter_by(user_id=current_user().id,status='pending').first()
    if pending: flash('لديك طلب API قيد المراجعة.','warning')
    else:
        req=ApiApplication(user_id=current_user().id,website_url=request.form.get('website_url','').strip(),details=request.form.get('details','').strip())
        db.session.add(req); db.session.commit()
        notify_admins('طلب ربط API',f'{current_user().username} طلب API لموقعه: {req.website_url}',url_for('admin_requests_extra'))
        db.session.commit(); flash('تم إرسال طلب API.','success')
    return redirect(url_for('profile'))

@app.route('/admin/requests-extra')
@admin_required
def admin_requests_extra():
    return render_template('admin_requests_extra.html',merchant_requests=MerchantApplication.query.order_by(MerchantApplication.id.desc()).all(),api_requests=ApiApplication.query.order_by(ApiApplication.id.desc()).all())

@app.route('/admin/merchant-application/<int:req_id>',methods=['POST'])
@admin_required
def admin_merchant_application(req_id):
    req=MerchantApplication.query.get_or_404(req_id)
    action=request.form.get('action')
    if action=='approve':
        req.status='approved'; req.user.is_trusted_merchant=True
        
        try:
            req.weekly_bonus=max(0.0,float(request.form.get('weekly_bonus',req.weekly_bonus or 0) or 0))
        except (TypeError, ValueError):
            req.weekly_bonus=0.0
        req.last_bonus_at=datetime.utcnow()
        if req.weekly_bonus:
            req.user.balance_usd+=req.weekly_bonus
        send_user_notification(req.user_id,'تم قبول طلب التاجر','تم تفعيل حساب التاجر. الأسعار لا تزال حسب إعدادات المتجر.',url_for('profile'))
    else:
        req.status='rejected'
        send_user_notification(req.user_id,'تم رفض طلب التاجر','يمكنك مراجعة الدعم إذا أردت معرفة السبب.',url_for('support'))
    db.session.commit(); flash('تم تحديث طلب التاجر.','success')
    return redirect(url_for('admin_requests_extra'))

@app.route('/admin/merchant-bonus/<int:req_id>',methods=['POST'])
@admin_required
def admin_merchant_bonus(req_id):
    req=MerchantApplication.query.get_or_404(req_id)
    req.weekly_bonus=max(0,float(request.form.get('weekly_bonus','0')))
    db.session.commit()
    flash('تم تحديث مبلغ الدفعة الأسبوعية.','success')
    return redirect(url_for('admin_requests_extra'))

@app.route('/admin/api-application/<int:req_id>',methods=['POST'])
@admin_required
def admin_api_application(req_id):
    req=ApiApplication.query.get_or_404(req_id)
    if request.form.get('action')=='approve':
        req.status='approved'
        if not req.encrypted_key:
            token='nova_'+base64.urlsafe_b64encode(os.urandom(36)).decode().rstrip('=')
            req.encrypted_key=encrypt_store_secret(token)
        send_user_notification(req.user_id,'تمت الموافقة على طلب API','تم إنشاء مفتاح API. افتح ملفك الشخصي لعرض المفتاح.',url_for('profile'))
    else:
        req.status='rejected'
        send_user_notification(req.user_id,'تم رفض طلب API','تم رفض طلب الربط. يمكنك التواصل مع الدعم.',url_for('support'))
    db.session.commit(); flash('تم تحديث طلب API.','success')
    return redirect(url_for('admin_requests_extra'))

def api_user_from_request():
    token=request.headers.get('Authorization','').replace('Bearer ','',1).strip()
    if not token: token=request.headers.get('X-NOVA-API-Key','').strip()
    if not token: return None
    for application in ApiApplication.query.filter_by(status='approved').all():
        if application.encrypted_key and decrypt_store_secret(application.encrypted_key)==token:
            return application.user
    return None

@app.route('/api/docs')
@login_required
def api_docs():
    return render_template('api_docs.html')

@app.route('/api/v1/catalog',methods=['GET'])
def public_api_catalog():
    user=api_user_from_request()
    if not user: return jsonify(error='unauthorized'),401
    services=Service.query.filter_by(is_available=True).order_by(Service.sort_order.asc(),Service.id.asc()).all()
    return jsonify(items=[{'id':s.id,'name':s.name,'category':s.category.name if s.category else '',
        'price':s.price,'type':s.service_type,'minimum':s.min_quantity,'maximum':s.max_quantity,
        'description':s.description} for s in services])

@app.route('/api/v1/balance',methods=['GET'])
def public_api_balance():
    user=api_user_from_request()
    if not user: return jsonify(error='unauthorized'),401
    return jsonify(user_id=user.id,balance=round(user.balance_usd,2),currency='USD')


@app.route('/api/v1/order', methods=['POST'])
def public_api_create_order():
    """Create a NOVA order for an approved API customer and debit their NOVA wallet."""
    user = api_user_from_request()
    if not user:
        return jsonify(success=False, error='unauthorized', message='مفتاح API غير صحيح أو غير معتمد.'), 401
    data = request.get_json(silent=True) or request.form
    try:
        service_id = int(data.get('service_id', 0))
    except (TypeError, ValueError):
        return jsonify(success=False, error='invalid_service_id'), 400
    service = Service.query.get(service_id)
    if not service or not service.is_available:
        return jsonify(success=False, error='service_unavailable', message='الخدمة غير موجودة أو غير متاحة.'), 404
    link = str(data.get('link', '')).strip()
    if not link:
        return jsonify(success=False, error='missing_link', message='حقل link مطلوب.'), 400
    if service.service_type in ('manual', 'smm_fixed'):
        quantity = 1
        total = float((service.merchant_price if user.is_trusted_merchant and (service.merchant_price or 0) > 0 else service.price) or 0)
    else:
        try:
            quantity = int(data.get('quantity', service.min_quantity or 1))
        except (TypeError, ValueError):
            return jsonify(success=False, error='invalid_quantity'), 400
        minimum, maximum = int(service.min_quantity or 1), int(service.max_quantity or 10000)
        if quantity < minimum or quantity > maximum:
            return jsonify(success=False, error='quantity_out_of_range', minimum=minimum, maximum=maximum), 400
        rate = service.merchant_price if user.is_trusted_merchant and (service.merchant_price or 0) > 0 else (service.price_per_1000 or service.price or 0)
        total = float(rate) * quantity / 1000
    if total <= 0:
        return jsonify(success=False, error='invalid_service_price'), 409
    # Check balance before contacting a provider; debit only after provider acceptance.
    if float(user.balance_usd or 0) + 1e-9 < total:
        return jsonify(success=False, error='insufficient_balance', balance=round(float(user.balance_usd or 0), 2), required=round(total, 4), currency='USD'), 402
    provider_order_id = ''
    if service.service_type in ('smm', 'smm_fixed'):
        provider = SMMProvider.query.filter_by(id=service.api_provider_id, is_active=True).first() if service.api_provider_id else None
        if not provider or not service.api_service_id:
            return jsonify(success=False, error='provider_not_configured', message='الخدمة غير مربوطة بمزوّد بشكل صحيح.'), 409
        try:
            if provider.api_protocol == 'syria_market':
                result = syria_market_request(provider, 'POST', 'orders', {
                    'product_id': str(service.api_service_id), 'qty': int(quantity),
                    'params': {'playerId': link}
                }, timeout=35)
                body = result.get('data', result) if isinstance(result, dict) else {}
                remote_id = body.get('order_id', body.get('id', body.get('order'))) if isinstance(body, dict) else None
            else:
                payload = {'key': reveal_api_key(provider.api_key), 'action': 'add', 'service': str(service.api_service_id), 'link': link, 'quantity': str(quantity)}
                response = requests.post(provider.api_url, data=payload, headers={'Content-Type': 'application/x-www-form-urlencoded'}, timeout=30)
                response.raise_for_status(); result = response.json()
                if not isinstance(result, dict) or result.get('error'):
                    raise ValueError(str(result.get('error') if isinstance(result, dict) else 'Invalid provider response'))
                remote_id = result.get('order')
            if remote_id in (None, ''): raise ValueError('لم يرجع المزوّد رقم الطلب.')
            provider_order_id = str(remote_id)
        except Exception as exc:
            app.logger.warning('API customer provider order failed: %s', exc)
            return jsonify(success=False, error='provider_rejected', message='المزوّد لم يقبل الطلب. لم يتم خصم رصيدك.'), 502
    # Recheck balance immediately before debit to reduce concurrent overspending.
    db.session.refresh(user)
    if float(user.balance_usd or 0) + 1e-9 < total:
        return jsonify(success=False, error='insufficient_balance', message='الرصيد لم يعد كافياً. لم يتم تسجيل الطلب.'), 402
    user.balance_usd = float(user.balance_usd or 0) - total
    order = Order(user_id=user.id, service_id=service.id, service_name=service.name, link=link,
                  quantity=quantity, total_price=total,
                  status=('قيد التنفيذ' if service.service_type in ('smm', 'smm_fixed') else 'قيد المراجعة'),
                  provider_order_id=provider_order_id)
    db.session.add(order)
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        app.logger.exception('Could not save API order after provider response')
        return jsonify(success=False, error='order_save_failed', message='تعذر حفظ الطلب. تواصل مع الدعم قبل إعادة المحاولة.'), 500
    notify_admins(f'طلب API جديد #{order.id}', f'المستخدم {user.username} (#{user.id}) أرسل طلب API للخدمة {service.name} بقيمة ${format_money(total)}.', url_for('admin'))
    db.session.commit()
    return jsonify(success=True, order_id=order.id, service_id=service.id, service=service.name,
                   quantity=quantity, charge=round(total, 4), balance=round(float(user.balance_usd), 2),
                   currency='USD', status=order.status, provider_order_id=provider_order_id), 201


@app.route('/api/v1/orders', methods=['GET'])
def public_api_orders():
    user = api_user_from_request()
    if not user:
        return jsonify(success=False, error='unauthorized'), 401
    try:
        limit = min(max(int(request.args.get('limit', 50)), 1), 100)
    except (TypeError, ValueError):
        limit = 50
    orders = Order.query.filter_by(user_id=user.id).order_by(Order.id.desc()).limit(limit).all()
    active_provider_orders = (Order.query.join(Service, Order.service_id == Service.id)
        .filter(Order.user_id == user.id, Order.provider_order_id != '',
                Order.admin_status_override.is_(False), Service.service_type.in_(('smm', 'smm_fixed')),
                Order.status.notin_(('مكتمل', 'تم استرداد المبلغ', 'مرفوض')))
        .order_by(Order.id.desc()).limit(10).all())
    for order in active_provider_orders:
        refresh_api_order_status(order)
    return jsonify(success=True, orders=[{'order_id': o.id, 'service_id': o.service_id, 'service': o.service_name,
        'link': o.link, 'quantity': o.quantity, 'charge': round(o.total_price, 4), 'status': o.status,
        'created_at': o.created_at.isoformat() if o.created_at else None} for o in orders])

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

def refund_order_once(order, reason=''):
    """Credit the customer's site price exactly once, even if two status checks race."""
    if order.refunded:
        return False
    user = db.session.get(User, order.user_id)
    if not user:
        app.logger.error('Cannot refund order #%s: user #%s is missing', order.id, order.user_id)
        return False
    # Atomic conditional update prevents duplicate wallet credits from concurrent API/admin requests.
    claimed = db.session.execute(
        db.update(Order).where(Order.id == order.id, Order.refunded.is_(False)).values(refunded=True)
    )
    if claimed.rowcount != 1:
        db.session.refresh(order)
        return False
    amount = max(0.0, float(order.total_price or 0))
    user.balance_usd = round(float(user.balance_usd or 0) + amount, 4)
    order.refunded = True
    if reason:
        order.status_note = reason[:1000]
    return True


def refresh_api_order_status(order):
    """Refresh provider-backed orders using the same SMM API used to create them."""
    if order.admin_status_override or not order.provider_order_id or not order.service:
        return
    if order.status in ('مكتمل', 'تم استرداد المبلغ', 'مرفوض'):
        return
    if order.service.service_type not in ('smm', 'smm_fixed') or not order.service.api_provider_id:
        return
    provider = SMMProvider.query.filter_by(id=order.service.api_provider_id, is_active=True).first()
    if not provider:
        return
    try:
        if provider.api_protocol == 'syria_market':
            payload = syria_market_request(provider, 'GET', f'orders/{order.provider_order_id}', timeout=8)
            payload = payload.get('data', payload) if isinstance(payload, dict) else {}
        else:
            response = requests.post(provider.api_url,
                data={'key': reveal_api_key(provider.api_key), 'action': 'status', 'order': order.provider_order_id},
                headers={'Content-Type': 'application/x-www-form-urlencoded'}, timeout=5)
            response.raise_for_status(); payload = response.json()
        if not isinstance(payload, dict) or payload.get('error'): return
        raw = str(payload.get('status', payload.get('state', ''))).strip().lower().replace('-', '_')
        status_map = {
            'pending': 'قيد الانتظار', 'in progress': 'قيد التنفيذ', 'in_progress': 'قيد التنفيذ',
            'processing': 'قيد التنفيذ', 'running': 'قيد التنفيذ',
            'completed': 'مكتمل', 'complete': 'مكتمل', 'success': 'مكتمل',
            'partial': 'مكتمل جزئياً', 'canceled': 'فشل الطلب', 'cancelled': 'فشل الطلب',
            'failed': 'فشل الطلب', 'failure': 'فشل الطلب', 'refunded': 'تم استرداد المبلغ',
        }
        new_status = status_map.get(raw)
        if not new_status:
            return
        # Failed/cancelled/refunded provider orders return the site-charged price once only.
        refund_changed = False
        if raw in ('failed', 'failure', 'canceled', 'cancelled', 'refunded'):
            refund_changed = refund_order_once(order, f'استرداد تلقائي بسبب حالة مزوّد الخدمة: {raw}')
        if new_status == order.status:
            if refund_changed:
                send_user_notification(order.user_id, f'استرداد مبلغ الطلب #{order.id}',
                    f'أعاد مزوّد الخدمة حالة الطلب إلى {new_status}، وتم إرجاع ${format_money(order.total_price)} إلى رصيدك.',
                    url_for('my_orders'))
                db.session.commit()
            return
        previous = order.status
        order.status = new_status
        send_user_notification(
            order.user_id,
            f'تحديث حالة الطلب #{order.id}',
            f'تم تحديث حالة طلب {order.service_name} من «{previous}» إلى «{new_status}». ' + (f'تم إرجاع ${format_money(order.total_price)} إلى رصيدك.' if refund_changed else ''),
            url_for('my_orders'),
        )
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        app.logger.warning('Could not refresh provider status for local order #%s: %s', order.id, exc)


@app.route('/api/my_orders/status')
@login_required
def my_orders_status_api():
    orders = Order.query.filter_by(user_id=current_user().id).order_by(Order.id.desc()).limit(100).all()
    for order in orders:
        refresh_api_order_status(order)
    return jsonify({'orders': [{'id': order.id, 'status': order.status} for order in orders]})


@app.route('/my_orders')
@login_required
def my_orders():
    orders = Order.query.filter_by(user_id=current_user().id).order_by(Order.id.desc()).all()
    for order in orders:
        refresh_api_order_status(order)
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
        total = (service.merchant_price if user.is_trusted_merchant and (service.merchant_price or 0) > 0 else service.price)
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
        rate = service.merchant_price if user.is_trusted_merchant and (service.merchant_price or 0) > 0 else (service.price_per_1000 or service.price)
        total = rate * quantity / 1000
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
            if provider.api_protocol == 'syria_market':
                api_result = syria_market_request(provider, 'POST', 'orders', {
                    'product_id': str(service.api_service_id), 'qty': int(quantity),
                    'params': {'playerId': link}
                }, timeout=35)
                body = api_result.get('data', api_result) if isinstance(api_result, dict) else {}
                remote_id = body.get('order_id', body.get('id', body.get('order'))) if isinstance(body, dict) else None
            else:
                response = requests.post(provider.api_url, data={
                    'key': reveal_api_key(provider.api_key), 'action': 'add',
                    'service': str(service.api_service_id), 'link': link, 'quantity': str(quantity)},
                    headers={'Content-Type': 'application/x-www-form-urlencoded'}, timeout=30)
                response.raise_for_status(); api_result = response.json()
                if not isinstance(api_result, dict) or api_result.get('error'):
                    raise ValueError(str(api_result.get('error') or 'استجابة غير متوقعة من مزوّد الخدمة.'))
                remote_id = api_result.get('order')
            if remote_id in (None, ''): raise ValueError('لم يرجع المزوّد رقم الطلب.')
            provider_order_id = str(remote_id)
        except Exception as exc:
            app.logger.warning('SMM provider order failed: %s', exc)
            flash('الخدمة غير متاحة حاليا، حاول بعد 5 دقائق.', 'error')
            return redirect(url_for('category_services', category_id=service.category_id))
    user.balance_usd -= total
    order = Order(user_id=user.id, service_id=service.id, service_name=service.name, link=link, quantity=quantity, total_price=total, status=('قيد التنفيذ' if service.service_type in ('smm', 'smm_fixed') else 'قيد المراجعة'), provider_order_id=provider_order_id)
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
@app.route('/admin/social-links', methods=['POST'])
@admin_required
def admin_social_links():
    for platform in ('whatsapp', 'facebook', 'instagram'):
        value = request.form.get(platform, '').strip()
        username = request.form.get(platform + '_username', '').strip().lstrip('@')[:120]
        if value and (not value.startswith('https://') or len(value) > 500):
            flash('يجب أن يبدأ كل رابط بـ https:// وألا يتجاوز 500 حرف.', 'error')
            return redirect(url_for('admin'))
        item = SocialLink.query.filter_by(platform=platform).first()
        if not item:
            item = SocialLink(platform=platform)
            db.session.add(item)
        item.url = value
        item.username = username
    db.session.commit()
    flash('تم حفظ روابط التواصل الاجتماعي.', 'success')
    return redirect(url_for('admin'))

@app.route('/about')
def about():
    links = SocialLink.query.all()
    return render_template('about.html', social_links={x.platform:x.url for x in links}, social_usernames={x.platform:x.username for x in links})
@app.route('/ai_bot')
@login_required
def ai_bot(): return render_template('ai_bot.html', user_name=current_user().full_name or current_user().username)

@app.route('/api/ai_chat', methods=['POST'])
def ai_chat():
    """Knowledge-based NOVA assistant. Works without any external AI/API key."""
    if not session.get('user_id') or not db.session.get(User, session.get('user_id')):
        return jsonify(reply='انتهت جلسة تسجيل الدخول. سجّل الدخول مجدداً.'), 401
    user = db.session.get(User, session.get('user_id'))
    data = request.get_json(silent=True) or {}
    message = str(data.get('message', '')).strip()[:1000]
    if not message:
        return jsonify(reply='اكتب سؤالك أولاً.'), 400

    # Normalize common Arabic spelling variants to improve keyword matching.
    m = message.lower().replace('أ', 'ا').replace('إ', 'ا').replace('آ', 'ا').replace('ى', 'ي')
    contacts = (
        'للتواصل عبر واتساب:\n'
        '• مؤسس ومبرمج الموقع: 963952169815\n'
        '• دعم الشحن والإبلاغ عن مشكلة: 963984727823\n'
        '• الطلبات وتسريع الطلب أو الإبلاغ عن خطأ: 963951287267\n'
        'احفظ الرقم المناسب وافتح محادثة واتساب معه.'
    )

    if any(x in m for x in ['تواصل', 'اتواصل', 'واتساب', 'واتس', 'رقم', 'ارقام', 'المؤسس', 'مبرمج', 'الدعم', 'دعم', 'شكوى', 'مشكلة', 'خطا', 'ابلاغ']):
        if any(x in m for x in ['مؤسس', 'مبرمج', 'صاحب', 'ادارة', 'الاداره']):
            reply = 'للتواصل مع مؤسس ومبرمج الموقع عبر واتساب: 963952169815'
        elif any(x in m for x in ['شحن', 'ايداع', 'دفع', 'تحويل']):
            reply = 'لدعم الشحن والإبلاغ عن مشكلة في الشحن عبر واتساب: 963984727823'
        elif any(x in m for x in ['طلب', 'تسريع', 'تاخير', 'متاخر']):
            reply = 'للطلبات أو تسريع طلب أو الإبلاغ عن خطأ عبر واتساب: 963951287267'
        else:
            reply = contacts
    elif any(x in m for x in ['رصيدي', 'كم رصيد', 'رصيد حسابي', 'المحفظة', 'محفظتي']):
        reply = f'رصيدك الحالي هو ${format_money(user.balance_usd)}. لشحن المحفظة افتح قسم «شحن المحفظة»، اختر طريقة الدفع، وأرسل إثبات التحويل وانتظر مراجعة الإدارة.'
    elif any(x in m for x in ['طلباتي', 'حالة الطلب', 'وين طلبي', 'طلبي', 'الطلبات']):
        orders = Order.query.filter_by(user_id=user.id).order_by(Order.id.desc()).limit(7).all()
        if orders:
            lines = [f'#{o.id} · {o.service_name} · الحالة: {o.status}' for o in orders]
            reply = 'هذه أحدث طلباتك المسجلة:\n' + '\n'.join(lines) + '\nللتفاصيل افتح صفحة «طلباتي». إذا أردت تسريع طلب تواصل مع 963951287267.'
        else:
            reply = 'لا توجد طلبات مسجلة في حسابك حالياً. افتح الأقسام، اختر الخدمة، ثم أرسل طلبك بعد التأكد من الرابط والكمية.'
    elif any(x in m for x in ['كيف اطلب', 'طريقة الطلب', 'اطلب خدمة', 'شراء', 'اشتري', 'طلب خدمة']):
        reply = 'لطلب خدمة: 1) افتح القسم المناسب. 2) اختر الخدمة أو المنتج. 3) اقرأ الوصف والحدود والسعر. 4) أدخل الرابط أو المعرّف والكمية المطلوبة. 5) راجع البيانات ثم أكد الطلب. تابع التنفيذ من صفحة «طلباتي». لا ترسل كلمة مرور حسابك لأي شخص.'
    elif any(x in m for x in ['شحن', 'دفع', 'تحويل', 'ايداع', 'كاش', 'اشحن']):
        methods = PaymentMethod.query.order_by(PaymentMethod.id.desc()).all()
        names = '، '.join(x.name for x in methods[:8]) if methods else 'راجع طرق الدفع الظاهرة في صفحة الشحن'
        reply = f'لشحن المحفظة افتح «شحن المحفظة»، اختر طريقة الدفع المتاحة ({names})، أدخل المبلغ وارفق إثبات التحويل. لا تعتبر المحفظة مشحونة حتى يظهر الرصيد بعد مراجعة الطلب. لمشاكل الشحن واتساب: 963984727823.'
    elif any(x in m for x in ['سعر', 'اسعار', 'خدمات', 'منتجات', 'متابع', 'لايك', 'مشاهد', 'انستغرام', 'انستا', 'تيك توك', 'يوتيوب', 'تلغرام', 'تليجرام', 'فيس', 'العاب', 'ببجي', 'فري فاير']):
        available = Service.query.filter_by(is_available=True).order_by(Service.sort_order.asc(), Service.id.desc()).limit(12).all()
        if available:
            lines = [f'• {x.name}: ${format_money(x.price)}' for x in available]
            reply = 'هذه عينة من الخدمات المتاحة حالياً وأسعارها بالدولار:\n' + '\n'.join(lines) + '\nقد تختلف التفاصيل والحدود حسب المنتج؛ افتح الخدمة لقراءة وصفها والسعر النهائي.'
        else:
            reply = 'لا تظهر خدمات متاحة حالياً. تحقق من الأقسام لاحقاً أو تواصل مع الدعم.'
    elif any(x in m for x in ['الغاء', 'الغاء الطلب', 'استرجاع', 'استرداد', 'تاخر', 'متاخر', 'ما وصل', 'لم يصل', 'فشل']):
        reply = 'إذا تأخر طلبك أو لم يصل، افتح «طلباتي» وتأكد من حالته ورقم الطلب. لا ترسل طلباً مكرراً قبل التحقق. للمتابعة أو طلب التسريع عبر واتساب: 963951287267.'
    elif any(x in m for x in ['كلمة المرور', 'كلمه المرور', 'باسورد', 'نسيت كلمة', 'نسيت كلمه', 'تغيير كلمة']):
        reply = 'يمكنك إدارة بيانات الدخول من صفحة «حسابي» ثم خيار تغيير كلمة المرور. إذا فقدت إمكانية الدخول، استخدم خيار استعادة الحساب إن كان متاحاً أو تواصل مع مؤسس الموقع: 963952169815. لا تشارك كلمة مرورك مع أحد.'
    elif any(x in m for x in ['حساب انستا', 'حساب انست', 'حسابات انستا', 'حسابات انست', 'شراء حساب', 'متجر الحسابات', 'حسابات رقمية']):
        reply = 'تجد الحسابات الرقمية المتاحة في «المتجر» من الشريط السفلي. افتح الحساب لقراءة الوصف والسعر، ثم اضغط شراء الآن. بعد إتمام الشراء ستظهر بيانات الدخول التي أضافها المتجر، مثل البريد وكلمة مروره واسم المستخدم وكلمة مروره إن كانت متوفرة. لا تشارك بيانات الحساب مع أي شخص.'
    elif any(x in m for x in ['حساب', 'تسجيل', 'انشاء حساب', 'انشاء', 'دخول', 'تسجيل الدخول']):
        reply = 'أنشئ حساباً من صفحة التسجيل باستخدام بيانات صحيحة، ثم سجّل الدخول لمتابعة الطلبات والمحفظة والإشعارات. من صفحة «حسابي» يمكنك تعديل بياناتك وتغيير كلمة المرور وتسجيل الخروج. حافظ على كلمة المرور ولا تشاركها مع أي شخص.'
    elif any(x in m for x in ['api', 'مفتاح', 'تاجر', 'طلب تاجر']):
        reply = 'طلبات التاجر وAPI تخضع لمراجعة الإدارة. افتح صفحة «حسابي» للوصول إلى أزرار طلب التاجر وطلب API، ثم أرسل البيانات المطلوبة وانتظر الموافقة.'
    elif any(x in m for x in ['مرحبا', 'السلام', 'اهلا', 'هاي', 'هلا', 'صباح', 'مساء']):
        reply = f'أهلاً {user.full_name or user.username} 👋 أنا مساعد NOVA STORE. بقدر أساعدك بالطلبات والشحن والرصيد والخدمات والحساب والتواصل. اكتب سؤالك بشكل مباشر.'
    elif any(x in m for x in ['من نحن', 'عن الموقع', 'نوفا', 'nova store', 'ما هو الموقع']):
        reply = 'NOVA STORE متجر للخدمات الرقمية وشحن الألعاب والحسابات والخدمات المرتبطة بمنصات التواصل. هدفنا تسهيل الطلب ومتابعته وتوفير قنوات واضحة للدعم. تفاصيل التواصل موجودة في صفحة «من نحن».'
    elif any(x in m for x in ['ضمان', 'النقصان', 'استرجاع', 'استرداد', 'سياسة', 'خصوصية', 'امان', 'امن', 'موثوق']):
        reply = 'تفاصيل الضمان والاسترجاع تختلف حسب الخدمة أو المنتج، لذلك راجع وصف الخدمة قبل تأكيد الطلب. لا تشارك كلمة مرور حسابك الشخصي مع أي جهة. إذا واجهت مشكلة في طلب قائم، تواصل مع دعم الطلبات عبر واتساب: 963951287267.'
    elif any(x in m for x in ['كيف استخدم', 'طريقة الاستخدام', 'كيف اشتغل', 'كيف يعمل', 'مساعدة', 'ساعدني', 'شو فيك', 'ماذا تستطيع']):
        reply = 'أنا مساعد NOVA STORE بدون اتصال بخدمة AI خارجية. أقدر أساعدك بمعلومات المتجر، الخدمات والأسعار المتاحة، خطوات الطلب، رصيدك، الشحن، طلباتك، متجر الحسابات، الحساب وطرق التواصل. اكتب سؤالك أو اختر القسم الذي تحتاجه.'
    elif any(x in m for x in ['شكرا', 'يسلمو', 'مشكور', 'يعطيك العافية']):
        reply = 'العفو، بالخدمة دائماً 💙 إذا احتجت مساعدة بالطلب أو الشحن أو الحساب اكتبلي مباشرة.'
    else:
        reply = ('أنا مساعد NOVA STORE وأعمل دون API خارجي، لذلك أجيب عن المعلومات المرتبطة بالمتجر وما أقدر أؤكد معلومات عامة لا أملك مصدراً لها. جرّب تسألني عن: طريقة الطلب، الخدمات والأسعار، رصيدك، الشحن، حالة طلباتك، حسابات إنستغرام، تغيير كلمة المرور أو أرقام التواصل.\n\n' + contacts)
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
                send_user_notification(ticket.user_id, 'تم الرد من الدعم', 'قام فريق NOVA STORE بالرد على محادثتك.', url_for('support_ticket', ticket_id=ticket.id))
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
            send_user_notification(ticket.user_id, 'تم الرد من الدعم', 'قام فريق NOVA STORE بالرد على محادثتك.', url_for('support_ticket', ticket_id=ticket.id))
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
    js = "self.addEventListener('push', function(event) { let data = {}; try { data = event.data.json(); } catch (e) { data = {title: 'NOVA STORE', body: event.data ? event.data.text() : 'لديك إشعار جديد'}; } event.waitUntil(self.registration.showNotification(data.title || 'NOVA STORE', {body: data.body || '', data: {url: data.url || '/notifications'}})); }); self.addEventListener('notificationclick', function(event) { event.notification.close(); const url = event.notification.data && event.notification.data.url ? event.notification.data.url : '/notifications'; event.waitUntil(clients.matchAll({type: 'window', includeUncontrolled: true}).then(function(list) { for (const client of list) { if ('focus' in client) { client.navigate(url); return client.focus(); } } return clients.openWindow(url); })); });"
    return Response(js, mimetype='application/javascript', headers={'Service-Worker-Allowed': '/'})


@app.route('/admin/accounts')
@admin_required
def admin_accounts():
    account_lookup_id = request.args.get('account_id', type=int)
    account_lookup = db.session.get(User, account_lookup_id) if account_lookup_id else None
    return render_template('admin_accounts.html', account_lookup=account_lookup, account_lookup_id=account_lookup_id, social_links={x.platform:x.url for x in SocialLink.query.all()})


@app.route('/admin')
@admin_required
def admin():
    account_lookup_id = request.args.get('account_id', type=int)
    account_lookup = db.session.get(User, account_lookup_id) if account_lookup_id else None
    all_categories = Category.query.all()
    ordered_categories = sorted(all_categories, key=lambda item: (0 if item.parent_id is None else item.parent_id, item.sort_order or 0, item.id))
    links = SocialLink.query.all()
    return render_template('admin.html', employees=User.query.filter_by(role='employee').order_by(User.id.desc()).all(), orders=Order.query.order_by(Order.id.desc()).all(), verification_requests=VerificationRequest.query.filter_by(status='pending').all(), categories=all_categories, ordered_categories=ordered_categories, services=Service.query.order_by(Service.sort_order.asc(), Service.id.desc()).all(), deposits=DepositRequest.query.filter_by(status='قيد المراجعة').order_by(DepositRequest.id.desc()).all(), payment_methods=PaymentMethod.query.order_by(PaymentMethod.id.desc()).all(), agents=Agent.query.order_by(Agent.id.desc()).all(), sms_number_providers=SMSNumberProvider.query.order_by(SMSNumberProvider.id.desc()).all(), smm_providers=SMMProvider.query.order_by(SMMProvider.id.desc()).all(), smm_catalog_services=SMMCatalogService.query.order_by(SMMCatalogService.name.asc()).all(), support_count=SupportTicket.query.filter(SupportTicket.status != 'مغلقة').count(), account_lookup=account_lookup, account_lookup_id=account_lookup_id, social_links={x.platform:x.url for x in links}, social_usernames={x.platform:x.username for x in links})


@app.route('/admin/orders/status')
@admin_required
def admin_orders_status_api():
    # Cycle through every active provider order in small batches, so old pending orders are not starved.
    after_id = max(0, request.args.get('after_id', default=0, type=int) or 0)
    active_query = (Order.query.join(Service, Order.service_id == Service.id)
        .filter(Order.provider_order_id != '', Order.admin_status_override.is_(False),
                Service.service_type.in_(('smm', 'smm_fixed')),
                Order.status.notin_(('مكتمل', 'تم استرداد المبلغ', 'مرفوض'))))
    active_api_orders = active_query.filter(Order.id > after_id).order_by(Order.id.asc()).limit(10).all()
    next_cursor = active_api_orders[-1].id if len(active_api_orders) == 10 else 0
    if not active_api_orders and after_id:
        active_api_orders = active_query.order_by(Order.id.asc()).limit(10).all()
        next_cursor = active_api_orders[-1].id if len(active_api_orders) == 10 else 0
    for order in active_api_orders:
        refresh_api_order_status(order)
    return jsonify(next_cursor=next_cursor, orders=[{'id': order.id, 'status': order.status, 'refunded': bool(order.refunded),
                            'status_note': order.status_note or '', 'admin_status_override': bool(order.admin_status_override)}
                           for order in Order.query.order_by(Order.id.desc()).all()])


@app.route('/employee')
@login_required
@employee_required
def employee_dashboard():
    recent_orders = Order.query.order_by(Order.id.desc()).all()
    return render_template('employee_dashboard.html',
        tickets=SupportTicket.query.order_by(SupportTicket.updated_at.desc()).all(),
        merchant_requests=MerchantApplication.query.filter_by(status='pending').order_by(MerchantApplication.id.desc()).all(),
        verification_requests=VerificationRequest.query.filter_by(status='pending').order_by(VerificationRequest.id.desc()).all(),
        orders=recent_orders)

@app.route('/employee/support/<int:ticket_id>', methods=['POST'])
@login_required
@employee_required
def employee_reply(ticket_id):
    ticket = SupportTicket.query.get_or_404(ticket_id)
    content = request.form.get('message','').strip()
    if not content or len(content) > 5000:
        flash('اكتب رداً صحيحاً لا يتجاوز 5000 حرفاً.', 'error')
    else:
        db.session.add(SupportMessage(ticket_id=ticket.id, sender_id=current_user().id, sender_role='admin', content=content))
        ticket.status='تم الرد'; ticket.updated_at=datetime.utcnow()
        send_user_notification(ticket.user_id, 'تم الرد من الدعم', 'قام فريق NOVA STORE بالرد على محادثتك.', url_for('support_ticket', ticket_id=ticket.id))
        db.session.commit(); flash('تم إرسال الرد للعميل.', 'success')
    return redirect(url_for('employee_dashboard'))

@app.route('/employee/merchant/<int:req_id>', methods=['POST'])
@login_required
@employee_required
def employee_merchant(req_id):
    req=MerchantApplication.query.get_or_404(req_id)
    if req.status != 'pending':
        flash('تمت معالجة هذا الطلب مسبقاً.', 'warning')
        return redirect(url_for('employee_dashboard'))
    action=request.form.get('action')
    if action == 'approve':
        req.status='approved'; req.user.is_trusted_merchant=True
        req.weekly_bonus=0.0; req.last_bonus_at=datetime.utcnow()
        send_user_notification(req.user_id,'تم قبول طلب التاجر','تم توثيق حسابك كتاجر في NOVA STORE.',url_for('profile'))
    elif action == 'reject':
        req.status='rejected'
        send_user_notification(req.user_id,'تم رفض طلب التاجر','يمكنك التواصل مع الدعم لمعرفة التفاصيل.',url_for('support'))
    else:
        flash('إجراء غير صالح.', 'error'); return redirect(url_for('employee_dashboard'))
    db.session.commit(); flash('تم تحديث طلب التاجر.', 'success')
    return redirect(url_for('employee_dashboard'))

@app.route('/employee/verification/<int:req_id>', methods=['POST'])
@login_required
@employee_required
def employee_verification(req_id):
    req = VerificationRequest.query.get_or_404(req_id)
    if req.status != 'pending':
        flash('تمت معالجة طلب التوثيق مسبقاً.', 'warning')
        return redirect(url_for('employee_dashboard'))
    action = request.form.get('action')
    if action == 'approve':
        req.user.is_verified = True
        req.status = 'approved'
        req.rejection_reason = ''
        send_user_notification(req.user_id, 'تم توثيق حسابك', 'تمت الموافقة على طلب التوثيق.', url_for('profile'))
    elif action == 'reject':
        reason = request.form.get('reject_reason', '').strip()[:500]
        if not reason:
            flash('اكتب سبب الرفض.', 'error')
            return redirect(url_for('employee_dashboard'))
        req.status = 'rejected'
        req.rejection_reason = reason
        send_user_notification(req.user_id, 'تعذر توثيق حسابك', reason, url_for('verification'))
    else:
        flash('إجراء غير صالح.', 'error')
        return redirect(url_for('employee_dashboard'))
    db.session.commit()
    flash('تم تحديث طلب التوثيق.', 'success')
    return redirect(url_for('employee_dashboard'))

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
        if user.role == 'admin':
            flash('لا يمكن تغيير نوع حساب المدير.', 'error')
        elif user.is_trusted_merchant or user.role == 'merchant':
            user.role = 'user'
            user.is_trusted_merchant = False
            db.session.commit()
            flash(f'تم إرجاع الحساب #{user.id} إلى حساب عام وإلغاء السعر الخاص بالتاجر.', 'success')
        else:
            flash('هذا الحساب عام بالفعل.', 'info')
    elif action == 'remove_employee':
        if user.role != 'employee':
            flash('هذا الحساب ليس موظفاً حالياً.', 'info')
        else:
            user.role = 'user'
            db.session.commit()
            flash(f'تم إلغاء صلاحيات الموظف للحساب #{user.id} وإعادته إلى حساب عادي.', 'success')
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

@app.route('/admin/order/<int:order_id>/status', methods=['POST'])
@admin_required
def update_order_status(order_id):
    order = Order.query.get_or_404(order_id)
    action = (request.form.get('action') or '').strip().lower()
    reason = (request.form.get('reason') or '').strip()
    previous = order.status
    if action == 'complete':
        order.status = 'مكتمل'
        order.admin_status_override = True
        order.status_note = reason[:1000] or 'تم تحديد الطلب كمكتمل من لوحة الإدارة.'
        message = 'تم تحديد الطلب كمكتمل.'
    elif action == 'reject':
        if not reason:
            flash('اكتب سبب رفض الطلب ليظهر للمستخدم.', 'error')
            return redirect(url_for('admin'))
        order.status = 'مرفوض'
        order.admin_status_override = True
        refund_order_once(order, 'سبب الرفض: ' + reason)
        order.status_note = 'سبب الرفض: ' + reason[:900] + (' — تم استرداد المبلغ.' if order.refunded else '')
        message = 'تم رفض الطلب وإرجاع المبلغ إذا لم يكن مسترداً سابقاً.'
    elif action == 'refund':
        was_refunded = order.refunded
        order.status = 'تم استرداد المبلغ'
        order.admin_status_override = True
        order.status_note = reason[:1000] or 'تم استرداد المبلغ من لوحة الإدارة.'
        refund_order_once(order, order.status_note)
        message = 'تم استرداد المبلغ وإضافته إلى رصيد المستخدم.' if not was_refunded else 'المبلغ مسترد سابقاً؛ لم تتم إضافته مرة ثانية.'
    else:
        flash('الإجراء المحدد غير صالح.', 'error')
        return redirect(url_for('admin'))
    send_user_notification(order.user_id, f'تحديث حالة الطلب #{order.id}',
        f'تم تحديث حالة طلب {order.service_name} من «{previous}» إلى «{order.status}». ' + (('التفاصيل: ' + reason[:300]) if reason else ''),
        url_for('my_orders'))
    db.session.commit()
    flash(message, 'success')
    return redirect(url_for('admin'))


@app.route('/admin/complete_order/<int:order_id>', methods=['POST'])
@admin_required
def complete_order(order_id):
    # Backward-compatible route for older admin pages/bookmarks.
    order = Order.query.get_or_404(order_id)
    order.status = 'مكتمل'
    order.admin_status_override = True
    order.status_note = 'تم تحديد الطلب كمكتمل من لوحة الإدارة.'
    send_user_notification(order.user_id, f'تحديث حالة الطلب #{order.id}', f'تم تحديد طلب {order.service_name} كمكتمل.', url_for('my_orders'))
    db.session.commit()
    flash('تم تحديث حالة الطلب.', 'success')
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

@app.route('/admin/add_employee', methods=['POST'])
@admin_required
def add_employee():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    full_name = request.form.get('full_name', '').strip()[:120]
    if not username or len(username) > 80 or len(password) < 8:
        flash('أدخل اسم مستخدم صحيحاً وكلمة مرور من 8 أحرف على الأقل.', 'error')
    elif User.query.filter_by(username=username).first():
        flash('اسم المستخدم مستخدم مسبقاً.', 'error')
    else:
        staff = User(username=username, full_name=full_name or 'موظف NOVA STORE', role='employee', balance_usd=0)
        staff.set_password(password)
        db.session.add(staff)
        db.session.commit()
        flash('تم إنشاء حساب الموظف. صلاحياته محصورة بالدعم والطلبات وطلبات التاجر والتوثيق.', 'success')
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

def syria_market_request(provider, method, path, payload=None, timeout=25):
    """Call Syria Market REST API from the server; never expose credentials to the browser.

    HMAC signing is intentionally not added here: the merchant has disabled the
    mandatory HMAC switch in Syria Market. Bearer authentication remains required.
    """
    base = (provider.api_url or 'https://api.syrimarket.com/client/api/v1').rstrip('/')
    token = (reveal_api_key(provider.api_key) or '').strip()
    if not token:
        raise ValueError('مفتاح REST API فارغ. أدخل مفتاح API الخاص بالمتجر.')
    if token.startswith('spk_'):
        raise ValueError('هذا مفتاح PerfectPanel يبدأ بـ spk_ وهو مخصص للرشق فقط. استخدم مفتاح REST API الذي يبدأ عادةً بـ sst_.')
    if not base.startswith('https://api.syrimarket.com/client/api/v1'):
        raise ValueError('رابط API غير صحيح. استخدم https://api.syrimarket.com/client/api/v1')
    headers = {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/json',
        'Content-Type': 'application/json',
    }
    if method.upper() == 'POST':
        headers['Idempotency-Key'] = str(uuid.uuid4())
    response = requests.request(
        method.upper(), base + '/' + path.lstrip('/'), headers=headers,
        json=payload if method.upper() != 'GET' else None, timeout=timeout
    )
    if not response.ok:
        # Keep the provider's diagnostic message visible to the administrator;
        # this makes 401/403/422 issues actionable instead of showing only status.
        detail = (response.text or '')[:700]
        raise ValueError(f'Syria Market HTTP {response.status_code}: {detail or response.reason}')
    try:
        data = response.json()
    except ValueError:
        raise ValueError('استجابة سوريا ماركت ليست JSON صالحاً.')
    if isinstance(data, dict) and (data.get('success') is False or data.get('error')):
        raise ValueError(str(data.get('message') or data.get('error') or data))
    return data


def unwrap_api_list(data, *keys):
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in keys:
            value = data.get(key)
            if isinstance(value, list):
                return value
            if isinstance(value, dict):
                nested = unwrap_api_list(value, *keys)
                if nested:
                    return nested
        for key in ('data', 'result', 'catalog'):
            value = data.get(key)
            if isinstance(value, dict):
                found = unwrap_api_list(value, *keys)
                if found:
                    return found
    return []


@app.route('/admin/add_smm_provider', methods=['POST'])
@admin_required
def add_smm_provider():
    name = request.form.get('provider_name', '').strip()
    protocol = request.form.get('api_protocol', 'legacy').strip()
    api_url = request.form.get('api_url', '').strip()
    if protocol == 'syria_market' and not api_url:
        api_url = 'https://api.syrimarket.com/client/api/v1'
    test_key = request.form.get('test_api_key', '').strip()
    live_key = request.form.get('live_api_key', '').strip() or request.form.get('api_key', '').strip()
    if not name or not api_url.startswith(('https://', 'http://')) or not live_key:
        flash('أدخل اسم المزوّد ورابط API والمفتاح الفعلي.', 'error')
    else:
        db.session.add(SMMProvider(name=name, api_url=api_url, api_key=protect_api_key(live_key),
            test_api_key=protect_api_key(test_key), live_api_key=protect_api_key(live_key), api_protocol=protocol))
        db.session.commit()
        flash('تم حفظ إعدادات سوريا ماركت. المفتاح محفوظ بشكل مشفّر.', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/test_smm_provider/<int:provider_id>', methods=['POST'])
@admin_required
def test_smm_provider(provider_id):
    provider = SMMProvider.query.get_or_404(provider_id)
    try:
        if provider.api_protocol == 'syria_market':
            data = syria_market_request(provider, 'GET', 'profile')
            profile = data.get('data', data) if isinstance(data, dict) else {}
            balance = profile.get('balance', profile.get('wallet_balance', 'متصل')) if isinstance(profile, dict) else 'متصل'
            currency = profile.get('currency', 'USD') if isinstance(profile, dict) else ''
        else:
            response = requests.post(provider.api_url, data={'key': reveal_api_key(provider.test_api_key or provider.api_key), 'action': 'balance'}, timeout=15)
            response.raise_for_status(); data = response.json()
            if data.get('error'): raise ValueError(str(data['error']))
            balance, currency = data.get('balance', 'غير متاح'), data.get('currency', '')
        flash(f'نجح اختبار API للمزوّد {provider.name}. الرصيد: {balance} {currency}', 'success')
    except Exception as exc:
        flash(f'فشل اختبار API للمزوّد {provider.name}: {str(exc)[:220]}', 'error')
    return redirect(url_for('admin'))

@app.route('/admin/fetch_smm_services/<int:provider_id>', methods=['POST'])
@admin_required
def fetch_smm_services(provider_id):
    provider = SMMProvider.query.get_or_404(provider_id)
    try:
        if provider.api_protocol == 'syria_market':
            # Syria Market documents the v1 products endpoint; tree is a fallback for catalog layouts.
            data = syria_market_request(provider, 'GET', 'catalog/products')
            items = unwrap_api_list(data, 'products', 'items', 'services')
            if not items:
                tree = syria_market_request(provider, 'GET', 'catalog/tree')
                def walk(nodes):
                    out=[]
                    for node in nodes if isinstance(nodes, list) else []:
                        if not isinstance(node, dict): continue
                        out.extend(node.get('products') or [])
                        out.extend(walk(node.get('categories') or node.get('children') or []))
                    return out
                roots = unwrap_api_list(tree, 'categories', 'tree', 'items')
                items = walk(roots)
        else:
            response = requests.post(provider.api_url, data={'key': reveal_api_key(provider.api_key), 'action': 'services'}, timeout=20)
            response.raise_for_status(); data = response.json()
            if isinstance(data, dict) and data.get('error'): raise ValueError(str(data['error']))
            items = data if isinstance(data, list) else []
        if not items:
            raise ValueError('لم يعِد API أي منتجات. تحقق من صلاحية المفتاح ومسار الكتالوج.')
        imported_count = 0
        SMMCatalogService.query.filter_by(provider_id=provider.id).delete(synchronize_session=False)
        for item in items:
            if not isinstance(item, dict): continue
            code = item.get('product_id', item.get('productId', item.get('id', item.get('service'))))
            if code is None: continue
            pricing = item.get('pricing') if isinstance(item.get('pricing'), dict) else {}
            rate = item.get('price', item.get('rate', pricing.get('price', pricing.get('base', 0)))) or 0
            try: rate = float(rate)
            except (TypeError, ValueError): rate = 0
            minimum = item.get('min_quantity', item.get('min', 1)) or 1
            maximum = item.get('max_quantity', item.get('max', 10000)) or 10000
            try: minimum=max(1,int(minimum)); maximum=max(minimum,int(maximum))
            except (TypeError,ValueError): minimum,maximum=1,10000
            db.session.add(SMMCatalogService(provider_id=provider.id, service_code=str(code),
                name=str(item.get('name') or item.get('title') or code),
                category_name=str(item.get('category_name') or item.get('category') or ''),
                rate=rate, min_quantity=minimum, max_quantity=maximum))
            imported_count += 1
        if not imported_count: raise ValueError('لم تتضمن الاستجابة معرّفات منتجات صالحة.')
        db.session.commit()
        flash(f'تم استيراد {imported_count} منتج من {provider.name}. اربط المنتجات المطلوبة من نموذج إضافة الخدمة.', 'success')
    except Exception as exc:
        db.session.rollback(); flash(f'تعذر جلب خدمات API: {str(exc)[:220]}', 'error')
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
            last_order = db.session.query(db.func.max(Category.sort_order)).filter_by(parent_id=None).scalar()
            db.session.add(Category(name=name, parent_id=None, image_url=image_url, sort_order=(last_order or 0) + 1))
            db.session.commit()
            flash('تم إنشاء القسم الرئيسي مع صورته بنجاح.', 'success')
        except ValueError as exc:
            flash(str(exc), 'error')
    return redirect(url_for('admin'))

@app.route('/admin/update_category/<int:category_id>', methods=['POST'])
@admin_required
def update_category(category_id):
    category = Category.query.get_or_404(category_id)
    name = request.form.get('category_name', '').strip()
    if not name:
        flash('اسم القسم مطلوب.', 'error')
        return redirect(url_for('admin'))
    duplicate = Category.query.filter(Category.id != category.id, Category.name == name, Category.parent_id == category.parent_id).first()
    if duplicate:
        flash('يوجد قسم آخر بالاسم نفسه ضمن المستوى نفسه.', 'error')
        return redirect(url_for('admin'))
    try:
        uploaded = save_uploaded_image('category_image_file')
        image_url = uploaded or request.form.get('category_image_url', '').strip()
        category.name = name
        if image_url:
            category.image_url = image_url
        elif request.form.get('remove_category_image') == '1':
            category.image_url = ''
        category.sort_order = max(0, min(request.form.get('sort_order', type=int) or 0, 1000000))
        db.session.commit()
        flash('تم حفظ اسم القسم وصورته وترتيبه.', 'success')
    except ValueError as exc:
        db.session.rollback()
        flash(str(exc), 'error')
    return redirect(url_for('admin'))


@app.route('/admin/move_category/<int:category_id>/<direction>', methods=['POST'])
@admin_required
def move_category(category_id, direction):
    """Move a category up/down within its own parent group."""
    if direction not in ('up', 'down'):
        flash('اتجاه الترتيب غير صحيح.', 'error')
        return redirect(url_for('admin'))
    category = Category.query.get_or_404(category_id)
    siblings = Category.query.filter_by(parent_id=category.parent_id).order_by(Category.sort_order.asc(), Category.id.asc()).all()
    current_index = next((i for i, item in enumerate(siblings) if item.id == category.id), None)
    if current_index is None:
        flash('تعذر العثور على القسم ضمن قائمة الترتيب.', 'error')
        return redirect(url_for('admin'))
    target_index = current_index - 1 if direction == 'up' else current_index + 1
    if target_index < 0 or target_index >= len(siblings):
        flash('القسم موجود بالفعل عند هذا الطرف من القائمة.', 'info')
        return redirect(url_for('admin'))
    siblings[current_index], siblings[target_index] = siblings[target_index], siblings[current_index]
    try:
        # Re-number all siblings sequentially to keep ordering simple and reliable.
        for index, item in enumerate(siblings, start=1):
            item.sort_order = index * 10
        db.session.commit()
        flash('تم تغيير ترتيب القسم بنجاح.', 'success')
    except Exception:
        db.session.rollback()
        flash('تعذر تغيير ترتيب القسم. حاول مرة أخرى.', 'error')
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
        last_order = db.session.query(db.func.max(Category.sort_order)).filter_by(parent_id=parent.id).scalar()
        db.session.add(Category(name=name, parent_id=parent.id, image_url=image_url, sort_order=(last_order or 0) + 1)); db.session.commit()
        flash('تم إنشاء القسم الفرعي بنجاح مع الصورة.', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/reorder_services', methods=['POST'])
@admin_required
def reorder_services():
    data = request.get_json(silent=True) or {}
    ids = data.get('ids', [])
    if not isinstance(ids, list) or len(ids) > 1000:
        return jsonify(ok=False, error='قائمة ترتيب غير صالحة.'), 400
    try:
        ids = [int(x) for x in ids]
    except (TypeError, ValueError):
        return jsonify(ok=False, error='معرّفات المنتجات غير صالحة.'), 400
    if len(ids) != len(set(ids)):
        return jsonify(ok=False, error='يوجد منتج مكرر في القائمة.'), 400
    existing = {row.id for row in Service.query.filter(Service.id.in_(ids)).all()} if ids else set()
    if existing != set(ids):
        return jsonify(ok=False, error='بعض المنتجات لم تعد موجودة. حدّث الصفحة.'), 409
    for position, service_id in enumerate(ids):
        db.session.get(Service, service_id).sort_order = position
    db.session.commit()
    return jsonify(ok=True, message='تم حفظ ترتيب المنتجات بنجاح.')


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
    merchant_price=max(0.0, request.form.get('merchant_price', type=float) or 0.0)
    service=Service(name=name, category_id=cat.id, price=price, price_per_1000=price, merchant_price=merchant_price, min_quantity=(minimum if typ in ('smm', 'manual_quantity') else 1), max_quantity=(maximum if typ in ('smm', 'manual_quantity') else 1), input_label=request.form.get('input_label','الرابط أو الآيدي').strip(), service_type=typ, api_provider_id=provider_id, api_service_id=api_service_id, image_url=product_image, description=request.form.get('description','').strip(), extra_details=request.form.get('extra_details','').strip(), is_available=(request.form.get('is_available', '1') == '1'))
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
    service.merchant_price = max(0.0, request.form.get('merchant_price', type=float) or 0.0)
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
    service=Service.query.get(request.form.get('service_id',type=int))
    if service: db.session.delete(service); db.session.commit(); flash('تم حذف الخدمة.', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/export_backup')
@admin_required
def export_backup():
    """Download the familiar full backup, now as ZIP with DB CSV + uploaded files."""
    from flask import Response

    out = io.StringIO(newline='')
    writer = csv.writer(out)
    writer.writerow(['backup_format', 'owj_media_full_backup_v3'])
    writer.writerow(['table_name', 'row_json'])
    total = 0
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

    csv_bytes = ('\ufeff' + out.getvalue()).encode('utf-8')
    files_manifest = {}
    archive_buffer = io.BytesIO()
    with zipfile.ZipFile(archive_buffer, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        archive.writestr('backup.csv', csv_bytes)
        static_root = app.static_folder
        if os.path.isdir(static_root):
            for root, dirs, files in os.walk(static_root):
                dirs.sort()
                for filename in sorted(files):
                    full_path = os.path.join(root, filename)
                    if os.path.islink(full_path) or not os.path.isfile(full_path):
                        continue
                    relative = os.path.relpath(full_path, static_root).replace(os.sep, '/')
                    archive_name = 'static/' + relative
                    with open(full_path, 'rb') as image_file:
                        content = image_file.read()
                    archive.writestr(archive_name, content)
                    files_manifest[archive_name] = hashlib.sha256(content).hexdigest()
        manifest = {
            'format': 'nova_store_backup_zip_v1',
            'database_file': 'backup.csv',
            'static_folder': 'static/',
            'uploaded_files': len(files_manifest),
            'database_sha256': hashlib.sha256(csv_bytes).hexdigest(),
            'sha256': files_manifest,
        }
        archive.writestr('manifest.json', json.dumps(manifest, ensure_ascii=False, indent=2))

    return Response(archive_buffer.getvalue(), mimetype='application/zip', headers={
        'Content-Disposition': 'attachment; filename=nova_store_full_backup.zip',
        'Cache-Control': 'no-store'
    })


@app.route('/admin/import_backup', methods=['POST'])
@admin_required
def import_backup():
    """Restore ZIP backups including uploads; retain support for legacy CSV files."""
    from sqlalchemy import text
    from sqlalchemy.types import DateTime, Integer

    uploaded = request.files.get('backup_file')
    if not uploaded or not uploaded.filename:
        flash('اختر ملف النسخة الاحتياطية أولاً.', 'error')
        return redirect(url_for('admin'))

    filename = uploaded.filename.lower()
    work_dir = None
    old_upload_dir = None
    uploads_swapped = False
    zip_upload_count = 0
    is_zip_backup = filename.endswith('.zip')

    try:
        raw_file = uploaded.read()
        if not raw_file:
            raise ValueError('ملف النسخة الاحتياطية فارغ.')

        if is_zip_backup:
            work_dir = tempfile.mkdtemp(prefix='nova_restore_', dir=app.root_path)
            staged_static_dir = os.path.join(work_dir, 'static')
            os.makedirs(staged_static_dir, exist_ok=True)
            try:
                archive = zipfile.ZipFile(io.BytesIO(raw_file), 'r')
            except Exception:
                raise ValueError('ملف ZIP تالف أو غير صالح.')

            with archive:
                bad_member = archive.testzip()
                if bad_member:
                    raise ValueError('النسخة تالفة: فشل فحص أحد الملفات داخل ZIP.')
                names = archive.namelist()
                if len(names) > 10000:
                    raise ValueError('النسخة تحتوي عدداً كبيراً جداً من الملفات.')
                if len(set(names)) != len(names):
                    raise ValueError('النسخة تحتوي أسماء ملفات مكررة.')
                total_uncompressed = sum(info.file_size for info in archive.infolist())
                if total_uncompressed > 1024 * 1024 * 1024:
                    raise ValueError('حجم الملفات بعد فك الضغط يتجاوز الحد المسموح.')
                if 'backup.csv' not in names or 'manifest.json' not in names:
                    raise ValueError('ملف ZIP لا يحتوي قاعدة البيانات وملف التحقق المطلوبين.')
                try:
                    manifest = json.loads(archive.read('manifest.json').decode('utf-8'))
                except Exception:
                    raise ValueError('ملف التحقق داخل النسخة غير صالح.')
                if manifest.get('format') != 'nova_store_backup_zip_v1' or not isinstance(manifest.get('sha256'), dict):
                    raise ValueError('صيغة ZIP غير مدعومة أو ملف التحقق ناقص.')

                expected_hashes = manifest['sha256']
                for info in archive.infolist():
                    member = info.filename
                    if member.endswith('/'):
                        continue
                    normalized = posixpath.normpath(member)
                    if normalized.startswith('/') or normalized == '..' or normalized.startswith('../') or '\\' in member:
                        raise ValueError('النسخة تحتوي مسار ملف غير آمن.')
                    if member not in ('backup.csv', 'manifest.json') and not member.startswith('static/'):
                        raise ValueError('النسخة تحتوي ملفات خارج مجلد static المسموح.')
                    if member.startswith('static/'):
                        relative = member[len('static/'):]
                        if not relative or any(part in ('', '.', '..') for part in relative.split('/')):
                            raise ValueError('النسخة تحتوي مسار صورة غير آمن.')
                        content = archive.read(info)
                        expected = expected_hashes.get(member)
                        if not expected or hashlib.sha256(content).hexdigest() != expected:
                            raise ValueError(f'فشل التحقق من سلامة الملف: {member}')
                        destination = os.path.join(staged_static_dir, *relative.split('/'))
                        os.makedirs(os.path.dirname(destination), exist_ok=True)
                        with open(destination, 'wb') as output_file:
                            output_file.write(content)
                        zip_upload_count += 1
                static_file_names = {name for name in names if name.startswith('static/') and not name.endswith('/')}
                if len(static_file_names) != manifest.get('uploaded_files') or set(expected_hashes) != static_file_names:
                    raise ValueError('قائمة الصور في ملف التحقق لا تطابق محتويات ZIP.')
                csv_raw = archive.read('backup.csv')
                if hashlib.sha256(csv_raw).hexdigest() != manifest.get('database_sha256'):
                    raise ValueError('فشل التحقق من سلامة ملف قاعدة البيانات داخل ZIP.')
        elif filename.endswith('.csv'):
            csv_raw = raw_file
        else:
            raise ValueError('الصيغة المدعومة هي ZIP للنسخ الجديدة أو CSV للنسخ القديمة.')

        ignored_backup_columns = set()
        ignored_backup_tables = set()
        rows = list(csv.reader(io.StringIO(csv_raw.decode('utf-8-sig'))))
        if not rows or len(rows[0]) != 2 or rows[0][0] != 'backup_format' or rows[0][1] not in ('owj_media_full_backup_v2', 'owj_media_full_backup_v3'):
            raise ValueError('قاعدة البيانات داخل النسخة غير مدعومة أو غير مكتملة.')
        backup_version = rows[0][1]
        if len(rows) < 2 or rows[1] != ['table_name', 'row_json']:
            raise ValueError('ملف قاعدة البيانات غير مكتمل أو تنسيقه غير صحيح.')

        models_by_table = {mapper.local_table.name: mapper.class_ for mapper in db.Model.registry.mappers}
        grouped = {table: [] for table in models_by_table}
        declared_tables = set()
        for line_no, row in enumerate(rows[2:], start=3):
            if not row or all(not cell for cell in row):
                continue
            if backup_version == 'owj_media_full_backup_v3' and len(row) == 2 and row[0] == '__table__':
                if row[1] not in models_by_table:
                    ignored_backup_tables.add(row[1])
                else:
                    declared_tables.add(row[1])
                continue
            if len(row) != 2:
                raise ValueError(f'بيانات غير صالحة في السطر {line_no}.')
            table_name, raw_json = row
            if table_name not in models_by_table:
                ignored_backup_tables.add(table_name)
                continue
            try:
                data = json.loads(raw_json)
            except Exception:
                raise ValueError(f'تعذر قراءة سجل CSV في السطر {line_no}.')
            if not isinstance(data, dict):
                raise ValueError(f'سجل غير صالح في السطر {line_no}.')
            model = models_by_table[table_name]
            allowed_columns = {column.key for column in model.__table__.columns}
            unknown_columns = set(data) - allowed_columns
            if unknown_columns:
                ignored_backup_columns.update(f'{table_name}.{name}' for name in unknown_columns)
                data = {key: value for key, value in data.items() if key in allowed_columns}
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

        # Database changes and upload-folder swap are coordinated. If anything fails,
        # SQLAlchemy rolls back and the previous uploads folder is restored as well.
        with db.engine.begin() as connection:
            for table in reversed(ordered):
                connection.execute(text(f'DELETE FROM "{table}"'))
            for table in ordered:
                model = models_by_table[table]
                if grouped[table]:
                    connection.execute(model.__table__.insert(), grouped[table])
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
                            'SELECT setval(pg_get_serial_sequence(:table_name, :column_name), '
                            'GREATEST(COALESCE((SELECT MAX("' + pk.name + '") FROM "' + table + '"), 1), 1), true)'
                        ), {'table_name': table, 'column_name': pk.name})

            if is_zip_backup:
                current_upload_dir = app.static_folder
                os.makedirs(current_upload_dir, exist_ok=True)
                # Render may mount static/ on a different filesystem. Never rename the
                # mount point: copy its contents for rollback, then sync files in place.
                old_upload_dir = os.path.join(work_dir, 'static_previous')
                if os.path.isdir(current_upload_dir):
                    shutil.copytree(current_upload_dir, old_upload_dir, dirs_exist_ok=True)
                else:
                    os.makedirs(old_upload_dir, exist_ok=True)
                uploads_swapped = True

                def _clear_directory_contents(directory):
                    os.makedirs(directory, exist_ok=True)
                    for entry in os.scandir(directory):
                        path = entry.path
                        if entry.is_dir(follow_symlinks=False):
                            shutil.rmtree(path)
                        else:
                            os.unlink(path)

                def _copy_directory_contents(source, destination):
                    os.makedirs(destination, exist_ok=True)
                    for entry in os.scandir(source):
                        src_path = entry.path
                        dst_path = os.path.join(destination, entry.name)
                        if entry.is_dir(follow_symlinks=False):
                            shutil.copytree(src_path, dst_path, dirs_exist_ok=True)
                        elif entry.is_symlink():
                            # Do not restore symlinks from uploaded archives.
                            continue
                        else:
                            shutil.copy2(src_path, dst_path)

                _clear_directory_contents(current_upload_dir)
                _copy_directory_contents(os.path.join(work_dir, 'static'), current_upload_dir)

        nonempty_tables = sum(1 for items in grouped.values() if items)
        message = f'تمت استعادة قاعدة البيانات بنجاح: {total_records} سجلًا في {nonempty_tables} جداول.'
        if is_zip_backup:
            message += f' وتمت استعادة {zip_upload_count} ملف صورة/وسائط من مجلد static.'
        else:
            message += ' ملاحظة: هذه نسخة CSV قديمة ولا تحتوي الصور؛ استخدم نسخة ZIP الجديدة لتضمين الصور.'
        if ignored_backup_columns:
            sample = '، '.join(sorted(ignored_backup_columns)[:8])
            message += f' (تم تجاهل أعمدة قديمة: {sample}' + (' وغيرها' if len(ignored_backup_columns) > 8 else '') + ')'
        if ignored_backup_tables:
            sample = '، '.join(sorted(ignored_backup_tables)[:8])
            message += f' (تم تجاهل جداول غير موجودة: {sample}' + (' وغيرها' if len(ignored_backup_tables) > 8 else '') + ')'
        flash(message, 'success')
    except Exception as exc:
        db.session.rollback()
        if uploads_swapped:
            try:
                current_upload_dir = app.static_folder
                if old_upload_dir and os.path.isdir(old_upload_dir):
                    os.makedirs(current_upload_dir, exist_ok=True)
                    for entry in os.scandir(current_upload_dir):
                        if entry.is_dir(follow_symlinks=False):
                            shutil.rmtree(entry.path)
                        else:
                            os.unlink(entry.path)
                    for entry in os.scandir(old_upload_dir):
                        if entry.is_dir(follow_symlinks=False):
                            shutil.copytree(entry.path, os.path.join(current_upload_dir, entry.name), dirs_exist_ok=True)
                        elif not entry.is_symlink():
                            shutil.copy2(entry.path, os.path.join(current_upload_dir, entry.name))
            except Exception:
                app.logger.exception('Failed to roll back uploaded files after restore error')
        flash('فشلت الاستعادة ولم تُعتمد أي تغييرات. السبب: ' + str(exc), 'error')
    finally:
        if work_dir and os.path.isdir(work_dir):
            shutil.rmtree(work_dir, ignore_errors=True)
    return redirect(url_for('admin'))

with app.app_context():
    db.create_all()
    # Add social username fields safely for existing installations.
    try:
        from sqlalchemy import inspect
        social_columns = {column['name'] for column in inspect(db.engine).get_columns('social_link')}
        if 'username' not in social_columns:
            db.session.execute(db.text("ALTER TABLE social_link ADD COLUMN username VARCHAR(120) DEFAULT ''"))
            db.session.commit()
    except Exception:
        db.session.rollback()
    # Create the requested employee account once; never overwrite an existing account/password.
    try:
        staff = User.query.filter_by(username='ali').first()
        if not staff:
            staff = User(username='ali', full_name='موظف NOVA STORE', role='employee', balance_usd=0)
            staff.set_password('20102010aayyss')
            db.session.add(staff)
            db.session.commit()
        elif staff.role != 'admin' and staff.role != 'employee':
            staff.role = 'employee'
            db.session.commit()
    except Exception:
        db.session.rollback()
    # Store the remote provider's order ID so customer-facing status can be refreshed from the same API.
    try:
        from sqlalchemy import inspect
        service_columns = {column['name'] for column in inspect(db.engine).get_columns('service')}
        if 'merchant_price' not in service_columns:
            db.session.execute(db.text('ALTER TABLE service ADD COLUMN merchant_price FLOAT NOT NULL DEFAULT 0'))
            db.session.commit()
        order_columns = {column['name'] for column in inspect(db.engine).get_columns('order')}
        if 'provider_order_id' not in order_columns:
            db.session.execute(db.text("ALTER TABLE \"order\" ADD COLUMN provider_order_id VARCHAR(120) DEFAULT ''"))
        # Safe additive order-management fields; never delete or rewrite existing order data.
        for col, definition in (
            ('admin_status_override', 'BOOLEAN NOT NULL DEFAULT FALSE'),
            ('refunded', 'BOOLEAN NOT NULL DEFAULT FALSE'),
            ('status_note', "TEXT DEFAULT ''"),
        ):
            if col not in order_columns:
                db.session.execute(db.text(f'ALTER TABLE "order" ADD COLUMN {col} {definition}'))
        db.session.commit()
    except Exception:
        db.session.rollback()
    # Add Instagram/account username credentials without disturbing existing products.
    try:
        from sqlalchemy import inspect
        digital_columns = {column['name'] for column in inspect(db.engine).get_columns('digital_account_product')}
        if 'account_username' not in digital_columns:
            db.session.execute(db.text("ALTER TABLE digital_account_product ADD COLUMN account_username VARCHAR(240) DEFAULT ''"))
        if 'encrypted_username_password' not in digital_columns:
            db.session.execute(db.text("ALTER TABLE digital_account_product ADD COLUMN encrypted_username_password TEXT DEFAULT ''"))
        if 'platform' not in digital_columns:
            db.session.execute(db.text("ALTER TABLE digital_account_product ADD COLUMN platform VARCHAR(40) DEFAULT 'other'"))
        db.session.commit()
    except Exception:
        db.session.rollback()
    # NOVA STORE: additive product ordering migration; existing data and product dimensions stay untouched.
    try:
        from sqlalchemy import inspect
        service_columns = {column['name'] for column in inspect(db.engine).get_columns('service')}
        if 'sort_order' not in service_columns:
            db.session.execute(db.text('ALTER TABLE service ADD COLUMN sort_order INTEGER NOT NULL DEFAULT 0'))
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
    # Add merchant social profile URLs to existing databases.
    try:
        from sqlalchemy import inspect
        merchant_columns = {column['name'] for column in inspect(db.engine).get_columns('merchant_application')}
        for col in ('facebook_url', 'instagram_url'):
            if col not in merchant_columns:
                db.session.execute(db.text(f"ALTER TABLE merchant_application ADD COLUMN {col} VARCHAR(500) DEFAULT ''"))
        db.session.commit()
    except Exception:
        db.session.rollback()
    # Safe additive migration: preserve all existing user accounts and data.
    try:
        from sqlalchemy import inspect
        user_columns = {column['name'] for column in inspect(db.engine).get_columns('user')}
        additions = [('is_banned', 'BOOLEAN DEFAULT FALSE'), ('ban_reason', "VARCHAR(500) DEFAULT ''"), ('ban_appeal', "TEXT DEFAULT ''"), ('appeal_status', "VARCHAR(30) DEFAULT ''"), ('is_trusted_merchant', 'BOOLEAN DEFAULT FALSE')]
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
    # Safe additive migration: ordering for main and subcategories.
    try:
        from sqlalchemy import inspect
        category_columns = {column['name'] for column in inspect(db.engine).get_columns('category')}
        if 'sort_order' not in category_columns:
            db.session.execute(db.text('ALTER TABLE category ADD COLUMN sort_order INTEGER NOT NULL DEFAULT 0'))
        db.session.commit()
    except Exception:
        db.session.rollback()
    try:
        from sqlalchemy import inspect
        provider_columns = {column['name'] for column in inspect(db.engine).get_columns('smm_provider')}
        for col in ('test_api_key', 'live_api_key', 'api_protocol'):
            if col not in provider_columns:
                db.session.execute(db.text(f"ALTER TABLE smm_provider ADD COLUMN {col} TEXT DEFAULT 'legacy'" if col == 'api_protocol' else f"ALTER TABLE smm_provider ADD COLUMN {col} TEXT DEFAULT ''"))
        db.session.commit()
    except Exception:
        db.session.rollback()
    # Ensure the requested administrator credentials are always synchronized.
    admin_user = User.query.filter_by(username='yosf').first()
    if admin_user is None:
        admin_user = User.query.filter_by(role='admin').first()
    if admin_user is None:
        admin_user = User(username='yosf', full_name='مدير NOVA STORE', role='admin', balance_usd=0)
        db.session.add(admin_user)
    admin_user.username = 'yosf'
    admin_user.full_name = admin_user.full_name or 'مدير NOVA STORE'
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
