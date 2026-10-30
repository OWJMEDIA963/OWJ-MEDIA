import os
import requests
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'change-this-secret-key-before-deployment')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///owj_media.db').replace('postgres://', 'postgresql://')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'uploads')
ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp', 'gif'}

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
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    @property
    def is_authenticated(self): return True
    def set_password(self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password): return check_password_hash(self.password_hash, password)

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    image_url = db.Column(db.String(500), default='')

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
    is_available = db.Column(db.Boolean, default=True)
    category = db.relationship('Category', backref=db.backref('services', lazy=True))

class SMMProvider(db.Model):
    __tablename__ = 'smm_provider'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    api_url = db.Column(db.String(500), nullable=False)
    api_key = db.Column(db.Text, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    service_id = db.Column(db.Integer, db.ForeignKey('service.id'), nullable=True)
    service_name = db.Column(db.String(160), default='')
    link = db.Column(db.String(1000), default='')
    quantity = db.Column(db.Integer, default=1)
    total_price = db.Column(db.Float, default=0.0)
    status = db.Column(db.String(40), default='قيد المراجعة')
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
    proof_image = db.Column(db.String(500), default='')
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
    return {'current_user': user, 'site_name': 'أوج ميديا', 'unread_notification_count': unread_count}

def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get('user_id'):
            flash('سجّل الدخول أولاً للمتابعة.', 'error')
            return redirect(url_for('login'))
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

@app.route('/')
def index():
    categories = Category.query.order_by(Category.id).all()
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
    return render_template('category_services.html', category=category, services=services)

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form.get('username','').strip()).first()
        if user and user.check_password(request.form.get('password','')):
            session.clear(); session['user_id'] = user.id
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
        db.session.commit(); flash('تم تحديث بياناتك.', 'success'); return redirect(url_for('profile'))
    return render_template('profile.html', user=user)

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
    if service.service_type == 'manual':
        # طلب يدوي بسعر ثابت لكل طلب.
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
    if service.service_type == 'smm':
        provider = SMMProvider.query.filter_by(id=service.api_provider_id, is_active=True).first() if service.api_provider_id else None
        if not provider or not service.api_service_id:
            flash('هذه الخدمة التلقائية غير مربوطة بمزوّد API بشكل صحيح. تواصل مع الإدارة.', 'error')
            return redirect(url_for('category_services', category_id=service.category_id))
        try:
            response = requests.post(provider.api_url, data={
                'key': provider.api_key, 'action': 'add', 'service': service.api_service_id,
                'link': link, 'quantity': quantity
            }, timeout=20)
            response.raise_for_status()
            api_result = response.json()
            if api_result.get('error') or not api_result.get('order'):
                raise ValueError(str(api_result.get('error') or 'لم يؤكد مزود الخدمة قبول الطلب.'))
            provider_order_id = str(api_result['order'])
        except Exception as exc:
            app.logger.warning('SMM provider order failed: %s', exc)
            flash('لم يقبل مزوّد الخدمة الطلب. لم يتم خصم رصيدك؛ تحقق من إعدادات API وحاول لاحقاً.', 'error')
            return redirect(url_for('category_services', category_id=service.category_id))
    user.balance_usd -= total
    order = Order(user_id=user.id, service_id=service.id, service_name=service.name, link=link, quantity=quantity, total_price=total, status=('قيد التنفيذ' if service.service_type == 'smm' else 'قيد المراجعة'))
    db.session.add(order); db.session.commit()
    flash(('تم إرسال طلبك إلى مزوّد الخدمة. رقم الطلب: ' + provider_order_id) if provider_order_id else 'تم استلام طلبك بنجاح.', 'success'); return redirect(url_for('my_orders'))

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
                proof_image = save_uploaded_image('proof_image')
            except ValueError as exc:
                flash(str(exc), 'error')
                return redirect(url_for('deposit'))
            db.session.add(DepositRequest(
                user_id=current_user().id,
                amount=amount,
                proof=request.form.get('proof', '').strip(),
                proof_image=proof_image,
                payment_method_name=selected_payment.name
            ))
            db.session.commit()
            flash('تم إرسال طلب الشحن للمراجعة.', 'success')
            return redirect(url_for('deposit'))
    user = current_user() if session.get('user_id') else None
    my_deposits = DepositRequest.query.filter_by(user_id=user.id).order_by(DepositRequest.id.desc()).all() if user else []
    return render_template('deposit.html', payments=payments, my_deposits=my_deposits)

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
    return render_template('notifications.html', notifications=items, vapid_public_key=os.environ.get('VAPID_PUBLIC_KEY', ''))


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


@app.route('/admin')
@admin_required
def admin():
    return render_template('admin.html', orders=Order.query.order_by(Order.id.desc()).all(), verification_requests=VerificationRequest.query.filter_by(status='pending').all(), categories=Category.query.all(), services=Service.query.all(), deposits=DepositRequest.query.order_by(DepositRequest.id.desc()).all(), payment_methods=PaymentMethod.query.order_by(PaymentMethod.id.desc()).all(), sms_number_providers=SMSNumberProvider.query.order_by(SMSNumberProvider.id.desc()).all(), smm_providers=SMMProvider.query.order_by(SMMProvider.id.desc()).all(), support_count=SupportTicket.query.filter(SupportTicket.status != 'مغلقة').count())


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
        send_user_notification(user.id, 'تم شحن محفظتك', f'تمت الموافقة على طلب الشحن وإضافة ${deposit.amount:.2f} إلى حسابك.', url_for('deposit'))
        db.session.commit()
        flash(f'تم قبول طلب الشحن #{deposit.id} وإضافة ${deposit.amount:.2f} إلى المحفظة.', 'success')
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
    order = Order.query.get_or_404(order_id); order.status='مكتمل'; db.session.commit(); flash('تم تحديث حالة الطلب.', 'success'); return redirect(url_for('admin'))

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
        user=User(username=username, role='merchant', balance_usd=max(0, request.form.get('bonus',type=float) or 0)); user.set_password(password); db.session.add(user); db.session.commit(); flash('تم إنشاء حساب التاجر.', 'success')
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

@app.route('/admin/add_smm_provider', methods=['POST'])
@admin_required
def add_smm_provider():
    name = request.form.get('provider_name', '').strip()
    api_url = request.form.get('api_url', '').strip()
    api_key = request.form.get('api_key', '').strip()
    if not name or not api_url.startswith(('https://', 'http://')) or not api_key:
        flash('أدخل اسم المزوّد ورابط API صحيحاً ومفتاح API.', 'error')
    else:
        db.session.add(SMMProvider(name=name, api_url=api_url, api_key=api_key))
        db.session.commit()
        flash('تم حفظ مزوّد API. احتفظ بالمفتاح سرياً.', 'success')
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

@app.route('/admin/add_service', methods=['POST'])
@admin_required
def add_service():
    name=request.form.get('name','').strip(); category_name=request.form.get('category_name','').strip()
    if not name or not category_name: flash('أدخل اسم الخدمة والقسم.', 'error'); return redirect(url_for('admin'))
    try:
        category_image = save_uploaded_image('category_image_file') or request.form.get('category_image_url','').strip()
        product_image = save_uploaded_image('image_file') or request.form.get('image_url','').strip()
    except ValueError as exc:
        flash(str(exc), 'error'); return redirect(url_for('admin'))
    cat=Category.query.filter_by(name=category_name).first()
    if not cat:
        cat=Category(name=category_name, image_url=category_image); db.session.add(cat); db.session.flush()
    elif category_image:
        cat.image_url = category_image
    price=request.form.get('price_per_1000',type=float) or 0
    typ=request.form.get('service_type','manual')
    if typ not in ('manual', 'manual_quantity', 'smm'): typ = 'manual'
    minimum = request.form.get('min_quantity',type=int) or 1
    maximum = request.form.get('max_quantity',type=int) or 10000
    if price < 0 or minimum < 1 or maximum < minimum:
        flash('تحقق من السعر والحد الأدنى والأقصى للكمية.', 'error')
        return redirect(url_for('admin'))
    provider_id = request.form.get('api_provider_id', type=int) if typ == 'smm' else None
    api_service_id = request.form.get('api_service_id', '').strip() if typ == 'smm' else ''
    if typ == 'smm' and (not provider_id or not api_service_id):
        flash('لخدمة SMM تلقائية، اختر مزوّد API وأدخل رقم الخدمة لدى المزوّد.', 'error'); return redirect(url_for('admin'))
    service=Service(name=name, category_id=cat.id, price=price, price_per_1000=price, min_quantity=(minimum if typ in ('smm', 'manual_quantity') else 1), max_quantity=(maximum if typ in ('smm', 'manual_quantity') else 1), input_label=request.form.get('input_label','الرابط أو الآيدي').strip(), service_type=typ, api_provider_id=provider_id, api_service_id=api_service_id, image_url=product_image, description=request.form.get('description','').strip(), is_available=(request.form.get('is_available', '1') == '1'))
    db.session.add(service); db.session.commit(); flash('تمت إضافة الخدمة.', 'success'); return redirect(url_for('admin'))

@app.route('/admin/update_service/<int:service_id>', methods=['POST'])
@admin_required
def update_service(service_id):
    service = Service.query.get_or_404(service_id)
    name = request.form.get('name', '').strip()
    category_name = request.form.get('category_name', '').strip()
    if not name or not category_name:
        flash('أدخل اسم المنتج والقسم.', 'error')
        return redirect(url_for('admin'))
    category = Category.query.filter_by(name=category_name).first()
    if not category:
        category = Category(name=category_name)
        db.session.add(category)
        db.session.flush()
    try:
        price = float(request.form.get('price_per_1000', '0'))
        minimum = int(request.form.get('min_quantity', '1'))
        maximum = int(request.form.get('max_quantity', '10000'))
    except (TypeError, ValueError):
        flash('تحقق من السعر والحد الأدنى والأقصى.', 'error')
        return redirect(url_for('admin'))
    typ = request.form.get('service_type', 'manual')
    if typ not in ('manual', 'manual_quantity', 'smm'): typ = 'manual'
    if price < 0 or minimum < 1 or maximum < minimum:
        flash('السعر يجب أن يكون موجباً، والحد الأقصى أكبر من أو يساوي الحد الأدنى.', 'error')
        return redirect(url_for('admin'))
    provider_id = request.form.get('api_provider_id', type=int) if typ == 'smm' else None
    api_service_id = request.form.get('api_service_id', '').strip() if typ == 'smm' else ''
    if typ == 'smm' and (not provider_id or not api_service_id):
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
    # Add fields to existing databases without deleting user data.
    try:
        from sqlalchemy import inspect
        deposit_columns = {column['name'] for column in inspect(db.engine).get_columns('deposit_request')}
        if 'rejection_reason' not in deposit_columns:
            db.session.execute(db.text("ALTER TABLE deposit_request ADD COLUMN rejection_reason VARCHAR(500) DEFAULT ''"))
        if 'proof_image' not in deposit_columns:
            db.session.execute(db.text("ALTER TABLE deposit_request ADD COLUMN proof_image VARCHAR(500) DEFAULT ''"))
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
