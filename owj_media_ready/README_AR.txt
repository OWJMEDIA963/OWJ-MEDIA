OWJ MEDIA - نسخة Flask جاهزة للرفع إلى GitHub ثم Render

المتطلبات: Python 3.12 محلياً (اختياري للتجربة).
تشغيل محلي:
1) فك ضغط المشروع وافتح الطرفية داخل مجلد owj_media_ready.
2) python -m venv .venv
3) Windows: .venv\Scripts\activate  | macOS/Linux: source .venv/bin/activate
4) pip install -r requirements.txt
5) python app.py
6) افتح http://127.0.0.1:5000

النشر إلى Render من GitHub:
1) أنشئ مستودع GitHub جديداً وارفع محتويات هذا المجلد إلى جذر المستودع (app.py وrequirements.txt وProcfile وrender.yaml).
2) في Render اختر New > Blueprint أو Web Service واربط مستودع GitHub.
3) أمر البناء: pip install -r requirements.txt
4) أمر التشغيل: gunicorn app:app --workers 1 --threads 4 --timeout 120
5) اضبط SECRET_KEY بقيمة طويلة وعشوائية من إعدادات Environment.

بيانات دخول المدير الافتراضية لهذه النسخة القديمة:
اسم المستخدم: yosf
كلمة المرور: 2008rrnny
غيّرها فوراً بعد أول دخول، ولا تشاركها.

ملاحظات مهمة:
- التطبيق ينشئ قاعدة SQLite تلقائياً. مساحة الملفات/SQLite على استضافات مجانية قد تكون مؤقتة وتُمسح عند إعادة النشر أو إعادة التشغيل؛ لا تعتمد عليها لحفظ بيانات دائمة. لبيانات دائمة اربط قاعدة PostgreSQL مستضافة وتأكد من ضبط DATABASE_URL.
- الصور المرفوعة داخل static/uploads قد لا تبقى على بعض الاستضافات المجانية بعد إعادة النشر.
- المساعد الحالي يعتمد قواعد بسيطة وليس نموذج ذكاء اصطناعي خارجياً.
- تم حذف أداة تحويل العملات بناءً على الطلب.
