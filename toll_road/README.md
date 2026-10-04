# إدارة خدمات الطريق الدولي — Toll Road Services Management

**Flask + SQLite + HTML/CSS/JS فقط.** لا حزم أخرى، ولا حاجة لأي خادم إضافي.

## التشغيل

**Windows:** انقر مرتين على `start.bat`
**Linux / macOS:** `./start.sh`
**يدويًا:**
```
pip install -r requirements.txt
python app.py
```
يفتح المتصفح تلقائيًا على `http://127.0.0.1:5000` (وإن كان المنفذ مشغولًا يُستخدم التالي تلقائيًا؛ العنوان يظهر في الشاشة).

> افتح العنوان `127.0.0.1` أو `localhost` — **وليس** `0.0.0.0`، فالمتصفحات لا تفتحه.

## الدخول التجريبي
| المستخدم | كلمة المرور | الصلاحية |
|---|---|---|
| admin | admin123 | مدير النظام |
| manager | manager123 | مشرف |
| viewer | viewer123 | اطلاع فقط |

غيّر الكلمات من «إدارة المستخدمين» (حقل «كلمة المرور» لكل مستخدم).

## إعادة تعيين البيانات
أغلق الخادم، احذف `project_resources.db`، ثم شغّل التطبيق: تُنشأ قاعدة جديدة ببيانات تجريبية.

## الإعدادات (اختيارية)
انسخ `.env.example` إلى `.env`: `HOST`, `PORT`, `SECRET_KEY`, `SESSION_HOURS`, `OPEN_BROWSER`, `FLASK_DEBUG`.
للوصول من أجهزة أخرى في الشبكة: `HOST=0.0.0.0` ثم افتح `http://عنوان-الجهاز:5000`.

## الهيكل
```
app.py            المسارات والمنطق (تشغيل: python app.py)
database.py       الاتصال بـ SQLite + البيانات التجريبية
schema.sql        مخطط قاعدة البيانات
templates/        قوالب HTML (Jinja2)
static/           CSS + الشعارات + vendor (Chart.js, Leaflet) محليًا
```
ملاحظة: الخرائط (OpenStreetMap) وخطوط Google تحتاج إنترنت؛ بقية النظام يعمل بدونه.
