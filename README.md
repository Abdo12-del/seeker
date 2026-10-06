<p align="center"><b>Seeker — Awareness Edition</b></p>

<p align="center">
  منصة <b>محاكاة توعية أمنية مصرّحة</b> + <b>محرك تدقيق صفحات استغلال الموقع</b>.<br>
  Authorized phishing-simulation platform &amp; deceptive-location page auditor.
</p>

---

## English quick start

```bash
python3 seeker.py doctor                 # sanity check (no pip install needed)
python3 seeker.py serve --token demo1234 # console on http://127.0.0.1:8080/console
python3 seeker.py analyze https://example.com/page   # audit a page
python3 -m unittest discover -s tests    # 42 tests, zero dependencies
```

Everything runs on the Python standard library (3.8+). PHP is no longer required.

---

# العربية

## ما الذي تغيّر؟ (v1 → v2)

النسخة الأصلية (`thewhiteh4t/seeker`) كانت: صفحات PHP + ملفّين نصيين (`info.txt` و
`result.txt`) تقرأهما بايثون كل ثانيتين. الفكرة كانت «استضافة صفحة تطلب صلاحية
الموقع وأخذ الإحداثيات». النسخة 2 تعالج جذور المشكلة التقنية **وتغيّر الغرض**:

| | v1 | v2 |
|---|---|---|
| الغرض | جمع موقع شخص | **قياس** مدى قابلية فريق لمشاركة موقعه، وتدقيقه |
| التشغيل | PHP + بايثون | **بايثون وحدها** (مكتبة قياسية فقط) |
| التخزين | ملفّان نصيان + CSV | **SQLite** بسجل أحداث متسلسل بالهاش (tamper-evident) |
| تعدد الزوّار | ❌ تُربط بيانات شخص بمكان شخص آخر | ✅ كل حدث له `session_id` و`rid` |
| الموافقة | ❌ نافذة المتصفح فقط | ✅ **إشعار موافقة معلن + سجل موافقة موقّع** |
| الصلاحية | ❌ من يملك السكربت ينفّذه | ✅ **بوابة تصريح**: مُصرّح + نطاق + مدة + توقيع |
| تقليل البيانات | ❌ إحداثيات خام كاملة | ✅ سياسة دقة (`geohash` افتراضيًا) + مدة احتفاظ |
| النتيجة | إحداثيات + بيانات جهاز | **قمع محاكاة**: فتح / وافق / رفض / أبلغ |
| دفاعي | ❌ | ✅ `seeker analyze` يكشف الصفحات الخادعة |
| اختبارات | ❌ | ✅ 42 اختبارًا + CI |

### أخطاء حقيقية أُصلحت (كانت موجودة في v1)

* `logs/info.txt` يُفتح بـ `w+` وكذلك `result.txt` — أي زائرين في نفس الوقت
  يكتب كل منهما فوق الآخر، وقد تُنسب إحداثيات (أ) لجهاز (ب). في v2 كل حدث
  موسوم بـ `session_id` ويُخزَّن في جدول واحد.
* `maximumage: 0` في `js/location.js` — الخاصية الصحيحة `maximumAge` (حسّاسة
  لحالة الأحرف)، لذلك كان الخيار يُتجاهل بصمت.
* `re.sub(r'\33\[\d+m', ...)` في `utils.py` — يتعطل بـ `re.error` عند توجيه
  الخرج إلى أنبوب (`|`) لأن `\33` تُفسَّر كرجوع لمجموعة. **v1 كان ينهار عند
  `python3 seeker.py | tee log`**.
* `-d/--debugHTTP` معرّف كـ `type=bool` — أي نص غير فارغ يصبح `True`.
* معالجات PHP تقرأ `$_POST[...]` بدون تحقق: أول حقل ناقص يُنذر والملف يُكتب
  نصف JSON فينهار المحلّل.
* لا يوجد ربط بين «مَن فتح» و«مَن شارك» — لا توجد هوية جلسة أصلًا.

## الفكرة الفريدة

بدل أن تكون الأداة «طرف مهاجم فقط»، صارت **طرفي المعادلة**:

1. **وضع المحاكاة المصرّحة** — تقيس السلوك، لا تُنتج ملفًّا عن شخص.
2. **وضع التدقيق الدفاعي** — تحلّل أي صفحة (رابط أو HTML) وتقول لك إن كانت
   تطلب الموقع بشكل خادع، مع الدليل والتوصية.

ثلاثة أشياء لا تملكها أدوات هذا النوع مجتمعة:

* **بوابة تصريح (Authorization Gate):** لا تُخدَّم أي صفحة قبل وجود سجل موقّع
  يذكر المُصرّح (شخص بعينه) والنطاق والسبب وتاريخ الانتهاء. عند انتهاء المدة أو
  إيقاف الحملة ترجع الصفحة `403` ولا يُطلب الموقع أبدًا.
* **سجل الموافقة (Consent Ledger):** قبل رفع نافذة الصلاحية يظهر إشعار مقروء
  يذكر مَن يطلب ولماذا وكم تُحفظ البيانات، بلغة الزائر. القرار + نص الإشعار +
  هاشه + توقيع HMAC تُحفظ في سجل مستقل. الرفض يُسجَّل **كنتيجة إيجابية**.
* **تقليل البيانات كسياسة قابلة للتدقيق:** الإحداثيات تُخفَّض دقتها *قبل*
  التخزين لا بعده. الافتراضي `geohash` (~5 كم). تصدير KML لا يمكنه إنتاج دقة
  أعلى ممّا خُزِّن.

## التشغيل

```bash
# 1) تشغيل الخادم واللوحة
python3 seeker.py serve --port 8080 --token <رمز> \
    --org "فريق التوعية الأمنية" --contact soc@example.org

# 2) إنشاء حملة (لا تعمل بدون مُصرّح ونطاق)
python3 seeker.py campaign create \
    --name "خط الأساس الربع الرابع" \
    --scenario delivery \
    --authorizer "مدير مركز العمليات" \
    --scope "فريق المالية، 40 شخصًا" \
    --links 40 --group finance

# 3) النتائج
python3 seeker.py report <campaign-id>
python3 seeker.py export <campaign-id> -f html -o report.html

# 4) التدقيق الدفاعي
python3 seeker.py analyze https://example.com/tracking-page
python3 seeker.py analyze ./suspicious.html

# 5) التحقق من سلامة السجل
python3 seeker.py ledger verify
```

## السيناريوهات

سيناريوهات مضمّنة **without أي علامة تجارية حقيقية**: `delivery` (توصيل)،
`wifi` (شبكات قريبة)، `offers` (عروض)، `survey` (مجموعة ضابطة — صفحة تُصرّح
من البداية أنها تمرين). إضافة سيناريو = مجلد فيه `manifest.json`:

```json
{
  "id": "delivery",
  "name": "Delivery confirmation",
  "icon": "📦", "accent": "#0f766e",
  "requires_brand_authorization": false,
  "content": {
    "ar": {"title": "…", "headline": "…", "sub": "…", "cta": "…"},
    "en": {"title": "…", "headline": "…", "sub": "…", "cta": "…"}
  }
}
```

السيناريو الذي يقلّد علامة تجارية يجب أن يضبط
`requires_brand_authorization: true`، وحينها **ترفض المنصة عرضه** ما لم يحمل
سجل الحملة ترخيصًا موقّعًا باسم تلك العلامة.

## واجهة الويب

`http://HOST:8080/console` (تحتاج الرمز):

* **الحملات**: إنشاء، روابط تتبّع، إيقاف/تشغيل، تصدير CSV/JSON/KML/HTML، قمع
  محاكاة لكل حملة.
* **الأحداث المباشرة**: تدفق SSE لحظي لكل نقرة وقرار وإبلاغ.
* **تدقيق الصفحات**: لصق HTML أو رابط → درجة خطورة + ملاحظات بالدليل + توصيات.
* **النزاهة**: حالة سلسلة الهاش، صحة تواقيع الموافقة، أرقام المجموعات،
  سياسة تقليل البيانات الفعّالة.

## API

كل مسارات `/api/*` تحتاج `Authorization: Bearer <token>` (أو `?token=`).

| المسار | الوصف |
|---|---|
| `GET /api/state` | الحملات + القمع + المجموعات + آخر الأحداث |
| `GET /api/stream` | SSE للأحداث الحية |
| `POST /api/campaigns` | إنشاء حملة (ي require `authorizer` و`scope`) |
| `POST /api/campaigns/<id>/status` | `active` / `stopped` |
| `GET /api/campaigns/<id>/links` | روابط التتبّع |
| `GET /api/campaigns/<id>/export?format=` | `csv` `json` `kml` `html` |
| `DELETE /api/campaigns/<id>` | حذف الحملة وكل بياناتها |
| `POST /api/analyze` | `{url}` أو `{html}` |
| `GET /api/chain` | التحقق من سلسلة الأحداث وتواقيع الموافقة |

مسارات عامة (للزائر): `GET /l/<token>`، `POST /ingest/{device,open,consent_prompt,consent,location,error,report,reveal}`.

## التشغيل في Docker

```bash
docker compose up --build
# ثم: http://localhost:8080/console
```

## الأخلاقيات والقانون

راجع [`docs/ETHICS.md`](docs/ETHICS.md). باختصار: المحاكاة أداة تدريب تحتاج
تفويضًا كتابيًا من صاحب المنظمة، ونطاقًا محددًا، وإشعارًا صادقًا، وتقليلًا
للبيانات. المنصة **تفرض** هذه الشروط تقنيًا (بوابة التصريح + سجل الموافقة) بدل
أن تكتفي بطلبها.

## الملفات القديمة

نسخة 1 محفوظة كما هي في `legacy/` ويمكن تشغيلها بـ `python3 legacy/seeker_v1.py`
(تحتاج PHP). مجلد `template/` (صفحات Google Drive / WhatsApp / Telegram…)
**غير مستخدم** في المحرك الجديد ولا يُخدَّم افتراضيًا.

## الترخيص

MIT — انظر `LICENSE`. المشروع الأصلي: <https://github.com/thewhiteh4t/seeker>
