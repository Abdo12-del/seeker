"""Bilingual string table (Arabic / English).

Every user-facing string that leaves the server lives here so a platform can
be audited in the language the people being simulated actually read - an
informed consent notice is not informed if the reader cannot read it.
"""

from __future__ import annotations

STRINGS: dict = {
    'en': {
        'app_name': 'Seeker',
        'tagline': 'Authorized awareness simulations & deceptive-location audits',
        # consent notice
        'consent_title': 'Location request notice',
        'consent_intro': 'This page is an authorized security awareness simulation.',
        'consent_who': 'Who is asking',
        'consent_why': 'Why',
        'consent_what': 'What is collected',
        'consent_retention': 'How long it is kept',
        'consent_rights': 'Your choices',
        'consent_why_body': 'To measure how often people share their location with an unfamiliar page, so we can train teams to recognise the request.',
        'consent_what_body': 'Approximate location (stored at reduced precision), plus basic device and browser characteristics. No credentials are requested and none are stored.',
        'consent_retention_body': 'Records are kept for {days} days, then deleted automatically.',
        'consent_rights_body': 'You can decline. Declining is the safe response and is recorded as a positive result.',
        'consent_contact': 'Questions? Contact {contact}',
        'btn_allow': 'Share my approximate location',
        'btn_deny': 'Decline',
        'btn_report': 'Report this page as suspicious',
        'btn_continue': 'Continue',
        'btn_back': 'Back to safety',
        # teach-back
        'reveal_title': 'This was a simulation',
        'reveal_body': 'You just interacted with an authorized security awareness simulation run by {org}. No data was sold and no credentials were requested.',
        'reveal_tip_1': 'A page does not need your location unless it is a map, a delivery or a navigation service.',
        'reveal_tip_2': 'Read the notice before you tap Allow. Declining is always a valid answer.',
        'reveal_tip_3': 'Report suspicious pages to your security team - reporting is the behaviour we want to see.',
        'reveal_shared': 'You shared: {value}',
        'reveal_declined': 'You declined. That was the right call.',
        # dashboard
        'dash_title': 'Seeker console',
        'dash_campaigns': 'Campaigns',
        'dash_live': 'Live events',
        'dash_audit': 'Page audit',
        'dash_funnel': 'Simulation funnel',
        'dash_no_campaign': 'No campaigns yet. Create one to begin.',
        'sent': 'Links issued',
        'opened': 'Opened',
        'consented': 'Shared location',
        'declined': 'Declined',
        'reported': 'Reported the page',
        'revealed': 'Saw the teach-back',
        'open_rate': 'Open rate',
        'share_rate': 'Share rate',
        'report_rate': 'Report rate',
        'risk_score': 'Susceptibility',
        'status': 'Status',
        'actions': 'Actions',
        'export': 'Export',
        'refresh': 'Refresh',
        'loading': 'Loading…',
        'no_events': 'No events recorded yet.',
        'audit_placeholder': 'Paste HTML (or a URL) of a page you want checked for deceptive location harvesting.',
        'audit_run': 'Analyse page',
        'audit_verdict': 'Verdict',
        'audit_score': 'Risk score',
        'audit_findings': 'Findings',
        'audit_recommend': 'Recommendations',
        'login_title': 'Console access',
        'login_help': 'Use the API token printed when you started the server.',
        'login_btn': 'Unlock',
        'logout': 'Lock',
        'lang_toggle': 'English',
        'report_prompt': 'Why are you reporting this page?',
        'app_badge': 'security awareness simulation',
    },
    'ar': {
        'app_name': 'سيكر',
        'tagline': 'محاكاة توعية مصرّحة وتدقيق صفحات استغلال الموقع',
        'consent_title': 'إشعار طلب الموقع',
        'consent_intro': 'هذه الصفحة جزء من محاكاة توعية أمنية مصرّحة.',
        'consent_who': 'من يطلب',
        'consent_why': 'السبب',
        'consent_what': 'ما الذي يُجمع',
        'consent_retention': 'مدة الاحتفاظ',
        'consent_rights': 'خياراتك',
        'consent_why_body': 'لقياس عدد مرات مشاركة الأشخاص لموقعهم مع صفحة غير مألوفة، حتى ندرّب الفرق على تمييز هذا الطلب.',
        'consent_what_body': 'موقع تقريبي (يُخزّن بدقة مخفّضة)، وخصائص أساسية للجهاز والمتصفح. لا يُطلب أي كلمة مرور ولا تُخزّن.',
        'consent_retention_body': 'تُحذف السجلات تلقائيًا بعد {days} يومًا.',
        'consent_rights_body': 'يمكنك الرفض. الرفض هو التصرف الآمن ويُسجّل كنتيجة إيجابية.',
        'consent_contact': 'للاستفسار تواصل مع {contact}',
        'btn_allow': 'مشاركة موقعي التقريبي',
        'btn_deny': 'رفض',
        'btn_report': 'الإبلاغ عن هذه الصفحة',
        'btn_continue': 'متابعة',
        'btn_back': 'العودة إلى الأمان',
        'reveal_title': 'كانت هذه محاكاة',
        'reveal_body': 'لقد تفاعلت للتو مع محاكاة توعية أمنية مصرّحة ينفذها {org}. لم تُبع أي بيانات ولم يُطلب منك أي كلمة مرور.',
        'reveal_tip_1': 'الصفحة لا تحتاج موقعك إلا إن كانت خريطة أو خدمة توصيل أو ملاحة.',
        'reveal_tip_2': 'اقرأ الإشعار قبل الضغط على «سماح». الرفض دائمًا خيار صحيح.',
        'reveal_tip_3': 'أبلغ عن الصفحات المشبوهة لفريق الأمن — الإبلاغ هو السلوك المطلوب.',
        'reveal_shared': 'لقد شاركت: {value}',
        'reveal_declined': 'رفضت الطلب، وهذا هو التصرف الصحيح.',
        'dash_title': 'لوحة تحكم سيكر',
        'dash_campaigns': 'الحملات',
        'dash_live': 'الأحداث المباشرة',
        'dash_audit': 'تدقيق الصفحات',
        'dash_funnel': 'قمع المحاكاة',
        'dash_no_campaign': 'لا توجد حملات بعد. أنشئ حملة للبدء.',
        'sent': 'روابط مُصدَرة',
        'opened': 'فتح الرابط',
        'consented': 'شارك الموقع',
        'declined': 'رفض',
        'reported': 'أبلغ عن الصفحة',
        'revealed': 'شاهد رسالة التوعية',
        'open_rate': 'نسبة الفتح',
        'share_rate': 'نسبة المشاركة',
        'report_rate': 'نسبة الإبلاغ',
        'risk_score': 'القابلية',
        'status': 'الحالة',
        'actions': 'إجراءات',
        'export': 'تصدير',
        'refresh': 'تحديث',
        'loading': 'جارٍ التحميل…',
        'no_events': 'لا توجد أحداث مسجلة بعد.',
        'audit_placeholder': 'الصق HTML الصفحة (أو رابطها) للتحقق من استغلال الموقع بشكل خادع.',
        'audit_run': 'حلّل الصفحة',
        'audit_verdict': 'النتيجة',
        'audit_score': 'درجة الخطورة',
        'audit_findings': 'الملاحظات',
        'audit_recommend': 'التوصيات',
        'login_title': 'الدخول للوحة',
        'login_help': 'استخدم رمز API المطبوع عند تشغيل الخادم.',
        'login_btn': 'دخول',
        'logout': 'خروج',
        'lang_toggle': 'العربية',
        'report_prompt': 'لماذا تبلغ عن هذه الصفحة؟',
        'app_badge': 'محاكاة توعية أمنية',
    },
}

RTL = {'ar', 'fa', 'ur', 'he'}


def translate(key: str, lang: str = 'en', **kwargs) -> str:
    table = STRINGS.get(lang, STRINGS['en'])
    value = table.get(key) or STRINGS['en'].get(key) or key
    if kwargs:
        try:
            value = value.format(**kwargs)
        except (KeyError, IndexError):
            pass
    return value


def t(key: str, lang: str = 'en', **kwargs) -> str:
    return translate(key, lang, **kwargs)


def table(lang: str = 'en') -> dict:
    return STRINGS.get(lang, STRINGS['en'])


def is_rtl(lang: str) -> bool:
    return lang in RTL


def languages() -> tuple:
    return ('ar', 'en')
