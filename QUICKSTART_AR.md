# تشغيل Sentinel DFIR X v0.2 — دليل عربي مختصر

## ما الذي أرسلته لك؟

هذه حزمة **كود C# قابل للبناء على Windows**، وليست EXE جاهزًا تم اختباره. فيها ثلاثة مشاريع: Sentinel.Core، Sentinel.Agent (خدمة تعمل في الخلفية)، Sentinel.Desktop (واجهة WPF).

## أولاً: اختبر قبل تغيير الخدمة الموجودة

1. فك ضغط ZIP في مجلد **جديد**؛ لا تستبدل مجلد v0.1.
2. افتح PowerShell داخل مجلد `Sentinel_DFIR_v0.2`، ونفّذ:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Build.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\Publish.ps1
.\dist\desktop\Sentinel.Desktop.exe
```

3. إذا كانت الواجهة تعمل، افتح **PowerShell كمسؤول** داخل نفس المجلد:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Upgrade-Agent.ps1
Get-Service SentinelAgent
powershell -NoProfile -ExecutionPolicy Bypass -File .\Smoke-Test.ps1
```

هذا السكربت يستبدل ملفات الخدمة القديمة ويحتفظ بنسخة احتياطية منها، ولا يحذف ملفات الأدلة في `C:\ProgramData\SentinelDFIR`.

## إن لم تكن لديك خدمة سابقة

استبدل أمر `Upgrade-Agent.ps1` بأمر:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Install-Service.ps1
```

## أماكن المراقبة

- تبويب **Events & Alerts** يعرض أحداث النظام والتحذيرات مع المستوى والأسباب والتقنيات.
- تبويب **Network** يعرض العناوين والمنافذ وحالة TCP أو UDP ورقم PID لكل اتصال IPv4.
- تبويب **Autostart baseline** يعرض بعض مفاتيح التشغيل التلقائي ومجلدات Startup.
- تبويب **File/Entropy Inspector** يسمح باختيار ملف لحساب هاش SHA-256، والانتروبي لعينة، والتحقق من وجود شهادة مضمنة (دون تأكيد صلاحية التوقيع).
- جميع السجلات محلية افتراضياً في `C:\ProgramData\SentinelDFIR`.

## كيف نفهم التنبيهات؟

البرنامج لا يعرف تلقائيًا أن كل اتصال خارجي أو كل برنامج غير موقّع هو Backdoor. يعتمد على تراكم مؤشرات مستقلة، مثل ملف تنفيذي في AppData، واتصال خارجي متكرر، وتغيير مفتاح تشغيل تلقائي. حتى في هذه الحالة النتيجة **اشتباه يحتاج إلى تحليل** وليست حكمًا نهائيًا.

## معلومات مهمة

- ثبّت Sysmon من Microsoft بصورة مستقلة وفعّل قواعد أحداث مناسبة إذا أردت تفاصيل عمليات وDNS واتصالات أدق؛ المراقبة الافتراضية لـ Windows قد تفوّت نشاطًا سريعًا.
- لا يوجد حاليًا YARA-X مدمج أو تنفيذ كامل لقواعد Sigma أو تحليل AI حقيقي، ولا يوجد تحليل حزم مشفرة أو حماية ضد Kernel rootkits.
- لا تقم بإيقاف Defender. لا تشغّل هذه النسخة على جهاز حساس قبل اختبارها في VM؛ الكود الجديد لم يخضع إلى تجميع أو اختبار فعلي على Windows داخل هذه الجلسة.
