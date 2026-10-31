-- شغّل هذا التحديث مرة واحدة من Supabase SQL Editor قبل استخدام النسخة الجديدة.
-- يضيف حقولاً مستقلة للقطعة الأصلية والبديل، ويحافظ على البيانات القديمة.
alter table public.parts add column if not exists original_model text;
alter table public.parts add column if not exists replacement_name text;
alter table public.parts add column if not exists replacement_code text;

-- ترحيل السجلات القديمة: الاسم القديم يُستخدم مؤقتاً كاسم بديل.
update public.parts
set replacement_name = coalesce(nullif(replacement_name, ''), name),
    original_model = coalesce(nullif(original_model, ''), name)
where replacement_name is null or original_model is null;

-- لا تغيّر سياسات RLS الحالية. تأكد أن سياسات القراءة تسمح للمستخدم المسجل
-- وسياسات الإضافة والتعديل والحذف تسمح للمدير فقط.
