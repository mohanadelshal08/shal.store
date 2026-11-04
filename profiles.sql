-- ============================================================
-- profiles.sql — بروفايل لكل يوزر + دور (مالك / موظف) + اسم الكاشير على الفاتورة
-- شغّله مرة واحدة: Supabase → SQL Editor → الصق الملف كله → Run
-- ممكن تشغّله تاني بأمان (كل حاجة فيه idempotent).
-- ============================================================

-- 1) جدول البروفايلات (صف لكل حساب في Authentication)
create table if not exists public.profiles (
  id         uuid primary key references auth.users(id) on delete cascade,
  email      text,
  name       text not null default '',
  phone      text not null default '',
  avatar     text,                                   -- صورة صغيرة مخزنة كـ data URL
  role       text not null default 'employee' check (role in ('owner','employee')),
  created_at timestamptz not null default now()
);

alter table public.profiles enable row level security;

-- دور اليوزر الحالي (security definer علشان ما يحصلش recursion مع الـ RLS)
create or replace function public.my_role() returns text
language sql stable security definer set search_path = public as $$
  select role from public.profiles where id = auth.uid()
$$;

-- 2) سياسات الـ RLS
drop policy if exists profiles_select on public.profiles;
create policy profiles_select on public.profiles for select to authenticated
  using (id = auth.uid() or public.my_role() = 'owner');

drop policy if exists profiles_insert_self on public.profiles;
create policy profiles_insert_self on public.profiles for insert to authenticated
  with check (id = auth.uid() and role = 'employee');

drop policy if exists profiles_update on public.profiles;
create policy profiles_update on public.profiles for update to authenticated
  using (id = auth.uid() or public.my_role() = 'owner')
  with check (id = auth.uid() or public.my_role() = 'owner');

grant select, insert, update on public.profiles to authenticated;

-- 3) حماية الحقول: الإيميل والـ id ثابتين، والدور ما يتغيّرش غير بالمالك،
--    ولازم يفضل مالك واحد على الأقل
create or replace function public.profiles_guard() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  new.id         := old.id;
  new.email      := old.email;
  new.created_at := old.created_at;
  -- auth.uid() بيبقى null لما الأمر يتشغّل من SQL Editor، وده مسموح له
  if auth.uid() is not null and coalesce(public.my_role(), '') <> 'owner' then
    new.role := old.role;
  end if;
  if old.role = 'owner' and new.role <> 'owner'
     and not exists (select 1 from public.profiles where role = 'owner' and id <> old.id) then
    raise exception 'LASTOWNER';
  end if;
  return new;
end $$;

drop trigger if exists profiles_guard_trg on public.profiles;
create trigger profiles_guard_trg before update on public.profiles
  for each row execute function public.profiles_guard();

-- 4) أي حساب جديد يتعمله بروفايل أوتوماتيك (أول حساب = مالك، الباقي = موظف)
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, email, name, role)
  values (
    new.id, new.email, split_part(coalesce(new.email, ''), '@', 1),
    case when exists (select 1 from public.profiles where role = 'owner') then 'employee' else 'owner' end
  )
  on conflict (id) do nothing;
  return new;
end $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- 5) الحسابات الموجودة بالفعل: اعمل لهم بروفايل، وأقدم حساب يبقى المالك
insert into public.profiles (id, email, name, role)
select u.id, u.email, split_part(coalesce(u.email, ''), '@', 1), 'employee'
from auth.users u
on conflict (id) do nothing;

update public.profiles set role = 'owner'
where id = (select id from auth.users order by created_at limit 1)
  and not exists (select 1 from public.profiles where role = 'owner');

-- لو المالك مش هو أقدم حساب، صحّحه بإيميله:
--   update public.profiles set role = 'owner'    where email = 'your@email.com';
--   update public.profiles set role = 'employee' where email = 'other@email.com';

-- 6) اسم الكاشير على الفاتورة (بيتسجل أوتوماتيك من الحساب اللي عمل الفاتورة)
alter table public.invoices
  add column if not exists cashier    text,
  add column if not exists cashier_id uuid;

create or replace function public.stamp_invoice_cashier() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if new.cashier is null and new.cashier_id is null and auth.uid() is not null then
    new.cashier_id := auth.uid();
    new.cashier := coalesce((select nullif(name, '') from public.profiles where id = auth.uid()), '');
  end if;
  return new;
end $$;

drop trigger if exists invoices_stamp_cashier on public.invoices;
create trigger invoices_stamp_cashier before insert on public.invoices
  for each row execute function public.stamp_invoice_cashier();
