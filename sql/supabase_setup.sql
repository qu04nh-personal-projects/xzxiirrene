-- =====================================================================
--  Cây thông gửi lời chúc · thiết lập Supabase
--  Cách dùng: Supabase Dashboard → SQL Editor → New query → dán toàn bộ
--  file này → ĐỔI MẬT KHẨU ở dòng "DOI_MAT_KHAU_CUA_BAN" → Run.
-- =====================================================================

create extension if not exists pgcrypto with schema extensions;

-- 1) Bảng lưu thư --------------------------------------------------------
create table if not exists public.wishes (
  id          uuid primary key default gen_random_uuid(),
  name        text not null check (char_length(btrim(name)) between 1 and 40),
  icon        text not null default '💌' check (char_length(icon) between 1 and 8),
  message     text not null check (char_length(btrim(message)) between 1 and 1000),
  created_at  timestamptz not null default now()
);

-- Bật RLS và KHÔNG tạo policy nào → trình duyệt không thể đọc/ghi trực tiếp.
-- Mọi thao tác đều đi qua các hàm bên dưới.
-- (nếu bạn đã chạy bản cũ chưa có cột icon thì dòng này sẽ thêm vào)
alter table public.wishes add column if not exists icon text not null default '💌';

alter table public.wishes enable row level security;

-- 2) Bảng cấu hình (chứa mã băm của mật khẩu quản trị) -------------------
create table if not exists public.app_config (
  key   text primary key,
  value text not null
);
alter table public.app_config enable row level security;

insert into public.app_config (key, value)
values ('admin_password_hash', extensions.crypt('DOI_MAT_KHAU_CUA_BAN', extensions.gen_salt('bf')))
on conflict (key) do update set value = excluded.value;

-- Xóa các hàm bản cũ (nếu có) để tạo lại với cột icon
drop function if exists public.send_wish(text, text);
drop function if exists public.list_wish_names();
drop function if exists public.admin_list_wishes(text);

-- 3) Bạn bè gửi thư ------------------------------------------------------
create or replace function public.send_wish(p_name text, p_message text, p_icon text default '💌')
returns void
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_recent int;
begin
  if p_name is null or char_length(btrim(p_name)) = 0 or char_length(p_name) > 40 then
    raise exception 'Tên phải có từ 1 đến 40 ký tự';
  end if;
  if p_message is null or char_length(btrim(p_message)) = 0 or char_length(p_message) > 1000 then
    raise exception 'Lời chúc phải có từ 1 đến 1000 ký tự';
  end if;
  if p_icon is not null and char_length(p_icon) > 8 then
    raise exception 'Icon không hợp lệ';
  end if;

  -- chống spam đơn giản: tối đa 30 thư mỗi phút trên toàn trang
  select count(*) into v_recent from public.wishes where created_at > now() - interval '1 minute';
  if v_recent >= 30 then
    raise exception 'Đang có quá nhiều thư, thử lại sau ít phút nhé';
  end if;

  insert into public.wishes (name, message, icon)
  values (btrim(p_name), btrim(p_message), coalesce(nullif(btrim(p_icon), ''), '💌'));
end;
$$;

-- 4) Danh sách TÊN (không có nội dung) để hiện trên thư rơi --------------
create or replace function public.list_wish_names()
returns table (id uuid, name text, icon text)
language sql
security definer
set search_path = public
as $$
  select w.id, w.name, w.icon from public.wishes w order by w.created_at desc limit 300;
$$;

-- 5) Quản trị: đọc toàn bộ thư (cần mật khẩu) ----------------------------
create or replace function public.admin_list_wishes(p_password text)
returns table (id uuid, name text, icon text, message text, created_at timestamptz)
language plpgsql
security definer
set search_path = public, extensions
as $$
begin
  if not exists (
    select 1 from public.app_config c
    where c.key = 'admin_password_hash'
      and c.value = extensions.crypt(coalesce(p_password, ''), c.value)
  ) then
    perform pg_sleep(1);   -- làm chậm việc đoán mật khẩu
    raise exception 'Sai mật khẩu';
  end if;

  return query
    select w.id, w.name, w.icon, w.message, w.created_at
    from public.wishes w
    order by w.created_at desc;
end;
$$;

-- 6) Quản trị: xóa một thư (cần mật khẩu) --------------------------------
create or replace function public.admin_delete_wish(p_password text, p_id uuid)
returns void
language plpgsql
security definer
set search_path = public, extensions
as $$
begin
  if not exists (
    select 1 from public.app_config c
    where c.key = 'admin_password_hash'
      and c.value = extensions.crypt(coalesce(p_password, ''), c.value)
  ) then
    perform pg_sleep(1);
    raise exception 'Sai mật khẩu';
  end if;

  delete from public.wishes where id = p_id;
end;
$$;

-- 7) Cho phép trình duyệt (anon) gọi 4 hàm trên --------------------------
revoke all on function public.send_wish(text, text, text)        from public;
revoke all on function public.list_wish_names()                  from public;
revoke all on function public.admin_list_wishes(text)            from public;
revoke all on function public.admin_delete_wish(text, uuid)      from public;

grant execute on function public.send_wish(text, text, text)     to anon, authenticated;
grant execute on function public.list_wish_names()               to anon, authenticated;
grant execute on function public.admin_list_wishes(text)         to anon, authenticated;
grant execute on function public.admin_delete_wish(text, uuid)   to anon, authenticated;

-- Muốn đổi mật khẩu sau này, chạy:
-- update public.app_config
--   set value = extensions.crypt('MAT_KHAU_MOI', extensions.gen_salt('bf'))
--   where key = 'admin_password_hash';
