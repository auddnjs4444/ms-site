-- ============================================================
-- MEDISIGN 부원 전용 공간 — 데이터 구조와 권한 규칙
-- Supabase SQL Editor 에 통째로 붙여넣고 Run 하세요.
-- 여러 번 실행해도 안전하도록 작성했습니다.
-- ============================================================

-- ── 1. 부원 프로필 ──────────────────────────────────────────
-- 이메일과 비밀번호는 Supabase 인증(auth.users)이 관리합니다.
-- 비밀번호는 알아볼 수 없는 형태로 저장되며 우리도 원래 값을 알 수 없습니다.
create table if not exists public.members (
  id          uuid primary key references auth.users(id) on delete cascade,
  name        text not null check (length(btrim(name)) between 1 and 20),
  student_id  text not null unique check (student_id ~ '^[0-9]{8}$'),   -- 학번 8자리
  handle      text not null unique check (handle ~ '^[0-9A-Za-z가-힣]{2,16}$'), -- 닉네임
  role        text not null default 'member'  check (role   in ('member','officer')),
  status      text not null default 'pending' check (status in ('pending','approved','rejected')),
  created_at  timestamptz not null default now(),
  approved_at timestamptz
);

-- ── 2. 활동 기록 (자료실) ───────────────────────────────────
-- 작성자 이름은 handle(닉네임)만 남깁니다.
-- 이렇게 해두면 기록을 읽을 때 members 표를 볼 필요가 없어,
-- 이름·학번이 노출될 통로 자체가 생기지 않습니다.
create table if not exists public.records (
  id            bigint generated always as identity primary key,
  author_id     uuid references public.members(id) on delete set null,
  author_handle text not null,
  title         text not null check (length(btrim(title)) between 1 and 120),
  body          text not null,
  happened_on   date,
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now()
);
create index if not exists records_created_idx on public.records (created_at desc);

-- ── 3. 판별 함수 ────────────────────────────────────────────
-- members 규칙 안에서 members 를 다시 조회하면 무한 반복이 나므로
-- security definer 함수로 분리합니다.
create or replace function public.is_approved()
returns boolean language sql security definer stable set search_path = public as $$
  select exists (select 1 from public.members m
                 where m.id = auth.uid() and m.status = 'approved');
$$;

create or replace function public.is_officer()
returns boolean language sql security definer stable set search_path = public as $$
  select exists (select 1 from public.members m
                 where m.id = auth.uid() and m.role = 'officer' and m.status = 'approved');
$$;

-- ── 4. 권한 상승 차단 ───────────────────────────────────────
-- 부원이 스스로 role 이나 status 를 바꿔 임원이 되거나
-- 승인 상태로 만드는 것을 막습니다. 임원만 바꿀 수 있습니다.
create or replace function public.guard_member_columns()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if tg_op = 'INSERT' then
    -- 가입 시에는 무조건 일반 부원 + 승인 대기로 고정
    new.role := 'member';
    new.status := 'pending';
    new.approved_at := null;
    if new.id is distinct from auth.uid() then
      raise exception '본인 계정으로만 가입할 수 있습니다.';
    end if;
  else
    if (new.role is distinct from old.role or new.status is distinct from old.status)
       and not public.is_officer() then
      raise exception '권한 변경은 임원만 할 수 있습니다.';
    end if;
    if new.status = 'approved' and old.status <> 'approved' then
      new.approved_at := now();
    end if;
  end if;
  return new;
end;
$$;

drop trigger if exists members_guard on public.members;
create trigger members_guard before insert or update on public.members
  for each row execute function public.guard_member_columns();

-- 작성자 닉네임을 서버에서 채웁니다 (다른 사람 이름으로 못 쓰게)
create or replace function public.set_record_author()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  select m.id, m.handle into new.author_id, new.author_handle
  from public.members m where m.id = auth.uid() and m.status = 'approved';
  if new.author_handle is null then
    raise exception '승인된 부원만 기록을 쓸 수 있습니다.';
  end if;
  new.updated_at := now();
  return new;
end;
$$;

drop trigger if exists records_author on public.records;
create trigger records_author before insert on public.records
  for each row execute function public.set_record_author();

-- ── 5. 접근 규칙 (RLS) ──────────────────────────────────────
alter table public.members enable row level security;
alter table public.records enable row level security;

-- members: 본인 것만. 임원은 전체.
drop policy if exists members_select on public.members;
create policy members_select on public.members for select to authenticated
  using (id = auth.uid() or public.is_officer());

drop policy if exists members_insert on public.members;
create policy members_insert on public.members for insert to authenticated
  with check (id = auth.uid());

drop policy if exists members_update_self on public.members;
create policy members_update_self on public.members for update to authenticated
  using (id = auth.uid() or public.is_officer())
  with check (id = auth.uid() or public.is_officer());

drop policy if exists members_delete on public.members;
create policy members_delete on public.members for delete to authenticated
  using (public.is_officer());

-- records: 승인된 부원만 읽기/쓰기. 수정·삭제는 본인 글 또는 임원.
drop policy if exists records_select on public.records;
create policy records_select on public.records for select to authenticated
  using (public.is_approved());

drop policy if exists records_insert on public.records;
create policy records_insert on public.records for insert to authenticated
  with check (public.is_approved());

drop policy if exists records_update on public.records;
create policy records_update on public.records for update to authenticated
  using (author_id = auth.uid() or public.is_officer())
  with check (author_id = auth.uid() or public.is_officer());

drop policy if exists records_delete on public.records;
create policy records_delete on public.records for delete to authenticated
  using (author_id = auth.uid() or public.is_officer());

-- ── 6. 로그인하지 않은 사람은 아무것도 볼 수 없게 ───────────
revoke all on public.members from anon;
revoke all on public.records from anon;

-- ── 7. 임원 지정 ────────────────────────────────────────────
-- 아래 줄은 해당 이메일로 "가입을 마친 뒤에" 실행하세요.
-- update public.members set role='officer', status='approved'
--   where id = (select id from auth.users where email = 'auddnjs4444@gmail.com');
