-- ============================================================
-- 03. 닉네임에 한글 허용
-- 기존 규칙은 영문·숫자만 받았습니다. 한글도 받도록 바꿉니다.
-- 여러 번 실행해도 안전합니다.
-- ============================================================

-- ── 1. 표 자체의 형식 규칙 교체 ─────────────────────────────
-- 제약 이름이 자동 생성이라 이름을 찾아서 지운 뒤 새로 겁니다.
do $$
declare c record;
begin
  for c in
    select con.conname
    from pg_constraint con
    join pg_class rel on rel.oid = con.conrelid
    join pg_namespace ns on ns.oid = rel.relnamespace
    where ns.nspname='public' and rel.relname='members'
      and con.contype='c'
      and pg_get_constraintdef(con.oid) like '%handle%'
  loop
    execute format('alter table public.members drop constraint %I', c.conname);
  end loop;
end $$;

alter table public.members
  add constraint members_handle_check
  check (handle ~ '^[0-9A-Za-z가-힣]{2,16}$');

-- ── 2. 가입 트리거의 검사도 같이 바꿉니다 ───────────────────
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
declare
  v_name   text := btrim(coalesce(new.raw_user_meta_data->>'name',''));
  v_sid    text := btrim(coalesce(new.raw_user_meta_data->>'student_id',''));
  v_handle text := btrim(coalesce(new.raw_user_meta_data->>'handle',''));
begin
  if v_name = '' or v_sid = '' or v_handle = '' then
    raise exception '이름·학번·닉네임을 모두 입력해 주세요.';
  end if;
  if v_sid !~ '^[0-9]{8}$' then
    raise exception '학번은 8자리 숫자여야 합니다.';
  end if;
  if v_handle !~ '^[0-9A-Za-z가-힣]{2,16}$' then
    raise exception '닉네임은 한글·영문·숫자 2~16자여야 합니다.';
  end if;
  if exists (select 1 from public.members m where m.student_id = v_sid) then
    raise exception '이미 등록된 학번입니다.';
  end if;
  if exists (select 1 from public.members m where lower(m.handle) = lower(v_handle)) then
    raise exception '이미 사용 중인 닉네임입니다.';
  end if;

  insert into public.members (id, name, student_id, handle)
  values (new.id, v_name, v_sid, v_handle);
  return new;
end;
$$;
