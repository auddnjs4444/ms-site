-- ============================================================
-- 02. 가입 처리 보완
-- 계정이 만들어질 때 프로필(이름·학번·표시이름)도 함께 만들어 줍니다.
-- 이메일 인증을 켜두어 가입 직후 로그인 상태가 아니어도 안전하게 저장됩니다.
-- 이 파일도 여러 번 실행해도 괜찮습니다.
-- ============================================================

-- ── 1. 권한 상승 차단 규칙 보완 ─────────────────────────────
-- 아래 2번의 자동 생성은 로그인 이전에 일어나므로 auth.uid() 가 비어 있습니다.
-- 그 경우까지 막아버리면 가입 자체가 실패하므로, 사용자가 직접 넣는 경우에만 확인합니다.
-- (API 를 통한 입력은 members_insert 규칙이 id = auth.uid() 를 이미 강제합니다)
create or replace function public.guard_member_columns()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if tg_op = 'INSERT' then
    new.role := 'member';        -- 가입 시엔 무조건 일반 부원
    new.status := 'pending';     -- 무조건 승인 대기
    new.approved_at := null;
    if auth.uid() is not null and new.id is distinct from auth.uid() then
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

-- ── 2. 계정 생성 시 프로필 자동 생성 ────────────────────────
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
declare
  v_name  text := btrim(coalesce(new.raw_user_meta_data->>'name',''));
  v_sid   text := btrim(coalesce(new.raw_user_meta_data->>'student_id',''));
  v_handle text := btrim(coalesce(new.raw_user_meta_data->>'handle',''));
begin
  if v_name = '' or v_sid = '' or v_handle = '' then
    raise exception '이름·학번·표시 이름을 모두 입력해 주세요.';
  end if;
  if v_sid !~ '^[0-9]{8}$' then
    raise exception '학번은 8자리 숫자여야 합니다.';
  end if;
  if v_handle !~ '^[A-Za-z0-9]{2,16}$' then
    raise exception '표시 이름은 영문·숫자 2~16자여야 합니다.';
  end if;
  if exists (select 1 from public.members m where m.student_id = v_sid) then
    raise exception '이미 등록된 학번입니다.';
  end if;
  if exists (select 1 from public.members m where lower(m.handle) = lower(v_handle)) then
    raise exception '이미 사용 중인 표시 이름입니다.';
  end if;

  insert into public.members (id, name, student_id, handle)
  values (new.id, v_name, v_sid, v_handle);
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- ── 3. 계정이 지워지면 프로필도 함께 정리 ───────────────────
-- (members.id 가 auth.users(id) 를 on delete cascade 로 참조하므로 자동 처리됩니다)
