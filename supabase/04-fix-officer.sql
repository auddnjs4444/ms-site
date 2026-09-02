-- ============================================================
-- 04. 첫 임원을 지정할 수 없던 문제 수정
--
-- 문제: '등급 변경은 임원만' 규칙 때문에 첫 임원을 만들 수 없었습니다.
--       SQL 편집기에서 실행하면 로그인 사용자가 아니라 규칙에 걸립니다.
-- 해결: 로그인 사용자가 없는 경우(= 관리자가 직접 실행)는 통과시킵니다.
--       웹에서 오는 요청은 항상 로그인 사용자가 있으므로 규칙이 그대로 적용되고,
--       로그인하지 않은 사람은 애초에 이 표에 접근 권한이 없습니다.
-- ============================================================

create or replace function public.guard_member_columns()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if tg_op = 'INSERT' then
    new.role := 'member';
    new.status := 'pending';
    new.approved_at := null;
    if auth.uid() is not null and new.id is distinct from auth.uid() then
      raise exception '본인 계정으로만 가입할 수 있습니다.';
    end if;
  else
    -- auth.uid() 가 있다는 건 웹에서 온 요청이라는 뜻입니다. 그때만 임원인지 확인합니다.
    if (new.role is distinct from old.role or new.status is distinct from old.status)
       and auth.uid() is not null
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

-- ── 첫 임원 지정 ────────────────────────────────────────────
update public.members set role = 'officer', status = 'approved'
  where id = (select id from auth.users where email = 'auddnjs4444@naver.com');

-- ── 결과 확인 ───────────────────────────────────────────────
select m.name, m.handle, m.role, m.status, u.email
  from public.members m join auth.users u on u.id = m.id;
