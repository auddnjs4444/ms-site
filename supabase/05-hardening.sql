-- ============================================================
-- 05. 자체 점검에서 찾은 구멍 두 개 막기
--
-- (1) 부원이 승인받은 뒤 자기 이름·학번을 스스로 바꿀 수 있었습니다.
--     임원이 명단과 대조해 승인한 의미가 없어지므로 막습니다.
--     닉네임은 그대로 본인이 바꿀 수 있습니다.
--
-- (2) 닉네임 중복 검사가 가입 때는 대소문자를 무시했는데
--     표 제약은 대소문자를 구분해서, 나중에 닉네임을 바꿀 때
--     'Nick' / 'nick' 처럼 비슷한 이름으로 사칭이 가능했습니다.
-- ============================================================

-- ── (1) 이름·학번은 임원만 바꿀 수 있게 ─────────────────────
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
    -- auth.uid() 가 있으면 웹에서 온 요청입니다. 임원이 아니면 아래를 막습니다.
    if auth.uid() is not null and not public.is_officer() then
      if new.role is distinct from old.role or new.status is distinct from old.status then
        raise exception '권한 변경은 임원만 할 수 있습니다.';
      end if;
      if new.name is distinct from old.name then
        raise exception '이름은 임원만 바꿀 수 있습니다. 임원에게 문의해 주세요.';
      end if;
      if new.student_id is distinct from old.student_id then
        raise exception '학번은 임원만 바꿀 수 있습니다. 임원에게 문의해 주세요.';
      end if;
    end if;
    if new.status = 'approved' and old.status <> 'approved' then
      new.approved_at := now();
    end if;
  end if;
  return new;
end;
$$;

-- ── (2) 닉네임을 대소문자 구분 없이 유일하게 ────────────────
-- 이미 겹치는 닉네임이 있으면 이 명령이 실패합니다.
-- 그 경우 오류에 나온 닉네임을 임원이 먼저 정리한 뒤 다시 실행하세요.
drop index if exists public.members_handle_lower_idx;
create unique index members_handle_lower_idx on public.members (lower(handle));

-- ── 확인 ────────────────────────────────────────────────────
select m.name, m.handle, m.role, m.status from public.members m order by m.created_at;
