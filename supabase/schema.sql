-- Gold & Glory database setup. Run once in Supabase SQL Editor.
create extension if not exists pgcrypto;

create table if not exists public.characters (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  name_normalized text generated always as (lower(btrim(name))) stored,
  password_hash text not null,
  sheet jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  deleted_at timestamptz
);
drop index if exists public.characters_name_normalized_key;
create unique index if not exists characters_name_normalized_active_key on public.characters(name_normalized) where deleted_at is null;

create table if not exists public.app_settings (
  key text primary key,
  value text not null
);
create table if not exists public.sessions (
  token uuid primary key default gen_random_uuid(),
  character_id uuid references public.characters(id) on delete cascade,
  is_host boolean not null default false,
  created_at timestamptz not null default now()
);
alter table public.characters enable row level security;
alter table public.app_settings enable row level security;
alter table public.sessions enable row level security;
-- No direct browser table access. All access goes through security-definer RPCs.
revoke all on public.characters, public.app_settings, public.sessions from anon, authenticated;

-- CHANGE THIS before running, or update the value afterward.
insert into public.app_settings(key,value) values ('host_password_hash',crypt('CHANGE_ME_HOST_PASSWORD',gen_salt('bf')))
on conflict(key) do nothing;

create or replace function public.create_character(p_name text,p_password text)
returns jsonb language plpgsql security definer set search_path=public,extensions as $$
declare c public.characters; t uuid;
begin
 if btrim(coalesce(p_name,''))='' or coalesce(p_password,'')='' then return jsonb_build_object('ok',false,'error','Name and password are required.'); end if;
 if exists(select 1 from public.characters where name_normalized=lower(btrim(p_name)) and deleted_at is null) then return jsonb_build_object('ok',false,'error','That character name already exists.'); end if;
 insert into public.characters(name,password_hash,sheet) values(btrim(p_name),crypt(p_password,gen_salt('bf')),
 '{"resources":[{"name":"HP","current":30,"max":30},{"name":"Ward","current":0,"max":0},{"name":"Mana","current":10,"max":10},{"name":"Armor","current":0,"max":null},{"name":"Accuracy","current":0,"max":null},{"name":"Evasion","current":0,"max":null}],"attributes":{"Strength":10,"Attunement":10,"Dexterity":10,"Speed":10,"Fortitude":10,"Willpower":10,"Luck":1},"items":[],"loot":[],"weaponXp":[],"skills":[],"notes":"","maxHpBonus":0,"maxManaBonus":0}'::jsonb) returning * into c;
 insert into public.sessions(character_id) values(c.id) returning token into t;
 return jsonb_build_object('ok',true,'character_id',c.id,'token',t);
exception when unique_violation then return jsonb_build_object('ok',false,'error','That character name already exists.');
end $$;

create or replace function public.open_character(p_name text,p_password text)
returns jsonb language plpgsql security definer set search_path=public,extensions as $$
declare c public.characters; t uuid;
begin
 select * into c from public.characters where name_normalized=lower(btrim(p_name)) and deleted_at is null;
 if c.id is null or c.password_hash<>crypt(p_password,c.password_hash) then return jsonb_build_object('ok',false,'error','Character name or password is incorrect.'); end if;
 insert into public.sessions(character_id) values(c.id) returning token into t;
 return jsonb_build_object('ok',true,'character_id',c.id,'token',t);
end $$;

create or replace function public.get_character(p_character_id uuid,p_token uuid)
returns jsonb language plpgsql security definer set search_path=public as $$
declare c public.characters;
begin
 if not exists(select 1 from public.sessions where token=p_token and character_id=p_character_id and not is_host) then return jsonb_build_object('ok',false); end if;
 select * into c from public.characters where id=p_character_id and deleted_at is null;
 return jsonb_build_object('ok',true,'character',jsonb_build_object('id',c.id,'name',c.name,'sheet',c.sheet,'updated_at',c.updated_at));
end $$;

create or replace function public.save_character(p_character_id uuid,p_token uuid,p_sheet jsonb)
returns jsonb language plpgsql security definer set search_path=public as $$
declare u timestamptz;
begin
 if not exists(select 1 from public.sessions where token=p_token and character_id=p_character_id and not is_host) then return jsonb_build_object('ok',false); end if;
 update public.characters set sheet=p_sheet,updated_at=now() where id=p_character_id and deleted_at is null returning updated_at into u;
 return jsonb_build_object('ok',true,'updated_at',u);
end $$;

create or replace function public.host_login(p_password text)
returns jsonb language plpgsql security definer set search_path=public,extensions as $$
declare h text;t uuid;
begin
 select value into h from public.app_settings where key='host_password_hash';
 if h is null or h<>crypt(p_password,h) then return jsonb_build_object('ok',false,'error','Incorrect host password.'); end if;
 insert into public.sessions(is_host) values(true) returning token into t;
 return jsonb_build_object('ok',true,'token',t);
end $$;

create or replace function public.host_list_characters(p_token uuid)
returns jsonb language plpgsql security definer set search_path=public as $$
begin
 if not exists(select 1 from public.sessions where token=p_token and is_host) then return jsonb_build_object('ok',false); end if;
 return jsonb_build_object('ok',true,'characters',coalesce((select jsonb_agg(jsonb_build_object('id',id,'name',name,'updated_at',updated_at) order by updated_at desc) from public.characters where deleted_at is null),'[]'::jsonb));
end $$;

create or replace function public.host_get_character(p_token uuid,p_character_id uuid)
returns jsonb language plpgsql security definer set search_path=public as $$
declare c public.characters;
begin
 if not exists(select 1 from public.sessions where token=p_token and is_host) then return jsonb_build_object('ok',false); end if;
 select * into c from public.characters where id=p_character_id;
 if c.id is null then return jsonb_build_object('ok',false); end if;
 return jsonb_build_object('ok',true,'character',jsonb_build_object('id',c.id,'name',c.name,'sheet',c.sheet,'updated_at',c.updated_at));
end $$;

create or replace function public.host_delete_character(p_token uuid,p_character_id uuid)
returns jsonb language plpgsql security definer set search_path=public as $
begin
 if not exists(select 1 from public.sessions where token=p_token and is_host) then return jsonb_build_object('ok',false); end if;
 update public.characters set deleted_at=now(),updated_at=now() where id=p_character_id and deleted_at is null;
 delete from public.sessions where character_id=p_character_id and not is_host;
 return jsonb_build_object('ok',true);
end $;

-- Run periodically if desired; soft-deleted characters remain recoverable for 30 days.
create or replace function public.purge_deleted_characters()
returns integer language plpgsql security definer set search_path=public as $
declare n integer;
begin
 delete from public.characters where deleted_at is not null and deleted_at < now()-interval '30 days';
 get diagnostics n = row_count;
 return n;
end $;


create table if not exists public.initiative_state (
 id integer primary key default 1 check(id=1),
 active boolean not null default false,
 started boolean not null default false,
 round integer not null default 1,
 turn_index integer not null default 0,
 entries jsonb not null default '[]'::jsonb,
 updated_at timestamptz not null default now()
);
insert into public.initiative_state(id) values(1) on conflict(id) do nothing;
alter table public.initiative_state enable row level security;
revoke all on public.initiative_state from anon,authenticated;

create or replace function public.host_get_initiative(p_token uuid) returns jsonb language plpgsql security definer set search_path=public as $
declare s public.initiative_state;
begin
 if not exists(select 1 from sessions where token=p_token and is_host) then return jsonb_build_object('ok',false); end if;
 select * into s from initiative_state where id=1;
 return jsonb_build_object('ok',true,'initiative',jsonb_build_object('active',s.active,'started',s.started,'round',s.round,'turn_index',s.turn_index,'entries',s.entries));
end $;

create or replace function public.player_get_initiative(p_token uuid,p_character_id uuid) returns jsonb language plpgsql security definer set search_path=public as $
declare s public.initiative_state;
begin
 if not exists(select 1 from sessions where token=p_token and character_id=p_character_id and not is_host) then return jsonb_build_object('ok',false); end if;
 select * into s from initiative_state where id=1;
 if not s.active or not exists(select 1 from jsonb_array_elements(s.entries) e where e->>'type'='player' and e->>'id'=p_character_id::text) then return jsonb_build_object('ok',true,'initiative',jsonb_build_object('active',false)); end if;
 return jsonb_build_object('ok',true,'initiative',jsonb_build_object('active',s.active,'started',s.started,'round',s.round,'turn_index',s.turn_index,'entries',s.entries));
end $;

create or replace function public.host_start_initiative(p_token uuid,p_players jsonb) returns jsonb language plpgsql security definer set search_path=public as $
declare e jsonb;
begin
 if not exists(select 1 from sessions where token=p_token and is_host) then return jsonb_build_object('ok',false); end if;
 select coalesce(jsonb_agg(jsonb_build_object('key','p:'||(x->>'id'),'id',x->>'id','name',x->>'name','type','player','roll',null)),'[]'::jsonb) into e from jsonb_array_elements(p_players) x;
 update initiative_state set active=true,started=false,round=1,turn_index=0,entries=e,updated_at=now() where id=1;
 return jsonb_build_object('ok',true);
end $;

create or replace function public.host_set_initiative_roll(p_token uuid,p_key text,p_roll integer) returns jsonb language plpgsql security definer set search_path=public as $
begin
 if not exists(select 1 from sessions where token=p_token and is_host) then return jsonb_build_object('ok',false); end if;
 update initiative_state set entries=(select jsonb_agg(case when e->>'key'=p_key then jsonb_set(e,'{roll}',to_jsonb(p_roll),true) else e end order by coalesce((case when e->>'key'=p_key then p_roll else (e->>'roll')::int end),-999) desc) from jsonb_array_elements(entries) e),turn_index=0,updated_at=now() where id=1;
 return jsonb_build_object('ok',true);
end $;

create or replace function public.host_add_initiative_npc(p_token uuid,p_name text,p_roll integer) returns jsonb language plpgsql security definer set search_path=public as $
begin
 if not exists(select 1 from sessions where token=p_token and is_host) then return jsonb_build_object('ok',false); end if;
 update initiative_state set entries=entries||jsonb_build_array(jsonb_build_object('key','n:'||gen_random_uuid()::text,'name',btrim(p_name),'type','npc','roll',p_roll)),updated_at=now() where id=1;
 return jsonb_build_object('ok',true);
end $;

create or replace function public.host_remove_initiative_entry(p_token uuid,p_key text) returns jsonb language plpgsql security definer set search_path=public as $
begin
 if not exists(select 1 from sessions where token=p_token and is_host) then return jsonb_build_object('ok',false); end if;
 update initiative_state set entries=(select coalesce(jsonb_agg(e),'[]'::jsonb) from jsonb_array_elements(entries) e where e->>'key'<>p_key),turn_index=0,updated_at=now() where id=1;
 return jsonb_build_object('ok',true);
end $;

create or replace function public.host_begin_initiative(p_token uuid) returns jsonb language plpgsql security definer set search_path=public as $
begin
 if not exists(select 1 from sessions where token=p_token and is_host) then return jsonb_build_object('ok',false); end if;
 update initiative_state set entries=(select coalesce(jsonb_agg(e order by coalesce((e->>'roll')::int,-999) desc),'[]'::jsonb) from jsonb_array_elements(entries)e),started=true,round=1,turn_index=0,updated_at=now() where id=1;
 return jsonb_build_object('ok',true);
end $;

create or replace function public.host_next_turn(p_token uuid) returns jsonb language plpgsql security definer set search_path=public as $
declare n int;i int;r int;
begin
 if not exists(select 1 from sessions where token=p_token and is_host) then return jsonb_build_object('ok',false); end if;
 select jsonb_array_length(entries),turn_index,round into n,i,r from initiative_state where id=1;
 if n>0 then if i+1>=n then i:=0;r:=r+1; else i:=i+1; end if; end if;
 update initiative_state set turn_index=i,round=r,updated_at=now() where id=1;
 return jsonb_build_object('ok',true);
end $;

create or replace function public.host_previous_turn(p_token uuid) returns jsonb language plpgsql security definer set search_path=public as $
declare n int;i int;r int;
begin
 if not exists(select 1 from sessions where token=p_token and is_host) then return jsonb_build_object('ok',false); end if;
 select jsonb_array_length(entries),turn_index,round into n,i,r from initiative_state where id=1;
 if n>0 then if i<=0 then i:=n-1;r:=greatest(1,r-1); else i:=i-1; end if; end if;
 update initiative_state set turn_index=i,round=r,updated_at=now() where id=1;
 return jsonb_build_object('ok',true);
end $;

create or replace function public.host_end_initiative(p_token uuid) returns jsonb language plpgsql security definer set search_path=public as $
begin
 if not exists(select 1 from sessions where token=p_token and is_host) then return jsonb_build_object('ok',false); end if;
 update initiative_state set active=false,started=false,round=1,turn_index=0,entries='[]'::jsonb,updated_at=now() where id=1;
 return jsonb_build_object('ok',true);
end $;

grant execute on function public.host_get_initiative(uuid) to anon,authenticated;
grant execute on function public.player_get_initiative(uuid,uuid) to anon,authenticated;
grant execute on function public.host_start_initiative(uuid,jsonb) to anon,authenticated;
grant execute on function public.host_set_initiative_roll(uuid,text,integer) to anon,authenticated;
grant execute on function public.host_add_initiative_npc(uuid,text,integer) to anon,authenticated;
grant execute on function public.host_remove_initiative_entry(uuid,text) to anon,authenticated;
grant execute on function public.host_begin_initiative(uuid) to anon,authenticated;
grant execute on function public.host_next_turn(uuid) to anon,authenticated;
grant execute on function public.host_previous_turn(uuid) to anon,authenticated;
grant execute on function public.host_end_initiative(uuid) to anon,authenticated;

create or replace function public.host_reset_character_password(p_token uuid,p_character_id uuid,p_new_password text)
returns jsonb language plpgsql security definer set search_path=public,extensions as $
begin
 if not exists(select 1 from public.sessions where token=p_token and is_host) then return jsonb_build_object('ok',false); end if;
 if coalesce(p_new_password,'')='' then return jsonb_build_object('ok',false,'error','Password is required.'); end if;
 update public.characters set password_hash=crypt(p_new_password,gen_salt('bf')),updated_at=now() where id=p_character_id and deleted_at is null;
 if not found then return jsonb_build_object('ok',false,'error','Character not found.'); end if;
 delete from public.sessions where character_id=p_character_id and not is_host;
 return jsonb_build_object('ok',true);
end $;

grant execute on function public.host_reset_character_password(uuid,uuid,text) to anon,authenticated;

grant execute on function public.create_character(text,text) to anon,authenticated;
grant execute on function public.open_character(text,text) to anon,authenticated;
grant execute on function public.get_character(uuid,uuid) to anon,authenticated;
grant execute on function public.save_character(uuid,uuid,jsonb) to anon,authenticated;
grant execute on function public.host_login(text) to anon,authenticated;
grant execute on function public.host_list_characters(uuid) to anon,authenticated;
grant execute on function public.host_get_character(uuid,uuid) to anon,authenticated;
grant execute on function public.host_delete_character(uuid,uuid) to anon,authenticated;

-- Enable characters in Database > Replication / Realtime publication if not already enabled:
alter publication supabase_realtime add table public.characters;
