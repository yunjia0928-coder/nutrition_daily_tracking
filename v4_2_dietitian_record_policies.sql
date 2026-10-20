-- V4.2: permit dietitians to create/correct daily entries for assigned clients.
-- Run once in Supabase SQL Editor on the same project used by the website.
-- These policies do not grant access to unassigned clients; RLS still scopes access by auth.uid().

grant select, insert, update on table public.daily_entries to authenticated;
grant select, insert, update on table public.entry_reviews to authenticated;

alter table public.daily_entries enable row level security;
alter table public.entry_reviews enable row level security;

-- Dietitians must be able to read relationship rows so the policies below can
-- verify that the target client is assigned to auth.uid(). Existing policies
-- are permissive (OR-combined), so this adds the missing dietitian path safely.
grant select on table public.dietitian_clients to authenticated;
alter table public.dietitian_clients enable row level security;

drop policy if exists "v42_users_read_own_relationships" on public.dietitian_clients;
create policy "v42_users_read_own_relationships"
on public.dietitian_clients
for select
to authenticated
using (
  client_id = auth.uid()
  or dietitian_id = auth.uid()
);

drop policy if exists "v42_dietitian_select_assigned_daily_entries" on public.daily_entries;
create policy "v42_dietitian_select_assigned_daily_entries"
on public.daily_entries
for select
to authenticated
using (
  exists (
    select 1
    from public.dietitian_clients dc
    join public.profiles me on me.id = auth.uid()
    where dc.dietitian_id = auth.uid()
      and dc.client_id = daily_entries.client_id
      and me.role = 'dietitian'
  )
);

drop policy if exists "v42_dietitian_insert_assigned_daily_entries" on public.daily_entries;
create policy "v42_dietitian_insert_assigned_daily_entries"
on public.daily_entries
for insert
to authenticated
with check (
  exists (
    select 1
    from public.dietitian_clients dc
    join public.profiles me on me.id = auth.uid()
    where dc.dietitian_id = auth.uid()
      and dc.client_id = daily_entries.client_id
      and me.role = 'dietitian'
  )
);

drop policy if exists "v42_dietitian_update_assigned_daily_entries" on public.daily_entries;
create policy "v42_dietitian_update_assigned_daily_entries"
on public.daily_entries
for update
to authenticated
using (
  exists (
    select 1
    from public.dietitian_clients dc
    join public.profiles me on me.id = auth.uid()
    where dc.dietitian_id = auth.uid()
      and dc.client_id = daily_entries.client_id
      and me.role = 'dietitian'
  )
)
with check (
  exists (
    select 1
    from public.dietitian_clients dc
    join public.profiles me on me.id = auth.uid()
    where dc.dietitian_id = auth.uid()
      and dc.client_id = daily_entries.client_id
      and me.role = 'dietitian'
  )
);

drop policy if exists "v42_dietitian_select_assigned_entry_reviews" on public.entry_reviews;
create policy "v42_dietitian_select_assigned_entry_reviews"
on public.entry_reviews
for select
to authenticated
using (
  exists (
    select 1
    from public.dietitian_clients dc
    join public.profiles me on me.id = auth.uid()
    where dc.dietitian_id = auth.uid()
      and dc.client_id = entry_reviews.client_id
      and me.role = 'dietitian'
  )
);

drop policy if exists "v42_client_select_own_entry_reviews" on public.entry_reviews;
create policy "v42_client_select_own_entry_reviews"
on public.entry_reviews
for select
to authenticated
using (entry_reviews.client_id = auth.uid());

drop policy if exists "v42_dietitian_insert_assigned_entry_reviews" on public.entry_reviews;
create policy "v42_dietitian_insert_assigned_entry_reviews"
on public.entry_reviews
for insert
to authenticated
with check (
  entry_reviews.dietitian_id = auth.uid()
  and exists (
    select 1
    from public.dietitian_clients dc
    join public.profiles me on me.id = auth.uid()
    where dc.dietitian_id = auth.uid()
      and dc.client_id = entry_reviews.client_id
      and me.role = 'dietitian'
  )
);

drop policy if exists "v42_dietitian_update_assigned_entry_reviews" on public.entry_reviews;
create policy "v42_dietitian_update_assigned_entry_reviews"
on public.entry_reviews
for update
to authenticated
using (
  entry_reviews.dietitian_id = auth.uid()
  and exists (
    select 1
    from public.dietitian_clients dc
    join public.profiles me on me.id = auth.uid()
    where dc.dietitian_id = auth.uid()
      and dc.client_id = entry_reviews.client_id
      and me.role = 'dietitian'
  )
)
with check (
  entry_reviews.dietitian_id = auth.uid()
  and exists (
    select 1
    from public.dietitian_clients dc
    join public.profiles me on me.id = auth.uid()
    where dc.dietitian_id = auth.uid()
      and dc.client_id = entry_reviews.client_id
      and me.role = 'dietitian'
  )
);

-- Clients receive SELECT permission on their own review via the SELECT policy above,
-- but no INSERT/UPDATE policy is created for client role on entry_reviews.
