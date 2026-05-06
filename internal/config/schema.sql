-- 1. Enable the UUID extension (Required for uuid_generate_v4)
create extension if not exists "uuid-ossp" with schema extensions;

-- 2. Users Table: Stores the core identity and cryptographic markers
create table if not exists public.users (
    id uuid primary key default extensions.uuid_generate_v4(),
    public_key text not null,
    encrypted_private_key text not null,
    salt text not null,
    created_at timestamptz default now()
);

-- 3. Teams Table: Managed by the founder/CTO roles
create table if not exists public.teams (
    id uuid not null default extensions.uuid_generate_v4(),
    name text not null,
    created_at timestamp with time zone default now(),
    created_by uuid null,
    constraint teams_pkey primary key (id),
    constraint teams_name_key unique (name),
    constraint teams_created_by_fkey foreign key (created_by) references public.users (id) on delete set null
);

-- 4. Team Invites Table: Handles the 6-digit OTP flow for joining teams
create table if not exists public.team_invites (
    id uuid not null default gen_random_uuid(),
    team_id uuid not null,
    hashed_otp text not null,
    expires_at timestamp with time zone not null,
    is_used boolean default false,
    created_at timestamp with time zone default now(),
    constraint team_invites_pkey primary key (id),
    constraint team_invites_team_id_fkey foreign key (team_id) references public.teams (id) on delete cascade
);

-- 5. Membership Table: Connects users to teams with specific roles
create table if not exists public.membership (
    id uuid not null default extensions.uuid_generate_v4(),
    user_id uuid null,
    team_id uuid null,
    username text not null,
    role text default 'member' check (role in ('admin', 'member')),
    constraint membership_pkey primary key (id),
    constraint membership_team_id_username_key unique (team_id, username),
    constraint membership_team_id_fkey foreign key (team_id) references public.teams (id) on delete cascade,
    constraint membership_user_id_fkey foreign key (user_id) references public.users (id) on delete cascade
);

-- 6. Safe Table: The logical container for secrets within a team
create table if not exists public.safe (
    id uuid not null default extensions.uuid_generate_v4(),
    team_id uuid null,
    name text not null,
    lock text not null, -- Stores the encrypted master key for the safe
    version integer default 1,
    created_at timestamp with time zone default now(),
    constraint safe_pkey primary key (id),
    constraint safe_team_id_name_key unique (team_id, name),
    constraint safe_team_id_fkey foreign key (team_id) references public.teams (id) on delete cascade
);

-- 7. Envelopes Table: Stores the encrypted keys for individual users
create table if not exists public.envelopes (
    id uuid not null default extensions.uuid_generate_v4(),
    safe_id uuid null,
    user_id uuid null,
    encrypted_team_key text not null,
    created_at timestamp with time zone default now(),
    constraint envelopes_pkey primary key (id),
    constraint envelopes_safe_id_user_id_key unique (safe_id, user_id),
    constraint envelopes_safe_id_fkey foreign key (safe_id) references public.safe (id) on delete cascade,
    constraint envelopes_user_id_fkey foreign key (user_id) references public.users (id) on delete cascade
);

-- 8. Recommended: Create an index for faster lookups on team names and user IDs
create index if not exists idx_membership_user_id on public.membership(user_id);
create index if not exists idx_safe_team_id on public.safe(team_id);