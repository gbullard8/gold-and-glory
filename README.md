# Gold and Glory

Mobile-friendly custom tabletop RPG character sheets plus a desktop host dashboard.

## Features
- Player / Host landing screen
- Case-insensitive unique character names
- Arbitrary non-empty player passwords, stored only as bcrypt hashes
- Persistent character data in Supabase
- Auto-save while editing
- Custom resources, inventory, loot, weapon XP, skills, and notes
- Core stat modifier = stat - 10
- Host character browser sorted by last update
- Host can pin multiple character sheets at once
- Realtime host refresh when players save
- Responsive phone layout

## One-time setup
1. Create a Supabase project.
2. Open Supabase SQL Editor and run `supabase/schema.sql`.
3. Before running it, replace `CHANGE_ME_HOST_PASSWORD` with the host password you want.
4. In Supabase project settings/API, copy the Project URL and publishable (or legacy anon) key.
5. Put those two values in `config.js`. Never put a service-role/secret key in this repository.
6. In Supabase Realtime/Replication, confirm the `characters` table is enabled. The SQL attempts to add it automatically.
7. In GitHub repository Settings > Pages, deploy from the `main` branch/root.

GitHub Pages hosts the frontend; Supabase stores the persistent data.
