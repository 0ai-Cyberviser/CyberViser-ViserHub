# CyberViser Free GitHub-First Roadmap

This roadmap replaces the paid GPU-worker path with a zero-cost GitHub-first plan for making the CyberViser / 0AI ecosystem look polished, connected, and maintainable.

## Goal

Make every public CyberViser repository feel like part of one coherent platform:

- one public domain: `cyberviserai.com`
- one owner namespace: `0ai-Cyberviser`
- one flagship: `Hancock`
- one dataset engine: `PeachTree`
- one fuzzing engine: `PeachFuzz`
- one GitHub maintenance agent: `MrClean`
- one public site source: `CyberViser-ViserHub`

## Cost boundary

No paid GPU, hosted runner, cloud VM, or paid SaaS dependency is required for this phase.

Use:

- GitHub Pages for public websites
- GitHub Actions free tier where available
- local development machines
- pull requests for all changes
- issues for roadmap work
- MrClean for repo/PR maintenance planning

Avoid:

- paid GPU instances
- exposing private admin links
- publishing Google Admin or Drive URLs
- publishing private repositories or raw datasets
- training/fine-tuning until compute budget exists

## Priority order

### Phase 1 — Website and DNS stabilization

- Ensure `CyberViser-ViserHub` deploys to GitHub Pages.
- Set `cyberviserai.com` as the custom domain.
- Confirm Squarespace/Google DNS TXT verification.
- Keep Google Workspace MX/SPF/DKIM records unchanged.
- Add clear links to Hancock, PeachTree, PeachFuzz, MrClean, 0AI, and GitHub profile.

### Phase 2 — GitHub profile polish

- Update `0ai-Cyberviser/0ai-Cyberviser` profile README.
- Add project cards for the core stack.
- Add badges and links to the public site.
- Make the profile explain the relationship between CyberViser, 0AI, and Hancock.

### Phase 3 — Core repo README standard

Each core repo should include:

- short mission statement
- status badges
- quick start
- project architecture
- safety/ethics notes
- related project links
- roadmap
- license/security links
- link back to `https://cyberviserai.com/`

Core repos:

- `Hancock`
- `PeachTree`
- `peachfuzz`
- `mrclean`
- `0ai`
- `CyberViser-ViserHub`

### Phase 4 — Issue and label hygiene

Standard labels:

- `type:bug`
- `type:docs`
- `type:feature`
- `type:security`
- `type:fuzzing`
- `type:dataset`
- `type:ci`
- `risk:low`
- `risk:medium`
- `risk:high`
- `risk:critical`
- `status:blocked`
- `status:needs-review`
- `status:ready`
- `agent:mrclean`
- `agent:hancock`
- `agent:peachfuzz`
- `agent:peachtree`

### Phase 5 — Free dataset/fuzzing loop

Use local and GitHub-native workflows:

```bash
git clone https://github.com/0ai-Cyberviser/PeachTree.git
git clone https://github.com/0ai-Cyberviser/peachfuzz.git
git clone https://github.com/0ai-Cyberviser/Hancock.git

cd PeachTree
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
peachtree ingest-local --repo ../Hancock --repo-name hancock --output data/raw/hancock.jsonl
peachtree build --source data/raw/hancock.jsonl --dataset data/datasets/hancock-instruct.jsonl --manifest data/manifests/hancock.json --domain hancock
```

## Public/private boundary

Public:

- README files
- docs
- GitHub Pages
- public-safe examples
- sanitized schemas
- roadmap issues
- PRs

Private:

- Google Admin
- Google Drive private files
- secrets
- API keys
- raw honeypot telemetry
- raw datasets with sensitive content
- unpublished model artifacts

## Definition of done

The free-first polish phase is complete when:

- `cyberviserai.com` loads from GitHub Pages
- GitHub profile README links all core projects
- each core repo has a polished README
- MrClean has an estate-maintainer roadmap and config
- PeachTree and PeachFuzz are clearly connected to Hancock datasets
- all public docs link back to the central CyberViser site
