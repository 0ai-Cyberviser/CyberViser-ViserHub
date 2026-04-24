const grid = document.querySelector('#repo-grid');
const search = document.querySelector('#repo-search');
const filter = document.querySelector('#repo-filter');
const count = document.querySelector('#repo-count');

let repositories = [];

const normalize = (value) => String(value || '').toLowerCase();

function uniqueCategories(items) {
  return [...new Set(items.map((repo) => repo.category).filter(Boolean))].sort();
}

function renderFilters(items) {
  const categories = uniqueCategories(items);
  for (const category of categories) {
    const option = document.createElement('option');
    option.value = category;
    option.textContent = category;
    filter.appendChild(option);
  }
}

function repoMatches(repo, query, category) {
  const haystack = [repo.name, repo.owner, repo.category, repo.description].map(normalize).join(' ');
  const queryMatch = !query || haystack.includes(normalize(query));
  const categoryMatch = category === 'all' || repo.category === category;
  return queryMatch && categoryMatch;
}

function renderRepos() {
  const query = search.value.trim();
  const category = filter.value;
  const visible = repositories.filter((repo) => repoMatches(repo, query, category));

  count.textContent = `${visible.length} public-safe repositories shown${repositories.length ? ` out of ${repositories.length}` : ''}.`;

  grid.innerHTML = visible.map((repo) => `
    <article class="repo-card">
      <div class="meta">
        <span class="tag">${repo.category}</span>
        <span class="tag">${repo.owner}</span>
      </div>
      <h3>${repo.name}</h3>
      <p>${repo.description}</p>
      <a href="${repo.url}" rel="noopener">Open repository →</a>
    </article>
  `).join('');

  if (!visible.length) {
    grid.innerHTML = '<p class="empty-state">No repositories match that search/filter.</p>';
  }
}

async function init() {
  try {
    const response = await fetch('data/repos.json', { cache: 'no-store' });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    repositories = await response.json();
    repositories.sort((a, b) => a.category.localeCompare(b.category) || a.name.localeCompare(b.name));
    renderFilters(repositories);
    renderRepos();
  } catch (error) {
    count.textContent = 'Repository data could not be loaded.';
    grid.innerHTML = '<p class="empty-state">Open the GitHub profile links above while repository data is unavailable.</p>';
    console.error(error);
  }
}

search.addEventListener('input', renderRepos);
filter.addEventListener('change', renderRepos);
init();
