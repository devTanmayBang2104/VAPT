const fs = require('fs');

let c = fs.readFileSync('src/components/home.tsx', 'utf8');

const replacements = {
  "ðŸš€": "🚀",
  "ðŸ“Š": "📊",
  "ðŸ” ": "🔍",
  "ðŸ“‹": "📋",
  "â†’": "→",
  "ðŸ”¬": "🔬",
  "â”€": "─",
  "âš": "⚠️",
  "ï¸": "",
  "ðŸ“„": "📄",
  "ðŸ”": "🔍"
};

for (const [bad, good] of Object.entries(replacements)) {
  c = c.split(bad).join(good);
}

fs.writeFileSync('src/components/home.tsx', c);
console.log('Encoding fixed.');
