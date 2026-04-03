// CRA loads .env automatically. Never require('dotenv') here.
const path = require('path');
module.exports = {
  webpack: {
    alias: { '@': path.resolve(__dirname, 'src') },
    configure: (cfg) => {
      cfg.watchOptions = { ...cfg.watchOptions, ignored: ['**/node_modules/**','**/.git/**'] };
      return cfg;
    },
  },
};
