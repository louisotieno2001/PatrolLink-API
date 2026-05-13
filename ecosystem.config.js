module.exports = {
  apps: [{
    name: 'patrolLink',
    script: 'server.js',
    instances: 'max',
    exec_mode: 'cluster',
    env: {
      NODE_ENV: 'production',
    },
  }],
};
