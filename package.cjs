module.exports = {
  name: "backend",
  version: "1.0.0",
  description: "OmniWatch API Backend",
  main: "server.js",
  scripts: {
    start: "node server.js",
    dev: "nodemon server.js",
    test: "echo \"Error: no test specified\" && exit 1"
  },
  keywords: [],
  author: "",
  license: "ISC",
  dependencies: {
    axios: "^1.13.2",
    bcryptjs: "^3.0.3",
    "body-parser": "^2.2.2",
    "connect-pg-simple": "^10.0.0",
    "cookie-parser": "^1.4.7",
    cors: "^2.8.5",
    crypto: "^1.0.1",
    dotenv: "^17.2.3",
    ejs: "^4.0.1",
    express: "^5.2.1",
    "express-rate-limit": "^7.1.5",
    "express-session": "^1.18.2",
    "helmet": "^7.1.0",
    "https": "^1.0.0",
    jsonwebtoken: "^9.0.3",
    mongoose: "^9.1.3",
    multer: "^2.0.2",
    "node-fetch": "^3.3.2",
    path: "^0.12.7",
    pg: "^8.17.1",
    session: "^0.1.0"
  },
  devDependencies: {
    nodemon: "^3.1.11"
  }
};
