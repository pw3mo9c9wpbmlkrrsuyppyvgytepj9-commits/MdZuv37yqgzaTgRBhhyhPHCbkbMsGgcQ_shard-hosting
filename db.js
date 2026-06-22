require("dotenv").config();

function cleanEnv(value) {
	return String(value || "")
		.replace(/\r/g, "")
		.trim();
}

const mongoUri = cleanEnv(process.env.MONGODB_URI) || cleanEnv(process.env._MONGODB_URI);

if (mongoUri) {
	process.env.MONGODB_URI = mongoUri;
	module.exports = require("./db-mongo.js");
} else if (process.env.DATABASE_URL) {
	module.exports = require("./db-pg.js");
} else {
	module.exports = require("./db-nedb.js");
}
