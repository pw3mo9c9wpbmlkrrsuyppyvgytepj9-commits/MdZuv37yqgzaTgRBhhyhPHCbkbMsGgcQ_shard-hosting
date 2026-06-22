const crypto = require("crypto");
const { MongoClient } = require("mongodb");

const USER_FIELDS = new Set([
	"email",
	"username",
	"public_username",
	"password_hash",
	"signup_ip",
	"last_login_ip",
	"created_at",
	"updated_at",
	"last_login_at",
	"avatar_data_url",
	"discord_id",
	"discord_username",
]);

function trimUri(uri) {
	return String(uri || "")
		.replace(/\r/g, "")
		.trim();
}

function normalizeQuery(query) {
	if (!query || typeof query !== "object") {
		return query;
	}
	const q = { ...query };
	if (q._id != null && typeof q._id !== "object") {
		q._id = String(q._id);
	}
	if (q._id && typeof q._id === "object" && q._id.$ne !== undefined) {
		q._id = { ...q._id, $ne: String(q._id.$ne) };
	}
	return q;
}

function pickUserFields(doc) {
	const out = { _id: crypto.randomUUID() };
	for (const key of USER_FIELDS) {
		if (doc[key] !== undefined && doc[key] !== null) {
			out[key] = doc[key];
		}
	}
	return out;
}

let client;
let collection;

const ready = (async () => {
	const uri = trimUri(process.env.MONGODB_URI);
	if (!uri) {
		throw new Error("MONGODB_URI is not set.");
	}

	client = new MongoClient(uri);
	await client.connect();

	const explicitDb = process.env.MONGODB_DB_NAME && String(process.env.MONGODB_DB_NAME).trim();
	const db = explicitDb ? client.db(explicitDb) : client.db();
	collection = db.collection("users");

	await collection.createIndex({ email: 1 }, { unique: true, sparse: true });
	await collection.createIndex({ username: 1 }, { unique: true, sparse: true });
	await collection.createIndex({ public_username: 1 }, { unique: true, sparse: true });

	try {
		await collection.dropIndex("discord_id_1");
	} catch {
		// Index may not exist yet.
	}
	await collection.createIndex(
		{ discord_id: 1 },
		{
			unique: true,
			partialFilterExpression: { discord_id: { $type: "string" } },
		}
	);

	// Older signups stored discord_id: null, which blocks a second account on a sparse unique index.
	await collection.updateMany(
		{ discord_id: null },
		{ $unset: { discord_id: "", discord_username: "" } }
	);
})();

const users = {
	async findOne(query) {
		await ready;
		return collection.findOne(normalizeQuery(query));
	},

	async insert(doc) {
		await ready;
		const now = new Date();
		const record = pickUserFields({
			...doc,
			created_at: doc.created_at ?? now,
			updated_at: doc.updated_at ?? now,
			last_login_at: doc.last_login_at ?? now,
		});
		await collection.insertOne(record);
		return record;
	},

	async update(query, updateDoc) {
		await ready;
		await collection.updateOne(normalizeQuery(query), updateDoc);
		return 1;
	},

	async remove(query, options = {}) {
		await ready;
		const result = await collection.deleteOne(normalizeQuery(query));
		return result.deletedCount;
	},
};

module.exports = { ready, users };
