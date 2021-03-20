"use strict";

import {
	privateEncrypt as server_encrypt,
	privateDecrypt as server_decrypt,
	constants as padding
} from "crypto";

const NOT_FOUND_404 = new Response(null, {
	status: 404,
	statusText: "Not Found"
});
const PROTOCOL = ["ss", "v2"];
const CHANNEL = ["cmcc", "ctcc", "cucc", "auto"];
const CMCC = "移动";
const CTCC = "电信";
const CUCC = "联通";

function base64(buf) {
	let buff;
	if (typeof buf == "string") {
		buff = Buffer.from(buf);
	} else {
		buff = Buffer.from(JSON.stringify(buf));
	}
	return buff.toString("base64");
}

function base64_decode(text) {
	const buf = Buffer.from(text, "base64");
	return JSON.parse(buf);
}

async function md5sum(text) {
	const digest = await crypto.subtle.digest({ name: "MD5" }, Buffer.from(text));
	return Buffer.from(digest).toString("hex");
}

async function real_ip(headers) {
	const h = await CONFIG.get("real_ip_header");
	let ip = headers.get(h);
	if (!ip) ip = headers.get("cf-connecting-ip");
	if (!ip && req.headers["x-forwarded-for"]) {
		ip = req.headers["x-forwarded-for"].split(",")[0].trim();
	}
	return ip;
}

async function isplookup(ip) {
	const api = await CONFIG.get("iplookup_api");
	let ip_info;
	try {
		const response = await fetch(api, {
			method: "POST",
			headers: {
				"content-type": "application/x-www-form-urlencoded",
				connection: "close"
			},
			redirect: "follow",
			body: `ip=${ip}&isp=true`
		});
		ip_info = await response.json();
	} catch (err) {
		return "cmcc";
	}
	if (!ip_info["code"]) {
		return "cmcc";
	}
	const isp_zh_cn = ip_info["isp"];
	let isp;
	switch (isp_zh_cn) {
		case CMCC:
			isp = "cmcc";
			break;
		case CTCC:
			isp = "ctcc";
			break;
		case CUCC:
			isp = "cucc";
			break;
		default:
			isp = "cmcc";
			break;
	}
	return isp;
}

async function fetch_endpoint(t, api_url) {
	const future = await Promise.all([
		CONFIG.get("rsa_key"),
		CONFIG.get("user_agent")
	]);
	const [rsa_key, user_agent] = future;

	const data = JSON.stringify({
		t: t,
		cmd: "sub",
		data: "0"
	});
	const data_enc = server_encrypt(
		{
			key: rsa_key,
			padding: padding.RSA_PKCS1_PADDING
		},
		Buffer.from(data)
	);

	let r_data_enc;
	try {
		const response = await fetch(api_url, {
			method: "POST",
			headers: {
				"user-agent": user_agent,
				"content-type": "application/json",
				connection: "close"
			},
			redirect: "follow",
			body: data_enc.toString("base64")
		});
		r_data_enc = await response.text();
	} catch (err) {
		return null;
	}

	let r_data_plain;
	try {
		r_data_plain = server_decrypt(
			{
				key: rsa_key,
				padding: padding.RSA_PKCS1_PADDING
			},
			Buffer.from(r_data_enc, "base64")
		);
	} catch (_) {
		return null;
	}
	return JSON.parse(r_data_plain);
}

async function save_endpoint(name) {
	const t = name.split("_")[0];
	const endpoint_config_base64 = await ENDPOINT_CONFIG.get(name);
	const endpoint_config = base64_decode(
		endpoint_config_base64.replace("\n", "")
	);
	const api_url = endpoint_config["api"];
	const endpoint = await fetch_endpoint(t, api_url);
	const endpoint_base64 = base64(endpoint);
	await ENDPOINT.put(name, endpoint_base64);
}

async function do_create_share_link(name, inbound, endpoint, endpoint_manual) {
	const [t, tag] = name.split("_");
	let data;
	if (t == "v2") {
		data = {
			v: "2",
			ps: tag,
			add: "",
			port: "",
			id: "",
			aid: "1",
			net: "",
			type: "none",
			host: "",
			path: "",
			tls: "tls"
		};
	} else if (t == "ss") {
		data = {
			tag: tag,
			server: "",
			server_port: "",
			method: "",
			password: ""
		};
	}
	for (const k in endpoint) {
		data[k] = endpoint[k];
	}
	for (const k in endpoint_manual) {
		data[k] = endpoint_manual[k];
	}

	if (t == "v2" && data["add"] == "auto") {
		data["add"] = inbound;
	} else if (t == "ss" && data["server"] == "auto") {
		data["server"] = inbound;
	}

	let link;
	if (t == "v2") {
		link = "vmess://" + base64(data);
	} else if (t == "ss") {
		const account = base64(`${data.method}:${data.password}`);
		link = `ss://${account}@${inbound}:${data.server_port}#${data.tag}`;
	}
	return link;
}

async function create_share_link(name, inbound) {
	const future = await Promise.all([
		ENDPOINT.get(name),
		ENDPOINT_CONFIG.get(name)
	]);
	const [endpoint_base64, endpoint_config_base64] = future;
	const endpoint = base64_decode(endpoint_base64.replace("\n", ""));
	const endpoint_config = base64_decode(
		endpoint_config_base64.replace("\n", "")
	);
	const link = await do_create_share_link(
		name,
		inbound,
		endpoint,
		endpoint_config["manual"]
	);
	return link;
}

async function create_subscribe_table(t, inbound) {
	const list = await ENDPOINT_CONFIG.list({ prefix: t });
	const keys = list["keys"];
	let tasks = [];
	for (let i = 0, len = keys.length; i < len; i++) {
		const name = keys[i]["name"];
		tasks.push(create_share_link(name, inbound));
	}
	const future = await Promise.all(tasks);
	return base64(future.join("\n"));
}

async function handleRequest(request) {
	if (request.method != "GET") return NOT_FOUND_404;

	const url = new URL(request.url);
	const form = url.searchParams;
	const client = await real_ip(request.headers);

	const proto = form.get("proto"); // t [v2, ss]
	const channel = form.get("channel"); // isp [cmcc, ctcc, cucc]

	const month = new Date().getMonth() + 1;
	const token = await md5sum(month.toString());

	if (form.get("token") != token) return NOT_FOUND_404;
	if (!PROTOCOL.includes(proto)) return NOT_FOUND_404;
	if (!CHANNEL.includes(channel)) return NOT_FOUND_404;

	let isp;
	if (channel != "auto") {
		isp = channel;
	} else {
		isp = await isplookup(client);
	}
	const inbound = await CONFIG.get("isp_" + isp);
	const result = await create_subscribe_table(proto, inbound);
	return new Response(result, {
		headers: { "content-type": "plain/text" }
	});
}

async function handleScheduled(event) {
	const time = new Date(event.scheduledTime);
	const list = await ENDPOINT_CONFIG.list();
	const keys = list["keys"];
	let tasks = [];
	for (let i = 0, len = keys.length; i < len; i++) {
		const name = keys[i]["name"];
		tasks.push(save_endpoint(name));
	}
	await Promise.all(tasks);
}

addEventListener("fetch", event => {
	event.respondWith(handleRequest(event.request));
});

addEventListener("scheduled", event => {
	event.waitUntil(handleScheduled(event));
});
