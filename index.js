const express = require("express");
const app = express();
const cookieParser = require("cookie-parser");
const fs = require("fs");
const multer = require("multer");
const upload = multer({ dest: "./tmp/" });
const { XMLParser } = require("fast-xml-parser");
const {
  createSecurityRules,
  createZones,
  createTags,
  createAddressObjects,
  createApplicationGroups,
  createServices,
  createServiceGroups,
  createVirusProfiles,
  createNatRules,
  createAddressGroups,
  createInterfaces,
  createInterfaceManagementPolicies,
  createTunnelInterfaces,
} = require("./controllers");

const BASE = "https://api.strata.paloaltonetworks.com";
const API = {
  SECURITY_RULES: `${BASE}/config/security/v1/security-rules`,
  ZONES: `${BASE}/config/network/v1/zones`,
  TAGS: `${BASE}/config/objects/v1/tags`,
  ADDRESSES: `${BASE}/config/objects/v1/addresses`,
  ADDRESS_GROUPS: `${BASE}/config/objects/v1/address-groups`,
  APP_GROUPS: `${BASE}/config/objects/v1/application-groups`,
  SERVICES: `${BASE}/config/objects/v1/services`,
  SERVICE_GROUPS: `${BASE}/config/objects/v1/service-groups`,
  VIRUS_PROFILES: `${BASE}/config/security/v1/wildfire-anti-virus-profiles`,
  NAT_RULES: `${BASE}/config/network/v1/nat-rules`,
  INTERFACES: `${BASE}/config/network/v1/ethernet-interfaces`,
  TUNNEL_IFACES: `${BASE}/config/network/v1/tunnel-interfaces`,
  MGMT_PROFILES: (folder) =>
    `${BASE}/config/network/v1/interface-management-profiles?folder=${folder}`,
};

app.use(express.json());
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

// ─── Helpers ────────────────────────────────────────────────────────────────

/**
 * POST a single item; returns { ok, name, error? }
 */
async function postOne(url, token, item) {
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(item),
    });
    const data = await res.json();
    if (data["_error"]) {
      const msg = Array.isArray(data["_error"])
        ? data["_error"].map((e) => e.message).join(", ")
        : data["_error"].message || JSON.stringify(data["_error"]);
      console.error(`  ✗ ${item.name}: ${msg}`);
      return { ok: false, name: item.name, error: msg };
    }
    console.log(`  ✓ ${item.name}`);
    return { ok: true, name: item.name };
  } catch (err) {
    console.error(`  ✗ ${item.name} (network): ${err.message}`);
    return { ok: false, name: item.name, error: err.message };
  }
}

/**
 * POST a batch in parallel (concurrency-limited to avoid 429s).
 * Returns summary { created, failed }.
 */
async function postBatch(label, url, token, items, concurrency = 5) {
  if (!items || items.length === 0) {
    console.log(`[${label}] nothing to create, skipping`);
    return { created: 0, failed: 0 };
  }
  console.log(`\n[${label}] creating ${items.length} item(s)…`);

  let created = 0,
    failed = 0;
  // process in chunks to avoid overwhelming the API
  for (let i = 0; i < items.length; i += concurrency) {
    const chunk = items.slice(i, i + concurrency);
    const results = await Promise.allSettled(
      chunk.map((item) => postOne(url, token, item)),
    );
    results.forEach((r) => {
      const val = r.status === "fulfilled" ? r.value : { ok: false };
      val.ok ? created++ : failed++;
    });
  }
  console.log(`[${label}] done — created: ${created}, failed: ${failed}`);
  return { created, failed };
}

/**
 * PUT a single item (for zone updates).
 */
async function putOne(url, token, item) {
  try {
    const res = await fetch(`${url}/${encodeURIComponent(item.id)}`, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(item.body),
    });
    const data = await res.json();
    if (data["_error"]) {
      const msg = Array.isArray(data["_error"])
        ? data["_error"].map((e) => e.message).join(", ")
        : data["_error"].message || JSON.stringify(data["_error"]);
      console.error(`  ✗ zone ${item.name}: ${msg}`);
      return { ok: false };
    }
    console.log(`  ✓ zone updated: ${item.name}`);
    return { ok: true };
  } catch (err) {
    console.error(`  ✗ zone ${item.name} (network): ${err.message}`);
    return { ok: false };
  }
}

// ─── Routes ─────────────────────────────────────────────────────────────────

app.post("/api/v1/login", async (req, res) => {
  const { id, secret, tsgId } = req.body;
  if (!id || !secret || !tsgId)
    return res.status(400).json({ error: "Missing id, secret, or tsgId" });

  const creds = Buffer.from(`${id}:${secret}`).toString("base64");
  const payload = new URLSearchParams({
    grant_type: "client_credentials",
    scope: `tsg_id:${tsgId}`,
  });

  try {
    const response = await fetch(
      "https://auth.apps.paloaltonetworks.com/oauth2/access_token",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Authorization: `Basic ${creds}`,
        },
        body: payload.toString(),
      },
    );

    const data = await response.json();

    if (!response.ok) {
      const msg = data.error_description || data.error || "Auth failed";
      return res.status(401).json({ success: false, error: msg });
    }

    res.cookie("access_token", data.access_token, {
      httpOnly: true,
      sameSite: "strict",
    });
    return res.status(200).json({ success: true });
  } catch (err) {
    console.error("Auth error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/api/v1/get-devices", async (req, res) => {
  const token = req.cookies.access_token;
  if (!token) return res.status(401).json({ error: "Unauthorized" });

  try {
    const response = await fetch(`${BASE}/config/setup/v1/folders`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const data = await response.json();

    if (!response.ok) return res.status(response.status).json({ error: data });

    const devices = (data.data || []).filter(
      (item) => item.type === "container" && item.parent === "ngfw-shared",
    );
    return res.status(200).json(devices);
  } catch (error) {
    console.error("Error fetching devices:", error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

app.post("/api/v1/import-backup", upload.single("backup"), async (req, res) => {
  const token = req.cookies.access_token;
  const { serial } = req.body; // this is actually the folder id/name
  console.log("\n=== Import started for folder:", serial, "===");

  if (!token) return res.status(401).json({ error: "Unauthorized" });
  if (!req.file) return res.status(400).json({ error: "Missing backup file" });

  const filePath = req.file.path;
  let backup;
  try {
    backup = fs.readFileSync(filePath, "utf-8");
  } finally {
    // always clean up temp file
    try {
      fs.unlinkSync(filePath);
    } catch (_) {}
  }

  // ── Parse XML ──────────────────────────────────────────────────────────────
  const parser = new XMLParser({
    ignoreAttributes: false,
    attributeNamePrefix: "@",
  });
  let jsonData;
  try {
    jsonData = parser.parse(backup);
  } catch (err) {
    return res.status(400).json({ error: "Invalid XML: " + err.message });
  }

  const vsys = jsonData?.config?.devices?.entry?.vsys?.entry;
  const network = jsonData?.config?.devices?.entry?.network;

  if (!vsys || !network)
    return res.status(400).json({ error: "Unexpected XML structure" });

  // ── Extract & transform ────────────────────────────────────────────────────
  const tags = createTags(vsys.tag?.entry || [], serial);
  const addresses = createAddressObjects(vsys.address?.entry || [], serial);
  const addressGroups = createAddressGroups(
    vsys["address-group"]?.entry || [],
    serial,
  );
  const zones = createZones(vsys.zone?.entry || [], serial);
  const services = createServices(vsys.service?.entry || [], serial);
  const serviceGroups = createServiceGroups(
    vsys["service-group"]?.entry || [],
    serial,
  );
  const applicationGroups = createApplicationGroups(
    vsys["application-group"]?.entry || [],
    serial,
  );
  const virusProfiles = createVirusProfiles(
    vsys.profiles?.virus?.entry || [],
    serial,
  );
  const mgmtProfiles = createInterfaceManagementPolicies(
    network.profiles?.["interface-management-profile"]?.entry || [],
    serial,
  );
  const ethernetIfaces = createInterfaces(
    network.interface?.ethernet?.entry || [],
    serial,
  );
  const tunnelIfaces = createTunnelInterfaces(
    network.interface?.tunnel?.units?.entry || [],
    serial,
  );
  const natRules = createNatRules(
    vsys.rulebase?.nat?.rules?.entry || [],
    serial,
  );
  const securityRules = createSecurityRules(
    vsys.rulebase?.security?.rules?.entry || [],
    serial,
  );

  // ── Step 1: Create base objects in parallel where safe ────────────────────
  //   Tags, addresses, address groups, services, service groups,
  //   app groups, virus profiles can all run independently.
  console.log("\n── Phase 1: independent objects ──");
  await Promise.all([
    postBatch("Tags", API.TAGS, token, tags),
    postBatch("Services", API.SERVICES, token, services),
    postBatch("App Groups", API.APP_GROUPS, token, applicationGroups),
    postBatch("Virus Profiles", API.VIRUS_PROFILES, token, virusProfiles),
  ]);

  // Addresses must exist before address groups
  console.log("\n── Phase 2: addresses then address groups ──");
  await postBatch("Addresses", API.ADDRESSES, token, addresses);
  await postBatch("Address Groups", API.ADDRESS_GROUPS, token, addressGroups);
  await postBatch("Service Groups", API.SERVICE_GROUPS, token, serviceGroups);

  // ── Step 2: Create zones (no interfaces yet) ───────────────────────────────
  console.log("\n── Phase 3: zones (skeleton) ──");
  await postBatch("Zones", API.ZONES, token, zones);

  // ── Step 3: Fetch created zones to get their SCM IDs ──────────────────────
  console.log("\n── Phase 4: fetch zone IDs from SCM ──");
  let fetchedZones = [];
  try {
    const zRes = await fetch(
      `${API.ZONES}?folder=${encodeURIComponent(serial)}`,
      {
        headers: { Authorization: `Bearer ${token}` },
      },
    );
    const zData = await zRes.json();
    fetchedZones = zData.data || [];
    console.log(`Fetched ${fetchedZones.length} zone(s) from SCM`);
  } catch (err) {
    console.error("Could not fetch zones from SCM:", err.message);
    // non-fatal — zone updates will just be skipped
  }

  // Build a name→id map for zones
  const zoneIdMap = {};
  fetchedZones.forEach((z) => {
    zoneIdMap[z.name] = z.id;
  });

  // ── Step 4: Mgmt profiles, then interfaces (need zones to exist first) ─────
  console.log("\n── Phase 5: mgmt profiles ──");
  await postBatch(
    "Mgmt Profiles",
    API.MGMT_PROFILES(serial),
    token,
    mgmtProfiles,
  );

  console.log("\n── Phase 6: ethernet + tunnel interfaces ──");
  await Promise.all([
    postBatch("Ethernet Interfaces", API.INTERFACES, token, ethernetIfaces),
    postBatch("Tunnel Interfaces", API.TUNNEL_IFACES, token, tunnelIfaces),
  ]);

  // ── Step 5: Fetch created interfaces to get their names for zone binding ───
  console.log("\n── Phase 7: fetch interface names from SCM ──");
  let fetchedInterfaces = [];
  try {
    const iRes = await fetch(
      `${API.INTERFACES}?folder=${encodeURIComponent(serial)}`,
      { headers: { Authorization: `Bearer ${token}` } },
    );
    const iData = await iRes.json();
    fetchedInterfaces = iData.data || [];
    console.log(`Fetched ${fetchedInterfaces.length} interface(s) from SCM`);
  } catch (err) {
    console.error("Could not fetch interfaces from SCM:", err.message);
  }

  // ── Step 6: Update zones — attach interfaces by matching zone name ──────────
  // Original XML zones carry the interface list; we match by zone name.
  console.log("\n── Phase 8: update zones with interfaces ──");
  const zoneUpdates = buildZoneUpdates(
    vsys.zone?.entry || [],
    fetchedZones,
    serial,
  );

  if (zoneUpdates.length > 0) {
    await Promise.allSettled(
      zoneUpdates.map((zu) => putOne(API.ZONES, token, zu)),
    );
  } else {
    console.log(
      "[Zone Updates] nothing to update (no zone-interface mappings found)",
    );
  }

  // ── Step 7: NAT rules then security rules (order matters) ─────────────────
  console.log("\n── Phase 9: NAT rules ──");
  await postBatch("NAT Rules", API.NAT_RULES, token, natRules);

  console.log("\n── Phase 10: Security rules ──");
  await postBatch("Security Rules", API.SECURITY_RULES, token, securityRules);

  console.log("\n=== Import complete for folder:", serial, "===");
  return res.status(200).json({ success: true });
});

// ─── Zone update builder ─────────────────────────────────────────────────────
/**
 * Build PUT payloads for zones, binding the layer3 interfaces
 * extracted from the original XML.
 *
 * XML zone shape: { "@name": "trust", layer3: { member: "ethernet1/1" | ["ethernet1/1","ethernet1/2"] } }
 * SCM zone shape: { id: "uuid", name: "trust", network: { ... } }
 */
function buildZoneUpdates(xmlZones, scmZones, folder) {
  const updates = [];

  const ensureArray = (v) => {
    if (!v) return [];
    return Array.isArray(v) ? v : [v];
  };

  xmlZones.forEach((xz) => {
    const zoneName = xz["@name"];
    const scmZone = scmZones.find((z) => z.name === zoneName);
    if (!scmZone) {
      console.warn(`  ⚠ zone "${zoneName}" not found in SCM, skipping update`);
      return;
    }

    // grab layer3 members from XML (may not exist for all zones)
    const layer3Members = ensureArray(xz.network?.layer3?.member);

    if (layer3Members.length === 0) {
      // zone has no interface assignment — skip update, keep as-is
      return;
    }

    updates.push({
      id: scmZone.id,
      name: zoneName,
      body: {
        name: zoneName,
        folder: folder,
        enable_user_identification: false,
        enable_device_identification: false,
        network: {
          layer3: layer3Members,
          zone_protection_profile: "best-practice",
        },
      },
    });
  });

  return updates;
}

// ─── Static routes ───────────────────────────────────────────────────────────
app.get("/", (req, res) => res.sendFile(__dirname + "/templates/index.html"));
app.get("/scm/dashboard", (req, res) => {
  if (!req.cookies.access_token) return res.status(401).redirect("/");
  res.sendFile(__dirname + "/templates/dashboard-new.html");
});
app.get("/foo", (_, res) => res.send("bar"));

app.listen(9090, () => console.log("Server running on http://localhost:9090"));
