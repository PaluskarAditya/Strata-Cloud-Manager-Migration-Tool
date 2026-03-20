// ─── Shared helpers ──────────────────────────────────────────────────────────

/**
 * Safely unwrap PAN XML member fields into a plain string array.
 * Handles: undefined, string, string[], { member: string | string[] }, array of those.
 */
const unwrapMembers = (field, defaultVal = ["any"]) => {
  if (field == null) return defaultVal;

  // flat array of primitives or objects
  if (Array.isArray(field)) {
    const result = field.flatMap((item) => {
      if (item == null) return [];
      if (typeof item === "object" && item.member != null)
        return Array.isArray(item.member) ? item.member : [item.member];
      return [item];
    });
    return result.length ? result : defaultVal;
  }

  // object with .member
  if (typeof field === "object" && field.member != null) {
    const m = field.member;
    return Array.isArray(m) ? m : [m];
  }

  // primitive
  return [String(field)];
};

const ensureArray = (v) => {
  if (v == null) return [];
  return Array.isArray(v) ? v : [v];
};

// ─── Creators ────────────────────────────────────────────────────────────────

const createSecurityRules = (ruleData, folder = "ngfw-shared") => {
  return ensureArray(ruleData).map((rule) => ({
    name: rule["@name"],
    policy_type: "Security",
    disabled: false,
    description: rule.description || "",
    tag: unwrapMembers(rule.tag, []),
    from: unwrapMembers(rule.from),
    to: unwrapMembers(rule.to),
    source: unwrapMembers(rule.source),
    negate_source: false,
    source_user: unwrapMembers(rule["source-user"]),
    destination: unwrapMembers(rule.destination),
    negate_destination: false,
    service: unwrapMembers(rule.service),
    action: rule.action || "allow",
    application: unwrapMembers(rule.application),
    category: unwrapMembers(rule.category),
    profile_setting: { group: ["best-practice"] },
    log_start: true,
    log_end: true,
    folder,
  }));
};

const createNatRules = (natData, folder = "ngfw-shared") => {
  return ensureArray(natData).map((nat) => {
    let source_translation;
    const dip =
      nat["source-translation"]?.["dynamic-ip-and-port"]?.["interface-address"];
    if (dip) {
      source_translation = {
        "dynamic-ip-and-port": {
          interface: dip.interface,
          ...(dip.ip && { ip: dip.ip }),
        },
      };
    }

    let destination_translation;
    if (nat["destination-translation"]) {
      destination_translation = {
        translated_address:
          nat["destination-translation"]["translated-address"],
      };
    }

    return {
      name: nat["@name"],
      description: "Migrated NAT rule",
      tag: unwrapMembers(nat.tag, []),
      disabled: false,
      nat_type: "ipv4",
      from: unwrapMembers(nat.from, ["any"]),
      to: unwrapMembers(nat.to, ["any"]),
      source: unwrapMembers(nat.source, ["any"]),
      destination: unwrapMembers(nat.destination, ["any"]),
      service: nat.service || "any",
      to_interface: nat["to-interface"],
      active_active_device_binding: "primary",
      ...(source_translation && { source_translation }),
      ...(destination_translation && { destination_translation }),
      folder,
    };
  });
};

/**
 * Create skeleton zones (no interface assignment yet).
 * Interfaces are attached in a separate PUT after they are created.
 */
const createZones = (zoneData, folder = "ngfw-shared") => {
  return ensureArray(zoneData).map((zone) => ({
    name: zone["@name"],
    folder,
    enable_user_identification: false,
    enable_device_identification: false,
    network: {
      zone_protection_profile: "best-practice",
    },
  }));
};

const createTags = (tagData, folder = "ngfw-shared") => {
  return ensureArray(tagData).map((tag) => ({
    name: tag["@name"],
    comments: tag.comments || "",
    folder,
  }));
};

const createAddressObjects = (addressData, folder = "ngfw-shared") => {
  return ensureArray(addressData).map((address) => {
    const obj = {
      name: address["@name"],
      description: "Migrated address object",
      tag: unwrapMembers(address.tag, []),
      folder,
    };
    if (address["ip-netmask"]) obj.ip_netmask = address["ip-netmask"];
    else if (address["ip-range"]) obj.ip_range = address["ip-range"];
    else if (address.fqdn) obj.fqdn = address.fqdn;
    return obj;
  });
};

const createAddressGroups = (addressGroupData, folder = "ngfw-shared") => {
  return ensureArray(addressGroupData).map((ag) => ({
    name: ag["@name"],
    description: "Migrated address group",
    tag: unwrapMembers(ag.tag, []),
    static: unwrapMembers(ag.static, []),
    folder,
  }));
};

const createApplicationGroups = (
  applicationGroupData,
  folder = "ngfw-shared",
) => {
  return ensureArray(applicationGroupData).map((ag) => {
    // XML shape: ag.members.member or ag.members directly
    const raw = ag.members?.member ?? ag.members ?? [];
    return {
      name: ag["@name"],
      members: unwrapMembers(raw, []),
      folder,
    };
  });
};

const createServices = (servicesData, folder = "ngfw-shared") => {
  const services = [];
  ensureArray(servicesData).forEach((service) => {
    if (!service.protocol) return;
    const protocolType = Object.keys(service.protocol)[0];
    if (!protocolType) return;
    const protocolData = service.protocol[protocolType];
    if (!protocolData?.port) return;

    const ports = String(protocolData.port)
      .split(",")
      .map((p) => p.trim())
      .filter(Boolean);
    if (!ports.length) return;

    // override: if "no" key exists → no override object
    const hasOverride =
      protocolData.override && protocolData.override.no === undefined;

    services.push({
      name: service["@name"],
      description: service.description || "",
      protocol: {
        [protocolType]: {
          port: ports.join(","),
          ...(hasOverride && {
            override: {
              timeout: protocolData.override?.timeout,
              halfclose_timeout: protocolData.override?.halfclose_timeout,
              timewait_timeout: protocolData.override?.timewait_timeout,
            },
          }),
        },
      },
      folder,
    });
  });
  return services;
};

const createServiceGroups = (serviceGroupData, folder = "ngfw-shared") => {
  return ensureArray(serviceGroupData).map((sg) => {
    // XML: sg.members.member or sg.members
    const raw = sg.members?.member ?? sg.members ?? [];
    return {
      name: sg["@name"],
      members: unwrapMembers(raw, []),
      folder,
    };
  });
};

const createVirusProfiles = (virusProfileData, folder = "ngfw-shared") => {
  // virusProfileData can be a single object or array
  const profiles = ensureArray(virusProfileData);
  return profiles.map((vp) => {
    const decoders = ensureArray(vp.decoder?.entry || []);
    const rules = decoders.map((decoder) => ({
      name: decoder["@name"],
      action: decoder.action || "default",
      analysis: "public-cloud",
      application: ["any"],
      file_type: decoder["file-type"]
        ? ensureArray(decoder["file-type"])
        : ["any"],
      direction: "both",
    }));
    return {
      name: vp["@name"],
      description: "Migrated WildFire/Virus profile",
      rules,
      folder,
    };
  });
};

const createInterfaces = (interfaceData, folder = "ngfw-shared") => {
  return ensureArray(interfaceData).map((iface) => {
    const ipEntries = iface.layer3?.ip?.entry
      ? ensureArray(iface.layer3.ip.entry)
      : [];

    const base = {
      name: `$eth-${iface["@name"].replace("/", "-")}`,
      default_value: iface["@name"],
      comment: iface.comment || "",
      slot: 1,
      folder,
      layer3: {
        interface_management_profile:
          iface.layer3?.["interface-management-profile"],
        mtu: iface.layer3?.mtu || 1500,
      },
    };

    if (ipEntries.length > 0) {
      base.layer3.ip = ipEntries.map((ip) => ({ name: ip["@name"] }));
    }

    if (iface.layer3?.pppoe) {
      base.layer3.pppoe = {
        enable: true,
        username: iface.layer3.pppoe.username,
        password: iface.layer3.pppoe.password,
      };
    }

    return base;
  });
};

const createTunnelInterfaces = (
  tunnelInterfaceData,
  folder = "ngfw-shared",
) => {
  return ensureArray(tunnelInterfaceData).map((tunnel) => {
    const ipEntry = tunnel.ip?.entry;
    const obj = {
      name: `$eth-${tunnel["@name"].replace(".", "-")}`,
      default_value: tunnel["@name"],
      comment: tunnel.comment || "",
      interface_management_profile: tunnel["interface-management-profile"],
      folder,
    };
    if (ipEntry?.["@name"]) {
      obj.ip = [{ name: ipEntry["@name"] }];
    }
    return obj;
  });
};

const createInterfaceManagementPolicies = (
  intMgmtProfileData,
  folder = "ngfw-shared",
) => {
  const toBool = (v) => v === "yes" || v === true;
  return ensureArray(intMgmtProfileData).map((p) => ({
    name: p["@name"],
    http: toBool(p.http),
    https: toBool(p.https),
    telnet: toBool(p.telnet),
    ssh: toBool(p.ssh),
    ping: toBool(p.ping),
    http_ocsp: toBool(p["http-ocsp"] ?? p.http_ocsp),
    response_pages: toBool(p["response-pages"] ?? p.response_pages),
    userid_service: toBool(p["userid-service"] ?? p.userid_service),
    userid_syslog_listener_ssl: toBool(
      p["userid-syslog-listener-ssl"] ?? p.userid_syslog_listener_ssl,
    ),
    userid_syslog_listener_udp: toBool(
      p["userid-syslog-listener-udp"] ?? p.userid_syslog_listener_udp,
    ),
    folder,
  }));
};

module.exports = {
  createSecurityRules,
  createZones,
  createTags,
  createServices,
  createAddressObjects,
  createApplicationGroups,
  createServiceGroups,
  createVirusProfiles,
  createNatRules,
  createAddressGroups,
  createInterfaces,
  createInterfaceManagementPolicies,
  createTunnelInterfaces,
};
