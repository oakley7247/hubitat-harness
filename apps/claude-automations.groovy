/**
 * =============================================================================
 * claude-automations.groovy — parent app. Holds the device pool, validates
 * every rule Claude submits, owns the device subscriptions, and dispatches
 * events to the child app that asked for them.
 *
 * Part of: hubitat-harness. Installed on the hub itself. Called by: the MCP
 * server on Sean's Mac, over this app's local OAuth endpoints. Calls: its own
 * child apps (one per rule), and the devices selected in its preferences.
 *
 * Security: this is the project's only inbound listener. Four things bound it.
 * The device pool is chosen by hand in this page and cannot be widened by any
 * endpoint. Every submitted rule is validated against what the hub itself
 * reports a device can do, and rejected whole if any field fails. Devices that
 * guard a physical boundary are refused unless an operator turns them on here,
 * in the hub UI — deliberately not reachable from the network. And a rolling
 * firing-rate trip stops every rule if automations start driving each other.
 * The access token never appears in a log or a response body.
 * =============================================================================
 */

import groovy.json.JsonOutput
import groovy.transform.Field

definition(
    name: "Claude Automations",
    // NOTE: this namespace is the hub's identity for the app, and the child
    // app matches its `parent:` against it. The repo renaming to hubitat-harness
    // does not rename this — changing it would orphan every rule instance
    // already installed on the hub.
    namespace: "hubitat-claude",
    author: "Sean Oakley",
    description: "Lets Claude create automation rules on this hub, bounded by a device pool you choose.",
    category: "Convenience",
    iconUrl: "",
    iconX2Url: "",
    installOnOpen: true,
    singleInstance: true,
    oauth: true
)

preferences {
    page(name: "mainPage")
    page(name: "auditPage")
}

// --- Constants ---------------------------------------------------------------

// SECURITY: a device carrying any of these guards a physical boundary or a
// safety function. Rules touching them are refused unless allowBoundaryDevices
// is set on this page. The list matches GUARDED_CAPABILITIES in server.py; the
// two must stay in step, because a rule is the unattended path to the same
// devices the MCP server guards interactively.
@Field static final List<String> GUARDED_CAPABILITIES = [
    "Lock", "DoorControl", "GarageDoorControl", "Valve", "SecurityKeypad", "Alarm"
]

// SECURITY: capability names describe what a device declares; these describe
// what a command does. Refused on any device whatever it declares, because a
// garage door or gate is commonly wired as a plain relay reporting only Switch.
// Matches GUARDED_COMMANDS in server.py.
@Field static final List<String> GUARDED_COMMANDS = [
    "open", "close", "lock", "unlock", "arm", "armaway", "armhome", "armnight",
    "disarm", "disarmall", "armall", "cancelalerts", "siren", "strobe", "both",
    "setcode", "deletecode", "setcodelength", "setentrydelay", "setexitdelay"
]

@Field static final List<String> TRIGGER_TYPES = ["attribute", "time", "cron", "mode", "button"]
@Field static final List<String> CONDITION_TYPES = ["attribute", "mode", "timeBetween", "dayOfWeek"]
@Field static final List<String> ACTION_TYPES = ["command", "delay", "cancelPending", "setMode", "notify"]

@Field static final List<String> DAY_NAMES = [
    "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"
]

// Bounds on one submitted rule. A rule arriving from the network is untrusted
// input, so its size is capped before it is parsed into subscriptions.
@Field static final Integer MAX_RULES = 50
@Field static final Integer MAX_ACTIONS = 20
@Field static final Integer MAX_CONDITIONS = 10
@Field static final Integer MAX_NAME_CHARS = 80
@Field static final Integer MAX_TEXT_CHARS = 500
@Field static final Integer MAX_ARGS = 4

// The runaway bound. Attributing a firing to the rule that caused it is not
// reliably possible — a device event looks the same whether a person, a rule,
// or another hub app produced it — so the bound is a global rate trip rather
// than a cascade-depth count. Two rules driving each other exceed this within
// seconds; ordinary use never approaches it.
@Field static final Integer MAX_FIRINGS_PER_WINDOW = 30
@Field static final Integer FIRING_WINDOW_SECONDS = 10

// How many audit entries to retain, and how much of each rule's spec to keep
// with it. Bounded because state is persisted on the hub and grows without one.
// The count is lower than it would otherwise be because each entry now carries
// the spec as submitted — which is what makes the history worth reading after a
// rule has been quietly changed.
@Field static final Integer MAX_AUDIT_ENTRIES = 60
@Field static final Integer MAX_AUDIT_SPEC_CHARS = 1500

// Ceiling on a submitted rule, applied at the hub before validation. The MCP
// server caps this too, but a caller holding the token reaches these endpoints
// without going through it, so the bound has to exist on this side as well.
@Field static final Integer MAX_SPEC_CHARS = 16384

// SECURITY: characters refused in a rule name. Stricter than the set below
// because a name has no reason to carry punctuation of any kind.
@Field static final String NAME_FORBIDDEN = "<>&\"'`"

// SECURITY: characters refused in EVERY string a spec persists, at any depth —
// notification text, command arguments, comparison values, and any field a
// later schema adds. Without a tag character there is no element to open, so a
// stored spec cannot carry markup into a page whatever that page later does
// with it. This is the belt to the escaping's braces: the pages escape at the
// sink, and this keeps the durable artifact clean so a sink added later, or one
// that trusts the platform to escape for it, has nothing to render. Kept to the
// tag characters alone so ordinary text — an apostrophe, an ampersand — still
// works in a notification.
@Field static final String MARKUP_FORBIDDEN = "<>"

// Every key the rule schema defines. Anything else is refused rather than
// stored: an unknown key survives into state, back out through GET /rules/:id,
// and into the model's context as durable text nothing ever validated.
@Field static final List<String> RULE_KEYS = ["name", "enabled", "trigger", "conditions", "actions"]
@Field static final List<String> TRIGGER_KEYS = [
    "type", "deviceId", "attribute", "changesTo", "changes", "risesAbove",
    "dropsBelow", "at", "expression", "buttonNumber", "event"
]
@Field static final List<String> CONDITION_KEYS = [
    "type", "deviceId", "attribute", "equals", "notEquals", "greaterThan",
    "lessThan", "in", "from", "to"
]
@Field static final List<String> ACTION_KEYS = [
    "type", "deviceId", "command", "args", "seconds", "cancelOnRetrigger", "mode", "text"
]

@Field static final String CHILD_NAME = "Claude Automation Rule"
// NOTE: matches the child app's own namespace, which stays hubitat-claude for
// the reason given at the definition block above.
@Field static final String CHILD_NAMESPACE = "hubitat-claude"

// --- Pages -------------------------------------------------------------------

Map mainPage() {
    if (!state.accessToken && app.id) {
        // Minting on first view rather than at install: an app installed but
        // never opened has no reason to hold a live credential.
        createAccessToken()
    }

    dynamicPage(name: "mainPage", title: "Claude Automations", install: true, uninstall: true) {
        section("Device pool") {
            paragraph "Claude can only write rules over the devices selected here. " +
                      "It cannot add to this list — you are the only one who can."
            input name: "poolDevices", type: "capability.*", title: "Devices Claude may use",
                  multiple: true, required: false, submitOnChange: true
        }

        section("Safety") {
            input name: "masterEnable", type: "bool", title: "Rules enabled",
                  description: "Turn off to stop every rule acting, without deleting any.",
                  defaultValue: true, submitOnChange: true
            input name: "allowBoundaryDevices", type: "bool",
                  title: "Allow rules to command locks, doors, garage doors, valves, keypads and alarms",
                  description: "Leave off unless you want a rule to be able to unlock a door unattended.",
                  defaultValue: false, submitOnChange: true
            input name: "refuseCloudRequests", type: "bool",
                  title: "Refuse requests that did not arrive over the local network",
                  description: "Hubitat publishes a cloud URL for this app whether or not you use it.",
                  defaultValue: true
            if (atomicState.rateTripped) {
                paragraph "<b>Rules are stopped.</b> More than ${MAX_FIRINGS_PER_WINDOW} firings " +
                          "happened in ${FIRING_WINDOW_SECONDS} seconds, which means rules were " +
                          "triggering each other. Review them below before clearing this."
                input name: "clearTrip", type: "button", title: "Clear and resume"
            }
        }

        section("Rules (${getChildApps().size()} of ${MAX_RULES})") {
            List children = getChildApps().sort { it.getLabel() }
            if (children.isEmpty()) {
                paragraph "No rules yet. Ask Claude to create one."
            }
            children.each { child ->
                String status = child.isRuleEnabled() ? "enabled" : "disabled"
                // SECURITY: everything interpolated here is untrusted. A rule
                // name comes from the model, and describeRule embeds device
                // labels, command names, and action text — all of them written
                // by whoever configured the device or by whoever influenced the
                // model. Hubitat renders `paragraph` as HTML, and the hub's
                // admin origin has no login by default, so an unescaped label
                // is script execution with rights to install Groovy and read
                // both tokens. Every value goes through safe() (ledger LL-9:
                // neutralize the downstream grammar at the point of use).
                paragraph "<b>${safe(child.getLabel())}</b> — ${status}, fired " +
                          "${child.getFireCount()} times. ${safe(child.describeRule())}"
                href name: "open${child.id}", title: "Open this rule", description: "",
                     url: "/installedapp/configure/${child.id}", style: "external"
            }
        }

        section("Connection") {
            if (state.accessToken) {
                paragraph "Endpoint app id: <b>${app.id}</b>. Put this and the token below in " +
                          "the MCP server's .env as HUBITAT_AUTOMATIONS_APP_ID and " +
                          "HUBITAT_AUTOMATIONS_TOKEN."
                // NOTE: the token is displayed on every view of this page, on
                // the hub's own admin page — the same place the Maker API shows
                // its own. It is never logged and never returned by any
                // endpoint. Anyone who can open this page can already read the
                // Maker API token and install Groovy, so displaying it here
                // grants no access they did not have.
                paragraph "Token: <code>${safe(state.accessToken)}</code>"
                input name: "rotateToken", type: "button", title: "Rotate token"
            } else {
                paragraph "No token yet. Enable OAuth for this app under Apps Code, then reopen this page."
            }
        }

        section("History") {
            href name: "auditHref", page: "auditPage", title: "Rule history",
                 description: "Every rule created, changed, or deleted"
        }

        section("Logging") {
            input name: "logEnable", type: "bool", title: "Enable debug logging", defaultValue: false
        }
    }
}

Map auditPage() {
    dynamicPage(name: "auditPage", title: "Rule history") {
        section {
            // The 30-day window the spec calls for. Entries older than that are
            // still retained up to MAX_AUDIT_ENTRIES; this is what gets read.
            String cutoff = new Date(now() - (30L * 24 * 60 * 60 * 1000)).format("yyyy-MM-dd HH:mm:ss")
            List entries = ((state.audit ?: []) as List).findAll { (it.at as String) >= cutoff }.reverse()
            if (entries.isEmpty()) {
                paragraph "Nothing in the last 30 days."
            }
            entries.each { Map entry ->
                // SECURITY: the name and the spec are model-supplied. See the
                // note in mainPage — `paragraph` renders HTML.
                paragraph "<b>${safe(entry.at)}</b> — ${safe(entry.action)} — ${safe(entry.name)}" +
                          (entry.spec ? "<br><pre>${safe(entry.spec)}</pre>" : "")
            }
        }
    }
}

void appButtonHandler(String buttonName) {
    switch (buttonName) {
        case "clearTrip":
            atomicState.rateTripped = false
            atomicState.firings = []
            log.warn "Claude Automations: firing-rate trip cleared by hand"
            break
        case "rotateToken":
            // SECURITY: rotation is the answer to a leaked token, and to the
            // cloud endpoint if it turns out it cannot be refused. Hubitat
            // mints a new token and invalidates the old one in one step.
            state.accessToken = null
            createAccessToken()
            log.warn "Claude Automations: access token rotated"
            break
    }
}

// --- Lifecycle ---------------------------------------------------------------

void installed() {
    log.info "Claude Automations installed"
    state.audit = []
    atomicState.firings = []
    atomicState.rateTripped = false
    initialize()
}

void updated() {
    log.info "Claude Automations updated"
    initialize()
}

void initialize() {
    unsubscribe()
    if (state.audit == null) state.audit = []
    if (atomicState.firings == null) atomicState.firings = []
    resubscribeAll()
}

/**
 * Rebuild every device subscription from what the children currently want.
 *
 * Called on install, on update, and whenever a rule is created, changed, or
 * deleted. Rebuilding wholesale rather than adding and removing individually
 * means the subscription set always matches the rules that exist, with no way
 * for a deleted rule to leave one behind.
 */
void resubscribeAll() {
    unsubscribe()
    // NOTE: the parent owns device subscriptions rather than each child owning
    // its own, because the devices live in this app's settings — a child holds
    // only references passed to it. Subscribing here keeps device access and
    // the subscription in the same app, and dedupes: ten rules watching one
    // motion sensor produce one subscription, not ten.
    Set<String> wanted = [] as Set
    getChildApps().each { child ->
        Map sub = child.getDeviceSubscription()
        if (sub) wanted.add("${sub.deviceId}|${sub.attribute}".toString())
    }
    wanted.each { String key ->
        List<String> parts = key.tokenize("|")
        def dev = deviceById(parts[0])
        if (dev) subscribe(dev, parts[1], "onDeviceEvent")
    }
    if (logEnable) log.debug "subscribed to ${wanted.size()} device attributes"
}

// --- Event dispatch ----------------------------------------------------------

/**
 * Route one device event to every rule whose trigger matches it.
 *
 * @param evt The hub event for a subscribed device attribute.
 */
void onDeviceEvent(evt) {
    if (!rulesMayAct()) return
    String deviceId = evt.getDevice()?.id?.toString()
    if (deviceId == null) return

    getChildApps().each { child ->
        Map sub = child.getDeviceSubscription()
        if (sub && sub.deviceId == deviceId && sub.attribute == evt.name) {
            // The child decides whether the value change matches its trigger
            // shape (changesTo, risesAbove, and so on); the parent only routes.
            child.onParentEvent(evt.name, evt.value?.toString())
        }
    }
}

/**
 * Test whether rules may act at all, and charge one firing against the trip.
 *
 * @return true when the master switch is on and the rate trip has not fired.
 */
boolean rulesMayAct() {
    if (settings.masterEnable == false) return false
    if (atomicState.rateTripped) return false
    return true
}

/**
 * Charge one rule firing against the rolling-rate trip.
 *
 * Called by a child immediately before it runs its actions.
 *
 * @return true when the firing may proceed; false once the trip has fired.
 */
boolean chargeFiring() {
    // atomicState rather than state: two device events can be handled close
    // enough together that both would read a stale list and both pass, which
    // is exactly the runaway this is here to catch.
    Long now = now()
    Long cutoff = now - (FIRING_WINDOW_SECONDS * 1000L)
    List recent = ((atomicState.firings ?: []) as List).findAll { (it as Long) > cutoff }
    recent.add(now)
    atomicState.firings = recent

    if (recent.size() > MAX_FIRINGS_PER_WINDOW) {
        atomicState.rateTripped = true
        // SECURITY: this fails closed and stays closed. Clearing it needs a
        // person on the hub's own page, because the condition it detects —
        // rules driving each other — resolves only by changing the rules.
        log.error "Claude Automations: ${recent.size()} rule firings in " +
                  "${FIRING_WINDOW_SECONDS}s. All rules stopped. Clear this on the app's page."
        return false
    }
    return true
}

// --- Endpoints ---------------------------------------------------------------

mappings {
    path("/rules") {
        action: [GET: "apiListRules", POST: "apiCreateRule"]
    }
    path("/rules/:ruleId") {
        action: [GET: "apiGetRule", PUT: "apiUpdateRule", DELETE: "apiDeleteRule"]
    }
    path("/rules/:ruleId/enabled") {
        action: [PUT: "apiSetEnabled"]
    }
    path("/pool") {
        action: [GET: "apiListPool"]
    }
}

/** @return The rule list, without any spec detail. */
Object apiListRules() {
    Object refused = remoteRefusal()
    if (refused != null) return refused
    List rules = getChildApps().collect { child ->
        [
            ruleId : child.id.toString(),
            name   : child.getLabel(),
            enabled: child.isRuleEnabled(),
            fires  : child.getFireCount(),
            lastFired: child.getLastFired(),
            summary: child.describeRule()
        ]
    }
    return respond([rules: rules, poolSize: (settings.poolDevices ?: []).size(),
                    masterEnabled: settings.masterEnable != false, rateTripped: atomicState.rateTripped == true])
}

/** @return One rule with its full spec. */
Object apiGetRule() {
    Object refused = remoteRefusal()
    if (refused != null) return refused
    def child = findChild(params.ruleId)
    if (!child) return respond([error: "No rule with id ${params.ruleId}"], 404)
    return respond([
        ruleId   : child.id.toString(),
        name     : child.getLabel(),
        enabled  : child.isRuleEnabled(),
        fires    : child.getFireCount(),
        lastFired: child.getLastFired(),
        spec     : child.getSpec()
    ])
}

/** @return The devices Claude may use, with their attributes and commands. */
Object apiListPool() {
    Object refused = remoteRefusal()
    if (refused != null) return refused
    List devices = (settings.poolDevices ?: []).collect { dev ->
        [
            deviceId  : dev.id.toString(),
            label     : dev.displayName,
            attributes: dev.getSupportedAttributes().collect { attr ->
                [name: attr.name, dataType: attr.dataType, values: attr.getValues()]
            }.unique { it.name },
            commands  : dev.getSupportedCommands().collect { it.name }.unique(),
            boundary  : isBoundaryDevice(dev)
        ]
    }
    return respond([devices: devices, modes: location.getModes().collect { it.name }])
}

/** Create one rule from a submitted spec. */
Object apiCreateRule() {
    Object refused = remoteRefusal()
    if (refused != null) return refused
    if (getChildApps().size() >= MAX_RULES) {
        return respond([error: "This hub already holds ${MAX_RULES} rules, which is the cap."], 409)
    }
    Map spec = request.JSON as Map
    List<String> errors = validateSpec(spec)
    if (errors) return respond([error: "The rule was refused.", problems: errors], 400)

    def child = addChildApp(CHILD_NAMESPACE, CHILD_NAME, spec.name as String)
    try {
        child.configureRule(spec)
    } catch (Exception e) {
        // The child exists the moment addChildApp returns, so a spec that
        // passes validation and still throws while being applied — a cron
        // expression the hub's own parser rejects, say — would otherwise leave
        // a rule behind after an error response. "Refused whole" has to mean
        // nothing is created.
        deleteChildApp(child.id)
        log.warn "Claude Automations: rolled back '${spec.name}' — ${e.message}"
        return respond([error: "The rule was refused.", problems: ["The hub could not apply it: ${e.message}"]], 400)
    }
    resubscribeAll()
    recordAudit("created", spec.name as String, spec)
    log.info "Claude Automations: created rule '${spec.name}'"
    return respond([ruleId: child.id.toString(), name: child.getLabel(), enabled: child.isRuleEnabled()], 201)
}

/** Replace one rule's spec. */
Object apiUpdateRule() {
    Object refused = remoteRefusal()
    if (refused != null) return refused
    def child = findChild(params.ruleId)
    if (!child) return respond([error: "No rule with id ${params.ruleId}"], 404)

    Map spec = request.JSON as Map
    List<String> errors = validateSpec(spec)
    if (errors) return respond([error: "The rule was refused.", problems: errors], 400)

    // The same rollback the create path got. configureRule assigns the new
    // spec on its first line and then rebuilds schedules, so a trigger the hub
    // itself rejects — a cron string that satisfies the character check but not
    // the Quartz parser — would otherwise persist the new spec, lose the
    // schedules, skip the audit entry, and return a 500 saying nothing changed.
    Map previous = child.getSpec()
    try {
        child.configureRule(spec)
    } catch (Exception e) {
        try {
            child.configureRule(previous)
        } catch (Exception restoreFailure) {
            // Restoring failed too, so the rule is now inert rather than
            // wrong. Say so loudly; it needs a person.
            log.error "Claude Automations: '${child.getLabel()}' could not be restored " +
                      "after a failed update — ${restoreFailure.message}. Review it by hand."
        }
        resubscribeAll()
        log.warn "Claude Automations: update of '${spec.name}' rolled back — ${e.message}"
        return respond([error: "The rule was refused.", problems: ["The hub could not apply it: ${e.message}"]], 400)
    }
    resubscribeAll()
    recordAudit("changed", spec.name as String, spec)
    log.info "Claude Automations: updated rule '${spec.name}'"
    return respond([ruleId: child.id.toString(), name: child.getLabel(), enabled: child.isRuleEnabled()])
}

/** Enable or disable one rule without deleting it. */
Object apiSetEnabled() {
    Object refused = remoteRefusal()
    if (refused != null) return refused
    def child = findChild(params.ruleId)
    if (!child) return respond([error: "No rule with id ${params.ruleId}"], 404)

    Object wanted = (request.JSON as Map)?.enabled
    if (!(wanted instanceof Boolean)) {
        return respond([error: "Body must be {\"enabled\": true} or {\"enabled\": false}."], 400)
    }
    child.setRuleEnabled((Boolean) wanted)
    recordAudit(wanted ? "enabled" : "disabled", child.getLabel())
    return respond([ruleId: child.id.toString(), name: child.getLabel(), enabled: child.isRuleEnabled()])
}

/** Delete one rule and everything it scheduled. */
Object apiDeleteRule() {
    Object refused = remoteRefusal()
    if (refused != null) return refused
    def child = findChild(params.ruleId)
    if (!child) return respond([error: "No rule with id ${params.ruleId}"], 404)

    String name = child.getLabel()
    // Deleting the child app removes its schedules with it; resubscribing then
    // drops the parent-side subscription no remaining rule wants.
    deleteChildApp(child.id)
    resubscribeAll()
    recordAudit("deleted", name)
    log.info "Claude Automations: deleted rule '${name}'"
    return respond([deleted: true, name: name])
}

/**
 * Refuse a request that did not arrive over the local network.
 *
 * @return The refusal response when the request must stop, or null to let it
 *     proceed. A response rather than a boolean, because the caller has to
 *     return it — Hubitat sends what the handler returns.
 */
private Object remoteRefusal() {
    if (settings.refuseCloudRequests == false) return null

    // SECURITY: Hubitat publishes both a local and a cloud URL for any OAuth
    // app, and the cloud one is reachable by anyone holding the token. This
    // project is local-only by design, so the cloud path is refused by
    // comparing the Host header against the hub's own address.
    //
    // NOTE: this defence is unverified against a real hub. If the relay
    // rewrites Host to the hub's address, this check passes cloud traffic
    // silently — which is why the observed value is logged at debug, so it can
    // be confirmed, and why the token can be rotated from the app page. Until
    // it is confirmed, treat the cloud URL as live and keep the token secret.
    String host = null
    request?.headers?.each { key, value ->
        if (key?.toString()?.toLowerCase() == "host") {
            host = (value instanceof List) ? value[0]?.toString() : value?.toString()
        }
    }
    if (logEnable) log.debug "endpoint request Host header: ${host}"

    String localIp = location?.hub?.localIP
    if (host == null || localIp == null) {
        // Fail closed: an unreadable Host header cannot be shown to be local.
        // 409 rather than 403: http_client.py never reads a 401 or 403 body,
        // by design, so a 403 here reaches the operator as "the hub rejected
        // your token" and sends them to rotate a working credential.
        return respond([error: "Refused: this endpoint serves local-network callers only."], 409)
    }
    String hostName = host.tokenize(":")[0]
    if (hostName != localIp && hostName != "localhost" && hostName != "127.0.0.1") {
        log.warn "Claude Automations: refused a request with Host '${hostName}'"
        return respond([error: "Refused: this endpoint serves local-network callers only."], 409)
    }
    return null
}

/**
 * Render a JSON response.
 *
 * @param body The response body.
 * @param status HTTP status, 200 unless given.
 * @return The rendered response, which the caller must return in turn.
 */
private Object respond(Map body, Integer status = 200) {
    // NOTE: no response here ever carries the access token, a device's raw
    // state, or an exception message from the hub. Errors name the field that
    // failed and nothing else.
    //
    // NOTE: the result of render() is RETURNED, not discarded. Hubitat sends
    // what the mapping handler returns; calling render() and then returning
    // null produces HTTP 200 with a zero-length body — which is what every
    // endpoint did until this was corrected. Every caller must likewise
    // `return respond(...)` rather than calling it as a statement.
    return render(contentType: "application/json", data: JsonOutput.toJson(body), status: status)
}

// --- Validation --------------------------------------------------------------

/**
 * Check a submitted rule against the hub's own view of its devices.
 *
 * Every check reads the hub, never the request. A rule that fails any check is
 * refused whole — there is no partial create.
 *
 * @param spec The parsed rule spec.
 * @return A list of problems, empty when the rule is acceptable.
 */
List<String> validateSpec(Map spec) {
    List<String> problems = []
    if (spec == null) return ["The request body was not a JSON object."]

    // The size test is on the serialized form rather than on any one field,
    // because a spec's cost to store and to render is what it weighs in total.
    Integer size = JsonOutput.toJson(spec).length()
    if (size > MAX_SPEC_CHARS) {
        return ["The rule is ${size} characters; the limit is ${MAX_SPEC_CHARS}."]
    }
    problems.addAll(unknownKeys(spec, RULE_KEYS, "the rule"))
    problems.addAll(markupInStrings(spec, "the rule"))

    String name = spec.name as String
    if (!name || name.trim().isEmpty()) {
        problems.add("name is required.")
    } else if (name.length() > MAX_NAME_CHARS) {
        problems.add("name is ${name.length()} characters; the limit is ${MAX_NAME_CHARS}.")
    } else if (NAME_FORBIDDEN.any { name.contains(it) }) {
        problems.add("name may not contain any of ${NAME_FORBIDDEN}.")
    }

    if (spec.enabled != null && !(spec.enabled instanceof Boolean)) {
        problems.add("enabled must be true or false.")
    }

    problems.addAll(validateTrigger(spec.trigger))

    Object conditions = spec.conditions
    if (conditions != null) {
        if (!(conditions instanceof List)) {
            problems.add("conditions must be a list.")
        } else if (conditions.size() > MAX_CONDITIONS) {
            problems.add("conditions holds ${conditions.size()} entries; the limit is ${MAX_CONDITIONS}.")
        } else {
            conditions.eachWithIndex { Object condition, int index ->
                problems.addAll(validateCondition(condition, index))
            }
        }
    }

    Object actions = spec.actions
    if (!(actions instanceof List) || ((List) actions).isEmpty()) {
        problems.add("actions must be a non-empty list.")
    } else if (((List) actions).size() > MAX_ACTIONS) {
        problems.add("actions holds ${((List) actions).size()} entries; the limit is ${MAX_ACTIONS}.")
    } else {
        ((List) actions).eachWithIndex { Object action, int index ->
            problems.addAll(validateAction(action, index))
        }
    }

    return problems
}

/** @return Problems with the trigger, empty when it is acceptable. */
private List<String> validateTrigger(Object raw) {
    if (!(raw instanceof Map)) return ["trigger is required and must be an object."]
    Map trigger = (Map) raw
    String type = trigger.type as String
    if (!TRIGGER_TYPES.contains(type)) {
        return ["trigger.type must be one of ${TRIGGER_TYPES.join(', ')}; got ${type}."]
    }

    List<String> problems = unknownKeys(trigger, TRIGGER_KEYS, "trigger")
    switch (type) {
        case "attribute":
            problems.addAll(checkDeviceAttribute(trigger.deviceId as String, trigger.attribute as String, "trigger"))
            List<String> shapes = ["changesTo", "changes", "risesAbove", "dropsBelow"]
            List<String> given = shapes.findAll { trigger.containsKey(it) }
            if (given.size() != 1) {
                problems.add("trigger must carry exactly one of ${shapes.join(', ')}; got ${given.size()}.")
            } else if (given[0] == "changesTo") {
                problems.addAll(checkAttributeValue(
                    trigger.deviceId as String, trigger.attribute as String,
                    trigger.changesTo, "trigger.changesTo"))
            } else if (given[0] != "changes" && !(trigger[given[0]] instanceof Number)) {
                problems.add("trigger.${given[0]} must be a number.")
            }
            break
        case "time":
            problems.addAll(checkTimeSpec(trigger.at, "trigger.at"))
            break
        case "cron":
            String expression = trigger.expression as String
            // Kept to the characters a Quartz expression uses. The hub parses
            // it; this only keeps anything else from reaching the parser.
            if (!expression || !(expression ==~ /[0-9A-Za-z \*\?\/,\-#]{1,120}/)) {
                problems.add("trigger.expression must be a cron expression.")
            }
            break
        case "mode":
            problems.addAll(checkModeName(trigger.changesTo as String, "trigger.changesTo"))
            break
        case "button":
            def dev = deviceById(trigger.deviceId as String)
            if (!dev) {
                problems.add("trigger.deviceId ${trigger.deviceId} is not in the device pool.")
            }
            if (!(trigger.buttonNumber instanceof Number)) {
                problems.add("trigger.buttonNumber must be a number.")
            }
            if (!(["pushed", "held", "doubleTapped"].contains(trigger.event as String))) {
                problems.add("trigger.event must be pushed, held, or doubleTapped.")
            }
            break
    }
    return problems
}

/** @return Problems with one condition, empty when it is acceptable. */
private List<String> validateCondition(Object raw, int index) {
    if (!(raw instanceof Map)) return ["conditions[${index}] must be an object."]
    Map condition = (Map) raw
    String type = condition.type as String
    if (!CONDITION_TYPES.contains(type)) {
        return ["conditions[${index}].type must be one of ${CONDITION_TYPES.join(', ')}; got ${type}."]
    }

    List<String> problems = unknownKeys(condition, CONDITION_KEYS, "conditions[${index}]")
    switch (type) {
        case "attribute":
            problems.addAll(checkDeviceAttribute(
                condition.deviceId as String, condition.attribute as String, "conditions[${index}]"))
            List<String> comparisons = ["equals", "notEquals", "greaterThan", "lessThan"]
            List<String> given = comparisons.findAll { condition.containsKey(it) }
            if (given.size() != 1) {
                problems.add("conditions[${index}] must carry exactly one of ${comparisons.join(', ')}.")
            } else if (given[0] in ["greaterThan", "lessThan"] && !(condition[given[0]] instanceof Number)) {
                problems.add("conditions[${index}].${given[0]} must be a number.")
            } else if (given[0] in ["equals", "notEquals"]) {
                problems.addAll(checkAttributeValue(
                    condition.deviceId as String, condition.attribute as String,
                    condition[given[0]], "conditions[${index}].${given[0]}"))
            }
            break
        case "mode":
            if (!(condition.'in' instanceof List) || ((List) condition.'in').isEmpty()) {
                problems.add("conditions[${index}].in must be a non-empty list of mode names.")
            } else {
                ((List) condition.'in').each { Object mode ->
                    problems.addAll(checkModeName(mode as String, "conditions[${index}].in"))
                }
            }
            break
        case "timeBetween":
            problems.addAll(checkTimeSpec(condition.from, "conditions[${index}].from"))
            problems.addAll(checkTimeSpec(condition.to, "conditions[${index}].to"))
            break
        case "dayOfWeek":
            if (!(condition.'in' instanceof List) || ((List) condition.'in').isEmpty()) {
                problems.add("conditions[${index}].in must be a non-empty list of day names.")
            } else {
                ((List) condition.'in').each { Object day ->
                    if (!DAY_NAMES.contains(day as String)) {
                        problems.add("conditions[${index}].in holds ${day}, which is not a day name.")
                    }
                }
            }
            break
    }
    return problems
}

/** @return Problems with one action, empty when it is acceptable. */
private List<String> validateAction(Object raw, int index) {
    if (!(raw instanceof Map)) return ["actions[${index}] must be an object."]
    Map action = (Map) raw
    String type = action.type as String
    if (!ACTION_TYPES.contains(type)) {
        return ["actions[${index}].type must be one of ${ACTION_TYPES.join(', ')}; got ${type}."]
    }

    List<String> problems = unknownKeys(action, ACTION_KEYS, "actions[${index}]")
    switch (type) {
        case "command":
            problems.addAll(checkCommand(action, index))
            break
        case "delay":
            if (!(action.seconds instanceof Number) || (action.seconds as Integer) < 1
                || (action.seconds as Integer) > 86400) {
                problems.add("actions[${index}].seconds must be a number between 1 and 86400.")
            }
            if (action.cancelOnRetrigger != null && !(action.cancelOnRetrigger instanceof Boolean)) {
                problems.add("actions[${index}].cancelOnRetrigger must be true or false.")
            }
            break
        case "cancelPending":
            break
        case "setMode":
            // SECURITY: gated with the locks rather than with the lights,
            // because on most hubs the mode drives Hubitat Safety Monitor —
            // "set mode to Home" is a disarm. Matches set_mode in server.py.
            if (settings.allowBoundaryDevices != true) {
                problems.add("actions[${index}] sets the hub mode, which commonly arms or disarms " +
                             "security. Turn on boundary devices on the app's page to allow it.")
            }
            problems.addAll(checkModeName(action.mode as String, "actions[${index}].mode"))
            break
        case "notify":
            def dev = deviceById(action.deviceId as String)
            if (!dev) {
                problems.add("actions[${index}].deviceId ${action.deviceId} is not in the device pool.")
            } else if (!dev.hasCommand("deviceNotification")) {
                problems.add("actions[${index}].deviceId ${action.deviceId} cannot receive notifications.")
            }
            String text = action.text as String
            if (!text || text.trim().isEmpty()) {
                problems.add("actions[${index}].text is required.")
            } else if (text.length() > MAX_TEXT_CHARS) {
                problems.add("actions[${index}].text is over ${MAX_TEXT_CHARS} characters.")
            }
            break
    }
    return problems
}

/** @return Problems with a command action, empty when it is acceptable. */
private List<String> checkCommand(Map action, int index) {
    List<String> problems = []
    String deviceId = action.deviceId as String
    def dev = deviceById(deviceId)
    if (!dev) {
        return ["actions[${index}].deviceId ${deviceId} is not in the device pool."]
    }

    String command = action.command as String
    // SECURITY: the allowlist is the device's own reported command list, read
    // from the hub now — not a list carried in this code, and not the model's
    // belief about the device.
    if (!command || !dev.hasCommand(command)) {
        problems.add("actions[${index}].command ${command} is not a command " +
                     "${dev.displayName} accepts.")
    }

    if (settings.allowBoundaryDevices != true) {
        if (isBoundaryDevice(dev)) {
            problems.add("actions[${index}] commands ${dev.displayName}, which guards a physical " +
                         "or safety boundary. Turn on boundary devices on the app's page to allow it.")
        }
        if (command && GUARDED_COMMANDS.contains(command.toLowerCase(Locale.ROOT))) {
            problems.add("actions[${index}].command ${command} opens, closes, locks, unlocks, or " +
                         "arms something. Turn on boundary devices on the app's page to allow it.")
        }
    }

    Object args = action.args
    if (args != null) {
        if (!(args instanceof List)) {
            problems.add("actions[${index}].args must be a list.")
        } else if (((List) args).size() > MAX_ARGS) {
            problems.add("actions[${index}].args holds more than ${MAX_ARGS} values.")
        } else {
            ((List) args).each { Object arg ->
                if (!(arg instanceof Number) && !(arg instanceof String) && !(arg instanceof Boolean)) {
                    problems.add("actions[${index}].args may hold only numbers, strings, and booleans.")
                } else if (arg instanceof String && ((String) arg).length() > MAX_TEXT_CHARS) {
                    problems.add("actions[${index}].args holds a string over ${MAX_TEXT_CHARS} characters.")
                }
            }
        }
    }
    return problems
}

/**
 * Refuse tag characters anywhere in a spec's strings.
 *
 * @param value The spec, or any part of one.
 * @param label What to call this object in the message.
 * @return A problem naming the offending text, or an empty list.
 */
private List<String> markupInStrings(Object value, String label) {
    // The walk is over every nested value rather than the fields the schema
    // names today, for the same reason the id walk on the Mac side is: a field
    // added later must not be able to carry markup past a check that was only
    // ever taught about its siblings.
    if (value instanceof String) {
        if (MARKUP_FORBIDDEN.any { value.contains(it) }) {
            return ["${label} contains a < or > character, which is refused in a rule."]
        }
        return []
    }
    List<String> problems = []
    if (value instanceof Map) {
        value.each { key, entry -> problems.addAll(markupInStrings(entry, "${label}.${key}")) }
    } else if (value instanceof List) {
        value.eachWithIndex { entry, int index -> problems.addAll(markupInStrings(entry, "${label}[${index}]")) }
    }
    return problems
}

/**
 * Refuse keys the schema does not define.
 *
 * @param given The submitted object.
 * @param allowed Every key the schema defines at this level.
 * @param label What to call this object in the message.
 * @return A problem naming the unknown keys, or an empty list.
 */
private List<String> unknownKeys(Map given, List<String> allowed, String label) {
    // An unrecognized key is refused rather than ignored. Ignoring it would
    // persist it into state, return it from GET /rules/:id, and put unvalidated
    // text back into the model's context on every read.
    List<String> extra = given.keySet().collect { it as String }.findAll { !allowed.contains(it) }
    if (extra.isEmpty()) return []
    return ["${label} holds keys the rule schema does not define: ${extra.join(', ')}."]
}

/** @return Problems with a device-and-attribute pair, empty when acceptable. */
private List<String> checkDeviceAttribute(String deviceId, String attribute, String label) {
    def dev = deviceById(deviceId)
    if (!dev) return ["${label}.deviceId ${deviceId} is not in the device pool."]
    if (!attribute) return ["${label}.attribute is required."]
    List<String> names = dev.getSupportedAttributes().collect { it.name }
    if (!names.contains(attribute)) {
        return ["${label}.attribute ${attribute} is not reported by ${dev.displayName}."]
    }
    return []
}

/** @return Problems with a value compared against an ENUM attribute. */
private List<String> checkAttributeValue(String deviceId, String attribute, Object value, String label) {
    if (value == null) return ["${label} is required."]
    def dev = deviceById(deviceId)
    if (!dev) return []
    def attr = dev.getSupportedAttributes().find { it.name == attribute }
    if (attr == null) return []
    List values = attr.getValues()
    // Only ENUM attributes carry a value list. For the rest, any scalar goes —
    // the device itself is the judge at fire time.
    if (values && !values.isEmpty() && !values.contains(value as String)) {
        return ["${label} is ${value}, which ${dev.displayName} never reports for " +
                "${attribute}. It reports: ${values.join(', ')}."]
    }
    return []
}

/** @return Problems with a clock time or sun anchor, empty when acceptable. */
private List<String> checkTimeSpec(Object raw, String label) {
    if (raw instanceof String) {
        if (raw ==~ /([01][0-9]|2[0-3]):[0-5][0-9]/) return []
        if (raw in ["sunrise", "sunset"]) return []
        return ["${label} must be HH:mm, sunrise, or sunset."]
    }
    if (raw instanceof Map) {
        if (!(raw.at in ["sunrise", "sunset"])) {
            return ["${label}.at must be sunrise or sunset."]
        }
        if (raw.offsetMinutes != null && !(raw.offsetMinutes instanceof Number)) {
            return ["${label}.offsetMinutes must be a number."]
        }
        if (raw.offsetMinutes != null && Math.abs((raw.offsetMinutes as Integer)) > 720) {
            return ["${label}.offsetMinutes must be within 720 minutes."]
        }
        return []
    }
    return ["${label} is required."]
}

/** @return Problems with a mode name, empty when the hub has that mode. */
private List<String> checkModeName(String name, String label) {
    if (!name) return ["${label} is required."]
    List names = location.getModes().collect { it.name }
    if (!names.contains(name)) {
        return ["${label} is ${name}, which is not a mode on this hub. It has: ${names.join(', ')}."]
    }
    return []
}

// --- Device access -----------------------------------------------------------

/**
 * Return a device from the pool by its hub id.
 *
 * This is the only way a child app reaches a device, and the pool is the only
 * source — so a rule can never act on a device outside it, whatever its spec
 * says, and whether the spec was checked at creation or not.
 *
 * @param deviceId The hub's numeric device id, as a string.
 * @return The device, or null when it is not in the pool.
 */
def deviceById(String deviceId) {
    if (deviceId == null) return null
    return (settings.poolDevices ?: []).find { it.id.toString() == deviceId }
}

/** @return true when the device declares a capability that guards a boundary. */
boolean isBoundaryDevice(dev) {
    if (dev == null) return true
    return GUARDED_CAPABILITIES.any { dev.hasCapability(it) }
}

/** @return true when rules may command boundary devices. */
boolean boundaryDevicesAllowed() {
    return settings.allowBoundaryDevices == true
}

/** @return true when the given command name crosses a boundary. */
boolean isGuardedCommand(String command) {
    // SECURITY: Locale.ROOT, not the JVM default. Under a Turkish or
    // Azerbaijani locale the default lowercases "SIREN" to "sıren" — a dotless
    // ı that matches nothing in the list, so a boundary command would sail
    // through a check that reads as though it caught it.
    return command != null && GUARDED_COMMANDS.contains(command.toLowerCase(Locale.ROOT))
}

// --- Helpers -----------------------------------------------------------------

/** @return The child app with this id, or null. */
private Object findChild(String ruleId) {
    if (ruleId == null || !(ruleId ==~ /[0-9]{1,12}/)) return null
    return getChildApps().find { it.id.toString() == ruleId }
}

/**
 * Append one entry to the retained rule history.
 *
 * @param action What happened: created, changed, enabled, disabled, deleted.
 * @param name The rule's name at the time.
 * @param spec The spec as submitted, or null for actions that carry none.
 */
void recordAudit(String action, String name, Map spec = null) {
    List audit = (state.audit ?: []) as List
    // The spec is stored, not just the name. A rule written under a prompt
    // injection and then quietly updated would otherwise leave only "created"
    // and "changed" behind, with no record of what it actually did — and this
    // history is the one detective control over that.
    String recorded = null
    if (spec != null) {
        String serialized = JsonOutput.toJson(spec)
        recorded = serialized.length() > MAX_AUDIT_SPEC_CHARS
            ? serialized.substring(0, MAX_AUDIT_SPEC_CHARS) + "…"
            : serialized
    }
    audit.add([
        at    : new Date().format("yyyy-MM-dd HH:mm:ss"),
        action: action,
        name  : name,
        spec  : recorded
    ])
    // Bounded because state persists on the hub and would otherwise grow
    // without limit.
    while (audit.size() > MAX_AUDIT_ENTRIES) audit.remove(0)
    state.audit = audit
}

/** @return true when debug logging is on. */
boolean debugLogging() {
    return settings.logEnable == true
}

/**
 * Escape a value for the hub's admin page.
 *
 * @param value Any value about to be interpolated into a paragraph.
 * @return The value with HTML metacharacters neutralized.
 */
String safe(Object value) {
    // SECURITY: Hubitat renders `paragraph` content as HTML — that is a
    // documented feature, not a defect — and the hub's admin origin runs
    // without a login unless Hub Login Security is switched on. So every
    // untrusted value reaching a page must be escaped here, at the sink, where
    // it cannot be forgotten by a caller. XmlUtil is what the Groovy sandbox
    // offers; it covers & < > " ' which is the whole set that matters for both
    // element and attribute context.
    if (value == null) return ""
    return groovy.xml.XmlUtil.escapeXml(value.toString())
}
