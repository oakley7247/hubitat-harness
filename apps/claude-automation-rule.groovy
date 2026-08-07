/**
 * =============================================================================
 * claude-automation-rule.groovy — child app. Holds one rule: its trigger, its
 * conditions, and its actions, plus the schedules that fire it.
 *
 * Part of: hubitat-harness. Installed on the hub itself, always as a child of
 * Claude Automations. Called by: the parent, which routes device events here
 * and supplies every device this app touches. Calls: devices, through the
 * parent's pool.
 *
 * Security: this app reaches no device on its own — parent.deviceById is the
 * only route, and it serves only the pool the operator chose by hand. Every
 * boundary check the parent ran at creation runs again here at fire time,
 * because a device can be removed from the pool or swapped for another driver
 * long after a rule was written. Nothing in a rule spec is ever evaluated as
 * code; the spec is data read by the switch statements below.
 * =============================================================================
 */

import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import groovy.transform.Field

definition(
    name: "Claude Automation Rule",
    // NOTE: this namespace is the hub's identity for the app, and the child
    // app matches its `parent:` against it. The repo renaming to hubitat-harness
    // does not rename this — changing it would orphan every rule instance
    // already installed on the hub.
    namespace: "hubitat-claude",
    author: "Sean Oakley",
    description: "One automation rule, created and maintained by Claude.",
    category: "Convenience",
    parent: "hubitat-claude:Claude Automations",
    iconUrl: "",
    iconX2Url: ""
)

preferences {
    page(name: "rulePage")
}

// --- Constants ---------------------------------------------------------------

// Bounds how fast one rule can re-fire. A contact sensor that chatters, or a
// light whose own state change re-triggers the rule that set it, is stopped
// here before it reaches the parent's rate trip.
@Field static final Long MIN_REFIRE_MILLIS = 1000L

// The parent enforces the same ceiling when it validates. Repeated here so the
// executor cannot be walked past the end of a spec that arrived another way.
@Field static final Integer MAX_ACTIONS = 20

// --- Page --------------------------------------------------------------------

Map rulePage() {
    dynamicPage(name: "rulePage", title: safe(app.getLabel() ?: "Rule"), install: true, uninstall: true) {
        section("What this rule does") {
            // SECURITY: describeRule embeds the rule name, device labels,
            // command names, and action text — model-supplied or set by
            // whoever configured the device. Hubitat renders `paragraph` as
            // HTML on an admin origin that has no login by default, so every
            // one of them is escaped at this sink.
            paragraph safe(describeRule())
        }

        section("Control") {
            input name: "ruleEnabled", type: "bool", title: "Rule enabled",
                  defaultValue: true, submitOnChange: true
            input name: "runNow", type: "button", title: "Run now",
                  description: "Runs the actions, skipping the trigger and conditions."
        }

        section("Status") {
            paragraph "Fired ${state.fireCount ?: 0} times. " +
                      "Last fired: ${safe(state.lastFired ?: 'never')}."
            // lastError carries device labels and command names from a refusal.
            if (state.lastError) paragraph "Last problem: ${safe(state.lastError)}"
        }

        section("Rule spec") {
            // SECURITY: the stored spec is DISPLAYED here, escaped, and never
            // used to populate an input. An earlier version wrote it into the
            // textarea below and relied on Hubitat to escape a setting value —
            // an assumption about the platform that could not be tested, on the
            // same platform whose `paragraph` renders raw HTML by design. A
            // spec carrying "</textarea>" would have broken out of the field
            // and run script on an admin origin that has no login by default.
            // Display and edit are now separate: nothing stored reaches an
            // input, so there is no element for a payload to escape from.
            paragraph "<b>What is stored now</b><pre>${safe(prettySpec())}</pre>"
            paragraph "Claude wrote this. To change it by hand, paste a complete replacement " +
                      "below — it is checked against your device pool exactly as Claude's was. " +
                      "Leave the box empty to change nothing."
            input name: "rawSpec", type: "textarea", title: "Replacement JSON", rows: 14,
                  submitOnChange: false
            input name: "applySpec", type: "button", title: "Apply replacement"
            if (state.specErrors) {
                String listed = ((List) state.specErrors).collect { safe(it) }.join("<br>")
                paragraph "<b>Refused:</b><br>${listed}"
            }
        }
    }
}

void appButtonHandler(String buttonName) {
    switch (buttonName) {
        case "runNow":
            // The master switch and the rate trip are a kill switch, so they
            // have to hold on every path that reaches an action — including
            // this one. Without the check, "stop every rule" would be untrue
            // of the one button that sits next to it.
            if (!isRuleEnabled()) {
                note("Run now refused: this rule is disabled")
                return
            }
            if (!parent.rulesMayAct()) {
                note("Run now refused: rules are stopped on the parent app")
                return
            }
            log.info "${app.getLabel()}: running actions by hand"
            runActionsFrom(0)
            break
        case "applySpec":
            applyEditedSpec()
            break
    }
}

/** Parse, validate, and store a spec edited by hand on this page. */
private void applyEditedSpec() {
    state.specErrors = null
    String submitted = (settings.rawSpec as String)?.trim()
    if (!submitted) {
        state.specErrors = ["Nothing to apply — paste a complete replacement spec first."]
        return
    }

    Map parsed
    try {
        parsed = new JsonSlurper().parseText(submitted) as Map
    } catch (Exception e) {
        state.specErrors = ["That is not valid JSON: ${e.message}"]
        return
    }
    // SECURITY: a hand edit goes through the parent's validator, the same one
    // the endpoints use. There is no path into state.spec that skips it.
    List<String> problems = parent.validateSpec(parsed)
    if (problems) {
        state.specErrors = problems
        return
    }

    Map previous = getSpec()
    try {
        configureRule(parsed)
    } catch (Exception e) {
        configureRule(previous)
        state.specErrors = ["The hub could not apply it: ${e.message}"]
        return
    }
    parent.resubscribeAll()
    // The history has to cover this path too. A rule quietly changed on its own
    // page would otherwise leave no record at all, which is exactly the case
    // the history exists to catch.
    parent.recordAudit("edited by hand", parsed.name as String, parsed)
    // The box is cleared so the next view shows only what is stored, and a
    // stale replacement cannot be reapplied by a second click.
    app.updateSetting("rawSpec", [value: "", type: "textarea"])
    log.info "${app.getLabel()}: spec replaced by hand"
}

// --- Lifecycle ---------------------------------------------------------------

void installed() {
    state.fireCount = 0
    initialize()
}

void updated() {
    initialize()
}

void initialize() {
    unsubscribe()
    unschedule()
    if (state.spec) refreshTriggers()
}

// --- Parent interface --------------------------------------------------------

/**
 * Replace this rule's spec and rebuild everything it schedules.
 *
 * The parent validates before calling this; nothing here re-parses or
 * re-checks the spec's shape.
 *
 * @param spec A validated rule spec.
 */
void configureRule(Map spec) {
    state.spec = spec
    state.specErrors = null
    app.updateLabel(spec.name as String)
    // An absent `enabled` means enabled: a rule is created to run.
    Boolean wanted = (spec.enabled instanceof Boolean) ? (Boolean) spec.enabled : true
    app.updateSetting("ruleEnabled", [value: wanted.toString(), type: "bool"])
    // The replacement box is deliberately NOT populated from the spec — see the
    // note on the page. It is cleared instead, so what is displayed and what is
    // editable never share a value.
    app.updateSetting("rawSpec", [value: "", type: "textarea"])
    refreshTriggers()
}

/**
 * Report the one device attribute this rule needs the parent to watch.
 *
 * @return A map of deviceId and attribute, or null for a rule triggered by
 *     time, cron, or mode — none of which involve a pooled device.
 */
Map getDeviceSubscription() {
    Map trigger = (state.spec?.trigger ?: [:]) as Map
    switch (trigger.type) {
        case "attribute":
            return [deviceId: trigger.deviceId as String, attribute: trigger.attribute as String]
        case "button":
            // The hub reports a button press as an attribute event named for
            // the press type, so this needs no special routing.
            return [deviceId: trigger.deviceId as String, attribute: trigger.event as String]
        default:
            return null
    }
}

/**
 * Handle a device event the parent routed here.
 *
 * @param attribute The attribute that changed.
 * @param value Its new value, as the hub reported it.
 */
void onParentEvent(String attribute, String value) {
    Map trigger = (state.spec?.trigger ?: [:]) as Map
    if (trigger.type == "button") {
        if ((trigger.buttonNumber as String) != value) return
        fire("button ${value} ${attribute}")
        return
    }
    if (!triggerMatches(trigger, value)) {
        // Still record the value, so a crossing test has something to compare
        // against next time even when this event did not fire the rule.
        state.lastValue = value
        return
    }
    state.lastValue = value
    fire("${attribute} ${value}")
}

/** @return true when this rule is enabled. */
boolean isRuleEnabled() {
    return settings.ruleEnabled != false
}

/** Turn this rule on or off without deleting it. */
void setRuleEnabled(boolean wanted) {
    app.updateSetting("ruleEnabled", [value: wanted.toString(), type: "bool"])
    if (!wanted) {
        // Drop anything already waiting, so disabling takes effect now rather
        // than after an outstanding delay expires.
        unschedule("resumeActions")
    }
    log.info "${app.getLabel()}: ${wanted ? 'enabled' : 'disabled'}"
}

/** @return How many times this rule has fired. */
Integer getFireCount() {
    return (state.fireCount ?: 0) as Integer
}

/** @return When this rule last fired, or null. */
String getLastFired() {
    return state.lastFired as String
}

/** @return The stored spec. */
Map getSpec() {
    return (state.spec ?: [:]) as Map
}

// --- Triggers ----------------------------------------------------------------

/** Rebuild the schedules and location subscriptions this rule's trigger needs. */
private void refreshTriggers() {
    unsubscribe()
    unschedule("onTimeTrigger")
    unschedule("onSunTrigger")
    unschedule("rescheduleSunTrigger")

    Map trigger = (state.spec?.trigger ?: [:]) as Map
    switch (trigger.type) {
        case "time":
            scheduleTimeTrigger(trigger.at)
            break
        case "cron":
            schedule(trigger.expression as String, "onTimeTrigger")
            break
        case "mode":
            subscribe(location, "mode", "onModeEvent")
            break
        // attribute and button triggers are subscribed by the parent, which
        // owns the devices; nothing to do here.
    }
}

/**
 * Schedule a time trigger, whether a clock time or a sun anchor.
 *
 * @param at A "HH:mm" string, "sunrise"/"sunset", or a map with an offset.
 */
private void scheduleTimeTrigger(Object at) {
    if (at instanceof String && (at ==~ /([01][0-9]|2[0-3]):[0-5][0-9]/)) {
        List<String> parts = ((String) at).tokenize(":")
        schedule("0 ${parts[1].toInteger()} ${parts[0].toInteger()} * * ?", "onTimeTrigger")
        return
    }
    // Sun anchors move daily, so the next one is scheduled individually and
    // the handler books the following day. The 00:05 job is the safety net for
    // a hub that missed a firing overnight and so never rebooked.
    scheduleNextSunTrigger()
    schedule("0 5 0 * * ?", "rescheduleSunTrigger")
}

/** Book the next occurrence of this rule's sun anchor. */
private void scheduleNextSunTrigger() {
    Map anchor = sunAnchor(state.spec?.trigger?.at)
    if (anchor == null) return
    Map sun = getSunriseAndSunset([
        sunriseOffset: anchor.name == "sunrise" ? anchor.offset : 0,
        sunsetOffset : anchor.name == "sunset" ? anchor.offset : 0
    ])
    Date next = (anchor.name == "sunrise") ? sun.sunrise : sun.sunset
    if (next == null) return
    if (next.time <= now()) {
        // Today's has passed; the 00:05 job books tomorrow's.
        return
    }
    runOnce(next, "onSunTrigger")
}

/** Rebook the sun trigger for today. Runs shortly after midnight. */
void rescheduleSunTrigger() {
    scheduleNextSunTrigger()
}

/** Fire on a scheduled clock time or cron expression. */
void onTimeTrigger() {
    fire("schedule")
}

/** Fire on a sun anchor, then book the next one. */
void onSunTrigger() {
    fire("sun")
    scheduleNextSunTrigger()
}

/** Fire when the hub mode becomes the one this rule watches. */
void onModeEvent(evt) {
    if (evt.value != (state.spec?.trigger?.changesTo as String)) return
    fire("mode ${evt.value}")
}

/**
 * Test a device event against this rule's trigger shape.
 *
 * @param trigger The trigger portion of the spec.
 * @param value The new attribute value.
 * @return true when the event should fire the rule.
 */
private boolean triggerMatches(Map trigger, String value) {
    if (trigger.containsKey("changes")) return true
    if (trigger.containsKey("changesTo")) return value == (trigger.changesTo as String)

    // Both crossing tests need the previous value: "rises above 20" must fire
    // on the step from 19 to 21 and stay quiet from 21 to 22, which a test on
    // the current value alone cannot tell apart.
    BigDecimal current = toNumber(value)
    BigDecimal previous = toNumber(state.lastValue as String)
    if (current == null) return false
    if (trigger.containsKey("risesAbove")) {
        BigDecimal threshold = toNumber(trigger.risesAbove as String)
        return threshold != null && current > threshold && (previous == null || previous <= threshold)
    }
    if (trigger.containsKey("dropsBelow")) {
        BigDecimal threshold = toNumber(trigger.dropsBelow as String)
        return threshold != null && current < threshold && (previous == null || previous >= threshold)
    }
    return false
}

// --- Firing ------------------------------------------------------------------

/**
 * Run this rule: check the gates, evaluate conditions, then run the actions.
 *
 * @param cause A short description of what triggered it, for the log.
 */
private void fire(String cause) {
    if (!isRuleEnabled()) return
    // SECURITY: the parent's master switch and rate trip are checked on every
    // firing, not cached. A child that had cached "allowed" at install would
    // keep acting after the operator turned rules off.
    if (!parent.rulesMayAct()) return

    // atomicState rather than state, and claimed on entry rather than after
    // the condition checks below. Hubitat caches `state` for the length of one
    // execution and flushes at the end, so two events milliseconds apart would
    // both read the same stale marker and both pass — the interval would exist
    // on paper and not in fact. Claiming it here is what makes it a barrier.
    Long last = (atomicState.lastFiredMillis ?: 0L) as Long
    if (now() - last < MIN_REFIRE_MILLIS) {
        if (parent.debugLogging()) log.debug "${app.getLabel()}: ignored a re-fire inside ${MIN_REFIRE_MILLIS}ms"
        return
    }
    atomicState.lastFiredMillis = now()

    // The global trip is charged only once the conditions hold and the rule is
    // about to act. Charging before this point would let three ordinary rules
    // watching a chatty sensor — an energy meter reporting every second, say —
    // spend the shared budget on firings that do nothing, and stop every rule
    // on the hub with no fault present.
    if (!conditionsHold()) {
        if (parent.debugLogging()) log.debug "${app.getLabel()}: triggered by ${cause}, conditions did not hold"
        return
    }
    if (!parent.chargeFiring()) return

    state.fireCount = getFireCount() + 1
    state.lastFired = new Date().format("yyyy-MM-dd HH:mm:ss")
    if (parent.debugLogging()) log.debug "${app.getLabel()}: firing on ${cause}"

    if (cancelsOnRetrigger()) unschedule("resumeActions")
    runActionsFrom(0)
}

/** @return true when any delay in this rule cancels an outstanding run. */
private boolean cancelsOnRetrigger() {
    return ((state.spec?.actions ?: []) as List).any {
        (it instanceof Map) && it.type == "delay" && it.cancelOnRetrigger == true
    }
}

/** @return true when every condition holds right now. */
private boolean conditionsHold() {
    List conditions = (state.spec?.conditions ?: []) as List
    for (Object raw : conditions) {
        Map condition = raw as Map
        if (!conditionHolds(condition)) return false
    }
    return true
}

/** @return true when one condition holds. */
private boolean conditionHolds(Map condition) {
    switch (condition.type) {
        case "attribute":
            def dev = parent.deviceById(condition.deviceId as String)
            if (dev == null) {
                // A device removed from the pool since the rule was written
                // fails the condition rather than being ignored: the rule was
                // written to depend on it.
                note("condition device ${condition.deviceId} is no longer in the pool")
                return false
            }
            Object current = dev.currentValue(condition.attribute as String)
            if (condition.containsKey("equals")) return (current as String) == (condition.equals as String)
            if (condition.containsKey("notEquals")) return (current as String) != (condition.notEquals as String)
            BigDecimal value = toNumber(current as String)
            if (value == null) return false
            if (condition.containsKey("greaterThan")) {
                return value > toNumber(condition.greaterThan as String)
            }
            if (condition.containsKey("lessThan")) {
                return value < toNumber(condition.lessThan as String)
            }
            return false
        case "mode":
            return ((List) condition.'in').contains(location.mode)
        case "timeBetween":
            Date from = resolveTime(condition.from)
            Date to = resolveTime(condition.to)
            if (from == null || to == null) return false
            return timeOfDayIsBetween(from, to, new Date(), location.timeZone)
        case "dayOfWeek":
            String today = new Date().format("EEEE", location.timeZone)
            return ((List) condition.'in').contains(today)
        default:
            return false
    }
}

// --- Actions -----------------------------------------------------------------

/**
 * Run this rule's actions from one index onward, pausing at any delay.
 *
 * @param startIndex The action to start from.
 */
private void runActionsFrom(Integer startIndex) {
    List actions = (state.spec?.actions ?: []) as List
    Integer index = startIndex

    while (index < actions.size() && index < MAX_ACTIONS) {
        Map action = actions[index] as Map
        if (action.type == "delay") {
            Integer seconds = action.seconds as Integer
            // The rest of the list resumes in a separate execution, which is
            // what keeps a long delay from holding the hub's app thread.
            runIn(seconds, "resumeActions", [data: [index: index + 1], overwrite: true])
            return
        }
        // A failure in one action is recorded and the list continues. A rule
        // shaped [on, delay, off] whose first action throws would otherwise
        // leave the light on with nothing written down anywhere. Validation
        // cannot catch every case — an argument the device rejects at runtime
        // passes creation — so the executor has to survive one.
        try {
            runAction(action)
        } catch (Exception e) {
            note("action ${index} (${action.type}) failed: ${e.message}")
        }
        index = index + 1
    }
}

/** Resume a delayed action list. Scheduled by runActionsFrom. */
void resumeActions(Map data) {
    if (!isRuleEnabled()) return
    if (!parent.rulesMayAct()) return
    runActionsFrom((data?.index ?: 0) as Integer)
}

/** Run one action. */
private void runAction(Map action) {
    switch (action.type) {
        case "command":
            runCommand(action)
            break
        case "cancelPending":
            unschedule("resumeActions")
            break
        case "setMode":
            // SECURITY: re-checked here, not trusted from creation time. The
            // operator can turn boundary devices back off at any moment, and a
            // rule written while they were on must stop setting the mode.
            if (!parent.boundaryDevicesAllowed()) {
                note("refused setMode: boundary devices are off")
                return
            }
            location.setMode(action.mode as String)
            break
        case "notify":
            def dev = parent.deviceById(action.deviceId as String)
            if (dev == null) {
                note("notify device ${action.deviceId} is no longer in the pool")
                return
            }
            dev.deviceNotification(action.text as String)
            break
    }
}

/**
 * Send one device command, re-running every check the parent ran at creation.
 *
 * @param action A validated command action.
 */
private void runCommand(Map action) {
    String deviceId = action.deviceId as String
    String command = action.command as String

    // SECURITY: this is the fire-time half of the guard. A rule is a standing,
    // unattended write — it was approved once, and then runs for months. In
    // that time the device can leave the pool, be swapped for another driver
    // that reports different commands, or the operator can turn boundary
    // devices back off. Every one of those makes a rule that was safe when
    // written unsafe now, so all four checks run again on every firing.
    def dev = parent.deviceById(deviceId)
    if (dev == null) {
        note("refused ${command}: device ${deviceId} is no longer in the pool")
        return
    }
    if (!parent.boundaryDevicesAllowed()) {
        if (parent.isBoundaryDevice(dev)) {
            note("refused ${command}: ${dev.displayName} guards a boundary and boundary devices are off")
            return
        }
        if (parent.isGuardedCommand(command)) {
            note("refused ${command}: that command crosses a boundary and boundary devices are off")
            return
        }
    }
    if (!dev.hasCommand(command)) {
        note("refused ${command}: ${dev.displayName} does not accept it")
        return
    }

    List args = (action.args ?: []) as List
    // NOTE: the argument count is switched on rather than spread, because the
    // hub's Groovy sandbox does not reliably admit the spread operator on a
    // dynamic method call. MAX_ARGS in the parent is what bounds this list.
    switch (args.size()) {
        case 0: dev."${command}"(); break
        case 1: dev."${command}"(args[0]); break
        case 2: dev."${command}"(args[0], args[1]); break
        case 3: dev."${command}"(args[0], args[1], args[2]); break
        default: dev."${command}"(args[0], args[1], args[2], args[3]); break
    }
    if (parent.debugLogging()) log.debug "${app.getLabel()}: ${dev.displayName}.${command}(${args.join(', ')})"
}

// --- Helpers -----------------------------------------------------------------

/**
 * Resolve a time spec to a Date today.
 *
 * @param raw "HH:mm", "sunrise"/"sunset", or a map with an offset.
 * @return The resolved time, or null when the spec cannot be read.
 */
private Date resolveTime(Object raw) {
    if (raw instanceof String && (raw ==~ /([01][0-9]|2[0-3]):[0-5][0-9]/)) {
        return timeToday((String) raw, location.timeZone)
    }
    Map anchor = sunAnchor(raw)
    if (anchor == null) return null
    Map sun = getSunriseAndSunset([
        sunriseOffset: anchor.name == "sunrise" ? anchor.offset : 0,
        sunsetOffset : anchor.name == "sunset" ? anchor.offset : 0
    ])
    return (anchor.name == "sunrise") ? sun.sunrise : sun.sunset
}

/**
 * Read a sun anchor out of either spec shape.
 *
 * @param raw "sunrise", "sunset", or {at: "sunset", offsetMinutes: -15}.
 * @return A map of name and offset, or null when this is not a sun anchor.
 */
private Map sunAnchor(Object raw) {
    if (raw instanceof String && (raw == "sunrise" || raw == "sunset")) {
        return [name: raw, offset: 0]
    }
    if (raw instanceof Map && (raw.at == "sunrise" || raw.at == "sunset")) {
        return [name: raw.at as String, offset: (raw.offsetMinutes ?: 0) as Integer]
    }
    return null
}

/**
 * Parse a value as a number without throwing.
 *
 * @param value The value as the hub reported it.
 * @return The number, or null when it is not one.
 */
private BigDecimal toNumber(String value) {
    if (value == null) return null
    try {
        return new BigDecimal(value.trim())
    } catch (Exception ignored) {
        // A non-numeric value is not an error here — a comparison against it
        // simply does not hold.
        return null
    }
}

/** @return The stored spec, pretty-printed for display. Always escaped by the caller. */
private String prettySpec() {
    if (!state.spec) return "{}"
    return JsonOutput.prettyPrint(JsonOutput.toJson(state.spec))
}

/**
 * Escape a value for the hub's admin page.
 *
 * @param value Any value about to be interpolated into a paragraph.
 * @return The value with HTML metacharacters neutralized.
 *
 * SECURITY: duplicated from the parent rather than called through it. The two
 * apps are separate files installed independently on the hub and share no
 * code, and an escaping helper that depends on a cross-app call is one broken
 * parent reference away from rendering raw markup.
 */
private String safe(Object value) {
    if (value == null) return ""
    return groovy.xml.XmlUtil.escapeXml(value.toString())
}

/**
 * Record a refusal or a problem, to the log and to this rule's page.
 *
 * @param reason Operator-facing explanation.
 */
private void note(String reason) {
    log.warn "${app.getLabel()}: ${reason}"
    state.lastError = "${new Date().format('yyyy-MM-dd HH:mm:ss')} — ${reason}"
}

/** @return A one-line plain-English summary of this rule. */
String describeRule() {
    Map spec = getSpec()
    if (!spec.trigger) return "No rule spec yet."
    return "When ${describeTrigger(spec.trigger as Map)}" +
           (spec.conditions ? ", if ${((List) spec.conditions).collect { describeCondition(it as Map) }.join(' and ')}" : "") +
           ", ${((List) (spec.actions ?: [])).collect { describeAction(it as Map) }.join(', then ')}."
}

/** @return A phrase describing the trigger. */
private String describeTrigger(Map trigger) {
    switch (trigger.type) {
        case "attribute":
            String what = "${deviceLabel(trigger.deviceId as String)} ${trigger.attribute}"
            if (trigger.containsKey("changesTo")) return "${what} becomes ${trigger.changesTo}"
            if (trigger.containsKey("changes")) return "${what} changes"
            if (trigger.containsKey("risesAbove")) return "${what} rises above ${trigger.risesAbove}"
            return "${what} drops below ${trigger.dropsBelow}"
        case "time":
            return "the time reaches ${describeTimeSpec(trigger.at)}"
        case "cron":
            return "the schedule ${trigger.expression} comes round"
        case "mode":
            return "the hub mode becomes ${trigger.changesTo}"
        case "button":
            return "button ${trigger.buttonNumber} on ${deviceLabel(trigger.deviceId as String)} is ${trigger.event}"
        default:
            return "something happens"
    }
}

/** @return A phrase describing one condition. */
private String describeCondition(Map condition) {
    switch (condition.type) {
        case "attribute":
            String what = "${deviceLabel(condition.deviceId as String)} ${condition.attribute}"
            if (condition.containsKey("equals")) return "${what} is ${condition.equals}"
            if (condition.containsKey("notEquals")) return "${what} is not ${condition.notEquals}"
            if (condition.containsKey("greaterThan")) return "${what} is above ${condition.greaterThan}"
            return "${what} is below ${condition.lessThan}"
        case "mode":
            return "the mode is ${((List) condition.'in').join(' or ')}"
        case "timeBetween":
            return "the time is between ${describeTimeSpec(condition.from)} and ${describeTimeSpec(condition.to)}"
        case "dayOfWeek":
            return "it is ${((List) condition.'in').join(' or ')}"
        default:
            return "something holds"
    }
}

/** @return A phrase describing one action. */
private String describeAction(Map action) {
    switch (action.type) {
        case "command":
            String args = action.args ? " (${((List) action.args).join(', ')})" : ""
            return "${action.command}${args} on ${deviceLabel(action.deviceId as String)}"
        case "delay":
            return "wait ${action.seconds}s"
        case "cancelPending":
            return "cancel anything pending"
        case "setMode":
            return "set the mode to ${action.mode}"
        case "notify":
            return "notify ${deviceLabel(action.deviceId as String)}"
        default:
            return "do something"
    }
}

/** @return A phrase describing a time spec. */
private String describeTimeSpec(Object raw) {
    Map anchor = sunAnchor(raw)
    if (anchor == null) return raw as String
    if (anchor.offset == 0) return anchor.name as String
    return "${Math.abs((Integer) anchor.offset)} minutes ${anchor.offset < 0 ? 'before' : 'after'} ${anchor.name}"
}

/** @return The device's label, or its id when it has left the pool. */
private String deviceLabel(String deviceId) {
    def dev = parent.deviceById(deviceId)
    return dev ? dev.displayName : "device ${deviceId} (no longer in the pool)"
}
