/**
 * =============================================================================
 * claude-assistant.groovy — a virtual Hubitat device that asks Claude a
 * question and publishes the answer as a device attribute.
 *
 * Part of: hubitat-claude. Installed on the hub itself. Called by: Rule
 * Machine, dashboards, or the device page, via the askClaude command. Calls:
 * the Anthropic Messages API over HTTPS.
 *
 * Security: the API key lives in a password-type preference and is never
 * logged, never placed in a URL, and never written to an attribute. The call
 * is HTTPS with certificate verification left on. Spend is bounded three ways
 * — a max_tokens ceiling per call, a minimum interval between calls, and a
 * daily call cap — because a misfiring rule can otherwise call this in a loop.
 * =============================================================================
 */

metadata {
    definition(
        name: "Claude Assistant",
        namespace: "hubitat-claude",
        author: "Sean Oakley",
        importUrl: ""
    ) {
        // Actuator makes the device selectable in Rule Machine's custom-action
        // device picker; without a capability it cannot be filtered to.
        capability "Actuator"

        attribute "lastReply", "string"
        attribute "lastAsked", "string"
        attribute "lastError", "string"
        attribute "status", "enum", ["idle", "waiting", "ok", "error"]
        attribute "callsToday", "number"

        command "askClaude", [
            [
                name: "Prompt*",
                type: "STRING",
                description: "The question to ask Claude"
            ]
        ]
        command "clearReply"
    }

    preferences {
        input name: "apiKey", type: "password", title: "Anthropic API key",
              description: "From console.anthropic.com. Stored on the hub; never logged.",
              required: true
        input name: "model", type: "enum", title: "Model",
              options: ["claude-opus-5", "claude-sonnet-5"],
              defaultValue: "claude-opus-5", required: true
        input name: "systemPrompt", type: "text", title: "System prompt",
              description: "Sets Claude's role and voice for every question.",
              defaultValue: "You answer questions for a home-automation hub. Answer in one or two plain sentences. Never use markdown, lists, or headings.",
              required: true
        input name: "maxReplyChars", type: "number", title: "Maximum reply length (characters)",
              description: "Hubitat truncates any attribute over 1024 characters. 1-1024.",
              defaultValue: 500, required: true
        input name: "minSecondsBetweenCalls", type: "number",
              title: "Minimum seconds between calls",
              description: "Refuses calls that arrive faster than this, so a misfiring rule cannot loop.",
              defaultValue: 5, required: true
        input name: "maxCallsPerDay", type: "number", title: "Maximum calls per day",
              description: "Hard ceiling on daily spend. Resets at midnight hub time.",
              defaultValue: 100, required: true
        input name: "logEnable", type: "bool", title: "Enable debug logging",
              defaultValue: false
    }
}

// --- Constants ---------------------------------------------------------------

// Hubitat refuses to store an attribute value longer than this.
@groovy.transform.Field static final Integer HUBITAT_ATTRIBUTE_LIMIT = 1024

// Bounds the request side: a prompt longer than this is refused rather than
// sent, so a rule that concatenates device states in a loop cannot build an
// unbounded request body.
@groovy.transform.Field static final Integer MAX_PROMPT_CHARS = 2000

// Ceiling on what one call can generate and be billed for. On Claude Opus 5
// thinking is on by default and counts against this, so the value must leave
// room for both the reasoning and the short answer the system prompt asks for.
@groovy.transform.Field static final Integer MAX_TOKENS = 2048

// The hub caps any HTTP timeout at 300 seconds. 120 leaves room for a slow
// answer without pinning a callback slot for the full maximum.
@groovy.transform.Field static final Integer HTTP_TIMEOUT_SECONDS = 120

@groovy.transform.Field static final String API_URI = "https://api.anthropic.com"
@groovy.transform.Field static final String API_PATH = "/v1/messages"
@groovy.transform.Field static final String API_VERSION = "2023-06-01"

// Opts into server-side fallback: if a safety classifier declines the request,
// Anthropic re-runs it on a fallback model in the same call rather than
// returning nothing.
@groovy.transform.Field static final String API_BETA = "server-side-fallback-2026-07-01"

// --- Lifecycle ---------------------------------------------------------------

void installed() {
    log.info "Claude Assistant installed"
    sendEvent(name: "status", value: "idle")
    sendEvent(name: "callsToday", value: 0)
    atomicState.callDate = todayKey()
    atomicState.callCount = 0
    atomicState.lastCallMillis = 0L
}

void updated() {
    log.info "Claude Assistant updated"
    log.warn "debug logging is: ${logEnable == true}"
    if (logEnable) runIn(1800, logsOff)
    if (atomicState.callDate == null) {
        atomicState.callDate = todayKey()
        atomicState.callCount = 0
        atomicState.lastCallMillis = 0L
    }
}

void logsOff() {
    log.warn "debug logging disabled..."
    device.updateSetting("logEnable", [value: "false", type: "bool"])
}

void parse(String description) {
    // Required by the driver contract. This device has no inbound protocol
    // traffic — everything arrives through askClaude — so there is nothing
    // to parse.
}

// --- Commands ----------------------------------------------------------------

/**
 * Ask Claude a question and publish the answer to the lastReply attribute.
 *
 * @param prompt The question. Refused if empty or over MAX_PROMPT_CHARS.
 */
void askClaude(String prompt) {
    if (prompt == null || prompt.trim().isEmpty()) {
        fail("Prompt was empty")
        return
    }
    String trimmed = prompt.trim()
    if (trimmed.length() > MAX_PROMPT_CHARS) {
        fail("Prompt was ${trimmed.length()} characters; the limit is ${MAX_PROMPT_CHARS}")
        return
    }
    if (!settings.apiKey) {
        fail("No API key set. Open this device's preferences and add one.")
        return
    }
    // Refusing a concurrent ask is better than accepting it and dropping one
    // of the two answers: a rule waiting on lastReply would otherwise wait
    // forever for a reply that was silently discarded, having already paid
    // for it. This runs before the budget is charged — a question that never
    // goes out must not spend a call, or one hung request would let a 5-second
    // rule burn the whole daily cap without reaching Anthropic once.
    Long inFlightUntil = (atomicState.inFlightUntil ?: 0L) as Long
    if (now() < inFlightUntil) {
        fail("Refused: a question is already in flight. Wait for the reply, or for the ${HTTP_TIMEOUT_SECONDS}s timeout.")
        return
    }
    // SECURITY: the barrier is claimed here, on entry, rather than just before
    // dispatch. Everything between this line and the request — the budget
    // check, two sendEvent calls, building the request map — is time during
    // which a second invocation would otherwise read a stale marker, pass, and
    // dispatch alongside this one. Claiming late narrows the guard to almost
    // nothing; claiming on entry is what makes it a barrier. It is released
    // below if this call turns out not to dispatch.
    atomicState.inFlightUntil = now() + (HTTP_TIMEOUT_SECONDS * 1000L)
    if (!checkCallBudget()) {
        // Nothing was dispatched, so the barrier must come down — otherwise a
        // rate-limited ask would lock the device out for the whole timeout.
        atomicState.inFlightUntil = 0L
        return
    }

    sendEvent(name: "lastAsked", value: clampToAttribute(trimmed), isStateChange: true)
    sendEvent(name: "status", value: "waiting")

    Map params = [
        uri: API_URI,
        path: API_PATH,
        headers: [
            "x-api-key"       : settings.apiKey,
            "anthropic-version": API_VERSION,
            "anthropic-beta"  : API_BETA,
            "content-type"    : "application/json"
        ],
        requestContentType: "application/json",
        contentType: "application/json",
        body: [
            model      : settings.model ?: "claude-opus-5",
            max_tokens : MAX_TOKENS,
            system     : "${settings.systemPrompt}\nKeep the answer under ${replyLimit()} characters.".toString(),
            fallbacks  : "default",
            // Effort low keeps latency and cost down; thinking stays on, which
            // is both the model's default and the recommended setting.
            output_config: [effort: "low"],
            messages   : [[role: "user", content: trimmed]]
        ],
        timeout: HTTP_TIMEOUT_SECONDS
    ]

    // Correlates this request with its callback so a late answer cannot
    // overwrite a newer one. The in-flight marker claimed above expires on its
    // own after the HTTP timeout, so a callback the hub never delivers cannot
    // wedge the device permanently.
    String requestId = "${now()}-${Math.abs(trimmed.hashCode())}".toString()
    atomicState.currentRequestId = requestId

    if (logEnable) log.debug "asking Claude (${trimmed.length()} chars, model ${settings.model})"
    chargeCall()
    // SECURITY: `params` holds the API key in its headers. It is passed
    // straight to the hub's HTTP client and never logged — the debug line
    // above deliberately reports only the prompt length and the model.
    asynchttpPost("claudeCallback", params, [requestId: requestId])
}

/** Clear the stored reply and return the device to idle. */
void clearReply() {
    sendEvent(name: "lastReply", value: "", isStateChange: true)
    sendEvent(name: "lastError", value: "", isStateChange: true)
    sendEvent(name: "status", value: "idle")
}

// --- Response handling -------------------------------------------------------

/**
 * Handle the Messages API response and publish the answer or the failure.
 *
 * @param resp The hub's AsyncResponse for the call.
 * @param data Carries requestId, the correlation key for this call.
 */
void claudeCallback(resp, Map data) {
    String requestId = data?.requestId as String

    // NOTE: the in-flight guard in askClaude keeps at most one request
    // outstanding, so this check is the backstop for the one case it cannot
    // cover: a callback that arrives after its marker expired at the
    // HTTP_TIMEOUT_SECONDS boundary and a newer question was accepted. Without
    // it that stale answer would overwrite the newer one, pairing lastReply
    // with the wrong lastAsked.
    // A missing id is treated as stale rather than trusted: the only caller
    // supplies one, so its absence means this callback is not what it claims.
    if (requestId == null || requestId != atomicState.currentRequestId) {
        log.warn "Claude Assistant: discarded a reply that does not match the request in flight"
        return
    }
    atomicState.inFlightUntil = 0L

    if (resp.hasError()) {
        // Fail closed and loud: an unreachable API is reported, never silently
        // left as a stale reply from an earlier question.
        //
        // SECURITY: the daily charge is NOT returned here. hasError() covers
        // HTTP error statuses and client-side timeouts as well as connection
        // failures, and a timed-out generation was already dispatched and is
        // still billed. Refunding would mean a rule whose calls all fail never
        // advances the counter — and a rule whose calls all fail is exactly
        // the runaway this cap exists to stop.
        fail("Request failed: ${resp.getErrorMessage()}")
        return
    }
    if (resp.status != 200) {
        fail("Anthropic API returned HTTP ${resp.status}")
        return
    }

    Map payload
    try {
        payload = resp.json as Map
    } catch (Exception e) {
        // NOTE: on some responses every AsyncResponse accessor except
        // getStatus() and getHeaders() throws rather than returning null.
        fail("Could not read the API response as JSON: ${e.message}")
        return
    }
    if (payload == null) {
        fail("The API returned an empty response body")
        return
    }

    // Check stop_reason before reading content: a safety-classifier refusal
    // returns HTTP 200 with an empty or partial content array.
    if (payload.stop_reason == "refusal") {
        fail("Claude declined to answer this request")
        return
    }

    String answer = firstTextBlock(payload)
    if (answer == null || answer.trim().isEmpty()) {
        fail("The API returned no text in its response")
        return
    }

    String clamped = clampToAttribute(answer.trim())
    // isStateChange forces the event even when the answer matches the previous
    // one, so a rule triggering on lastReply fires every time.
    sendEvent(name: "lastReply", value: clamped, isStateChange: true,
              descriptionText: "${device.displayName} received a reply from Claude")
    sendEvent(name: "status", value: "ok")
    if (logEnable) log.debug "reply published (${clamped.length()} chars)"
}

/**
 * Pull the first text block out of a Messages API response.
 *
 * @param payload The parsed response body.
 * @return The block's text, or null when the response carries none.
 */
private String firstTextBlock(Map payload) {
    // The content array interleaves thinking and text blocks; thinking blocks
    // carry empty text by default, so the type check is what selects the
    // answer rather than simply taking content[0].
    List blocks = (payload.content instanceof List) ? (List) payload.content : []
    for (Object block : blocks) {
        if (block instanceof Map && block["type"] == "text" && block["text"] instanceof String) {
            return (String) block["text"]
        }
    }
    return null
}

// --- Budget ------------------------------------------------------------------

/** Zero the daily counter when the hub's date has rolled over. */
private void rollDailyCounterIfNeeded() {
    String today = todayKey()
    if (atomicState.callDate != today) {
        atomicState.callDate = today
        atomicState.callCount = 0
    }
}

/**
 * Test the call against the rate and daily-count ceilings without charging.
 *
 * Charging is a separate step (chargeCall) taken immediately before dispatch,
 * so a call refused after this point spends nothing.
 *
 * @return true when the call may proceed; false after reporting the refusal.
 */
private boolean checkCallBudget() {
    Long now = now()
    Integer minGap = (settings.minSecondsBetweenCalls ?: 5) as Integer
    Long since = now - ((atomicState.lastCallMillis ?: 0L) as Long)
    if (since < (minGap * 1000L)) {
        fail("Refused: the last call was ${Math.round(since / 1000)}s ago and the minimum gap is ${minGap}s")
        return false
    }

    rollDailyCounterIfNeeded()
    Integer dailyMax = (settings.maxCallsPerDay ?: 100) as Integer
    Integer used = (atomicState.callCount ?: 0) as Integer
    if (used >= dailyMax) {
        fail("Refused: already made ${used} calls today and the daily cap is ${dailyMax}")
        return false
    }

    return true
}

/**
 * Charge one dispatched call against both ceilings.
 *
 * Called immediately before the HTTP request goes out.
 */
private void chargeCall() {
    // SECURITY: both counters are charged at dispatch, because dispatch is
    // what costs money. Charging on a successful reply instead would miss the
    // two responses Anthropic bills in full but that carry no answer — a
    // safety refusal, and a reply whose thinking exhausted max_tokens. Those
    // are exactly what a misfiring rule produces, so the cap would not bind in
    // the case it exists for. Nothing refunds a charge, for the same reason.
    //
    // atomicState rather than state: Hubitat persists `state` at the end of an
    // execution, so two rules firing at once would both read a stale count and
    // both pass. atomicState commits immediately.
    rollDailyCounterIfNeeded()
    Integer used = (atomicState.callCount ?: 0) as Integer
    atomicState.lastCallMillis = now()
    atomicState.callCount = used + 1
    sendEvent(name: "callsToday", value: used + 1)
}

/** @return The current hub-local date as a yyyy-MM-dd key. */
private String todayKey() {
    return new java.text.SimpleDateFormat("yyyy-MM-dd").format(new Date())
}

// --- Helpers -----------------------------------------------------------------

/** @return The configured reply length, clamped to Hubitat's attribute limit. */
private Integer replyLimit() {
    Integer configured = (settings.maxReplyChars ?: 500) as Integer
    if (configured < 1) return 1
    if (configured > HUBITAT_ATTRIBUTE_LIMIT) return HUBITAT_ATTRIBUTE_LIMIT
    return configured
}

/**
 * Cut a string to something the hub will actually store.
 *
 * @param value The text to publish.
 * @return The text, truncated with an ellipsis when it exceeds the limit.
 */
private String clampToAttribute(String value) {
    Integer limit = replyLimit()
    if (value.length() <= limit) return value
    // Hubitat silently rejects an over-long attribute value, so the truncation
    // happens here where it can be marked visibly rather than at the hub.
    return value.substring(0, Math.max(0, limit - 1)) + "…"
}

/**
 * Report a failure to the logs and to the device's attributes.
 *
 * @param reason Operator-facing explanation. Never include the API key.
 */
private void fail(String reason) {
    log.warn "Claude Assistant: ${reason}"
    sendEvent(name: "status", value: "error")
    // The failure goes to its own attribute rather than into lastReply. A rule
    // triggering on lastReply is waiting for an answer, and would otherwise
    // fire on "Error: ..." text as though it were one.
    sendEvent(name: "lastError", value: clampToAttribute(reason), isStateChange: true)
}
