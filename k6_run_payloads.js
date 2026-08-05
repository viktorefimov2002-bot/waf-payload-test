import http from 'k6/http';
import { check, sleep } from 'k6';
import encoding from 'k6/encoding';

const caseFile = __ENV.CASE_FILE || './current_case.json';
const loaded = JSON.parse(open(caseFile));
const cases = Array.isArray(loaded) ? loaded : [loaded];
const fallbackIndex = Number.parseInt(__ENV.CASE_INDEX || '0', 10);
const targetBase = (__ENV.TARGET_URL || 'https://your-target.com').replace(/\/$/, '');
const runMode = __ENV.RUN_MODE || 'fast';
const rate = Number.parseInt(__ENV.RPS || '10', 10);
const duration = __ENV.DURATION || '30s';
const cooldown = Number.parseFloat(__ENV.COOLDOWN || '0');
const gracefulStop = __ENV.GRACEFUL_STOP || '1s';
const thresholdMode = __ENV.THRESHOLD_MODE || 'disabled';
const lanes = Math.max(1, Number.parseInt(__ENV.PARALLEL_LANES || '1', 10));
const preAllocatedVUs = Number.parseInt(__ENV.PREALLOCATED_VUS || String(Math.max(10, Math.ceil(rate / 5))), 10);
const maxVUs = Number.parseInt(__ENV.MAX_VUS || String(Math.max(preAllocatedVUs, rate * 2)), 10);
const abortOnOverload = (__ENV.ABORT_ON_OVERLOAD || 'false').toLowerCase() === 'true';
const maxDroppedIterations = Number.parseInt(__ENV.MAX_DROPPED_ITERATIONS || '0', 10);
const maxP95Ms = Number.parseFloat(__ENV.MAX_HTTP_REQ_DURATION_P95_MS || '0');
const overloadDelay = __ENV.OVERLOAD_DELAY || '5s';
const batchMode = cases.length > 1;
const highRpsMode = runMode === 'high-rps';

if (!cases.length || cases.some((item) => !item || typeof item !== 'object' || !item.body_base64)) {
    throw new Error(`CASE_FILE=${caseFile} does not contain valid case objects`);
}

function caseIndex(currentCase, offset = 0) {
    return Number.isInteger(currentCase._source_index) ? currentCase._source_index : fallbackIndex + offset;
}

function laneForOffset(offset) {
    return offset % lanes;
}

function durationSeconds(value) {
    const match = /^([0-9]+(?:\.[0-9]+)?)(ms|s|m|h)$/.exec(value);
    if (!match) throw new Error(`Unsupported duration: ${value}`);
    return Number.parseFloat(match[1]) * ({ ms: 0.001, s: 1, m: 60, h: 3600 })[match[2]];
}

function secondsDuration(value) {
    return `${Math.round(value * 1000) / 1000}s`;
}

function addPerScenarioSubmetrics(target) {
    if (!highRpsMode) return;
    for (let offset = 0; offset < cases.length; offset += 1) {
        const scenario = `payload_${offset}`;
        target[`http_reqs{scenario:${scenario}}`] = ['count>=0'];
        target[`http_req_duration{scenario:${scenario}}`] = ['p(95)>=0'];
        target[`http_req_failed{scenario:${scenario}}`] = ['rate>=0'];
        target[`dropped_iterations{scenario:${scenario}}`] = ['count>=0'];
        target[`iterations{scenario:${scenario}}`] = ['count>=0'];
    }
}

function buildThresholds() {
    const result = {};
    if (thresholdMode === 'strict') {
        result.http_req_failed = ['rate<0.05'];
        result.dropped_iterations = ['count==0'];
    }
    if (abortOnOverload) {
        result.dropped_iterations = [{
            threshold: `count<=${maxDroppedIterations}`,
            abortOnFail: true,
            delayAbortEval: overloadDelay,
        }];
        if (maxP95Ms > 0) {
            result.http_req_duration = [{
                threshold: `p(95)<${maxP95Ms}`,
                abortOnFail: true,
                delayAbortEval: overloadDelay,
            }];
        }
    }
    addPerScenarioSubmetrics(result);
    return result;
}

const thresholds = buildThresholds();

function buildHighRpsScenarios() {
    const scenarios = {};
    const slotSeconds = durationSeconds(duration) + durationSeconds(gracefulStop) + cooldown;
    for (let offset = 0; offset < cases.length; offset += 1) {
        const currentCase = cases[offset];
        const index = caseIndex(currentCase, offset);
        const lane = laneForOffset(offset);
        const slot = Math.floor(offset / lanes);
        scenarios[`payload_${offset}`] = {
            executor: 'constant-arrival-rate',
            exec: 'runHighRpsCase',
            rate,
            timeUnit: '1s',
            duration,
            startTime: secondsDuration(slot * slotSeconds),
            gracefulStop,
            preAllocatedVUs,
            maxVUs,
            env: { CASE_OFFSET: String(offset), CASE_LANE: String(lane) },
            tags: {
                payload_id: currentCase.id,
                payload_index: String(index),
                payload_lane: String(lane),
            },
        };
    }
    const activeLanes = Math.min(lanes, cases.length);
    for (let lane = 0; lane < activeLanes; lane += 1) {
        scenarios[`lane_controller_${lane}`] = {
            executor: 'shared-iterations',
            exec: 'highRpsLaneController',
            vus: 1,
            iterations: 1,
            maxDuration: __ENV.BATCH_MAX_DURATION || '24h',
            gracefulStop: '0s',
            env: { CASE_LANE: String(lane) },
            tags: { payload_lane: String(lane), controller: 'true' },
        };
    }
    return scenarios;
}

let scenarios;
if (highRpsMode) {
    scenarios = buildHighRpsScenarios();
} else if (batchMode) {
    scenarios = {
        batch_payloads: {
            executor: 'shared-iterations',
            vus: 1,
            iterations: 1,
            maxDuration: __ENV.BATCH_MAX_DURATION || '24h',
            gracefulStop,
        },
    };
} else {
    scenarios = {
        single_payload: {
            executor: 'constant-arrival-rate',
            rate,
            timeUnit: '1s',
            duration,
            gracefulStop,
            preAllocatedVUs,
            maxVUs,
        },
    };
}

export const options = {
    scenarios,
    thresholds,
    tags: {
        test_run_id: __ENV.RUN_ID || 'manual',
        run_mode: runMode,
        parallel_lanes: String(lanes),
    },
};

function event(name, currentCase, index, extra = {}) {
    console.log(JSON.stringify({
        event: name,
        payload_index: index,
        payload_id: currentCase.id,
        sha256: currentCase.sha256,
        wire_body_size: currentCase.wire_body_size,
        metadata: currentCase.metadata,
        ...extra,
    }));
}

function sendCase(currentCase, index, lane = 0) {
    const body = encoding.b64decode(currentCase.body_base64, 'std');
    const headers = {
        ...currentCase.headers,
        'X-WAF-Test-Run-ID': __ENV.RUN_ID || 'manual',
        'X-WAF-Test-Sequence': String(index),
        'X-WAF-Test-Lane': String(lane),
    };
    const response = http.request(currentCase.method || 'POST', `${targetBase}${currentCase.path || ''}`, body, {
        headers,
        tags: {
            payload_id: currentCase.id,
            payload_index: String(index),
            payload_lane: String(lane),
            payload_sha256: currentCase.sha256,
            content_type: headers['Content-Type'] || 'none',
            content_encoding: headers['Content-Encoding'] || 'none',
        },
    });
    check(response, {
        'response received': (r) => r.status > 0,
        'no upstream 5xx': (r) => r.status < 500,
    });
}

export function setup() {
    console.log(JSON.stringify({
        event: 'K6_RUN_START',
        cases: cases.length,
        mode: runMode,
        lanes,
        rps_per_case: rate,
        max_active_rps: rate * Math.min(lanes, cases.length),
        duration,
        cooldown,
        graceful_stop: gracefulStop,
        slot_seconds: durationSeconds(duration) + durationSeconds(gracefulStop) + cooldown,
        threshold_mode: thresholdMode,
        abort_on_overload: abortOnOverload,
        max_dropped_iterations: maxDroppedIterations,
        max_http_req_duration_p95_ms: maxP95Ms,
        overload_delay: overloadDelay,
        preallocated_vus_per_case: preAllocatedVUs,
        max_vus_per_case: maxVUs,
    }));
    if (!batchMode && !highRpsMode) event('CASE_START', cases[0], caseIndex(cases[0]), { lane: 0 });
}

export default function () {
    if (!batchMode) {
        sendCase(cases[0], caseIndex(cases[0]), 0);
        return;
    }

    const seconds = durationSeconds(duration);
    const interval = rate > 0 ? 1 / rate : 0;
    for (let offset = 0; offset < cases.length; offset += 1) {
        const currentCase = cases[offset];
        const index = caseIndex(currentCase, offset);
        const started = Date.now();
        let requests = 0;
        event('CASE_START', currentCase, index, { mode: 'fast', lane: 0 });
        while ((Date.now() - started) / 1000 < seconds) {
            const iterationStarted = Date.now();
            sendCase(currentCase, index, 0);
            requests += 1;
            const remaining = interval - ((Date.now() - iterationStarted) / 1000);
            if (remaining > 0) sleep(remaining);
        }
        event('CASE_END', currentCase, index, { mode: 'fast', lane: 0, requests, elapsed_seconds: (Date.now() - started) / 1000 });
        if (cooldown > 0 && offset + 1 < cases.length) sleep(cooldown);
    }
}

export function runHighRpsCase() {
    const offset = Number.parseInt(__ENV.CASE_OFFSET || '-1', 10);
    const lane = Number.parseInt(__ENV.CASE_LANE || '0', 10);
    const currentCase = cases[offset];
    if (!currentCase) throw new Error(`No payload for CASE_OFFSET=${offset}`);
    sendCase(currentCase, caseIndex(currentCase, offset), lane);
}

export function highRpsLaneController() {
    const lane = Number.parseInt(__ENV.CASE_LANE || '0', 10);
    const activeSeconds = durationSeconds(duration) + durationSeconds(gracefulStop);
    for (let offset = lane; offset < cases.length; offset += lanes) {
        const currentCase = cases[offset];
        const index = caseIndex(currentCase, offset);
        event('CASE_START', currentCase, index, {
            mode: 'high-rps', lane, target_rps: rate, scheduled_duration: duration,
        });
        sleep(activeSeconds);
        event('CASE_END', currentCase, index, {
            mode: 'high-rps', lane, target_rps: rate, scheduled_duration: duration,
            expected_requests: Math.round(rate * durationSeconds(duration)),
        });
        if (cooldown > 0 && offset + lanes < cases.length) sleep(cooldown);
    }
}

export function teardown() {
    if (!batchMode && !highRpsMode) event('CASE_END', cases[0], caseIndex(cases[0]), { lane: 0 });
    console.log(JSON.stringify({ event: 'K6_RUN_END', cases: cases.length, mode: runMode, lanes }));
}
