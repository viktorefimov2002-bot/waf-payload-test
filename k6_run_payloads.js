import http from 'k6/http';
import { check, sleep } from 'k6';
import encoding from 'k6/encoding';
import exec from 'k6/execution';

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
const preAllocatedVUs = Number.parseInt(__ENV.PREALLOCATED_VUS || String(Math.max(10, Math.ceil(rate / 5))), 10);
const maxVUs = Number.parseInt(__ENV.MAX_VUS || String(Math.max(preAllocatedVUs, rate * 2)), 10);
const batchMode = cases.length > 1;
const highRpsMode = runMode === 'high-rps';

if (!cases.length || cases.some((item) => !item || typeof item !== 'object' || !item.body_base64)) {
    throw new Error(`CASE_FILE=${caseFile} does not contain valid case objects`);
}

function caseIndex(currentCase, offset = 0) {
    return Number.isInteger(currentCase._source_index) ? currentCase._source_index : fallbackIndex + offset;
}

function durationSeconds(value) {
    const match = /^([0-9]+(?:\.[0-9]+)?)(ms|s|m|h)$/.exec(value);
    if (!match) throw new Error(`Unsupported duration: ${value}`);
    return Number.parseFloat(match[1]) * ({ ms: 0.001, s: 1, m: 60, h: 3600 })[match[2]];
}

function secondsDuration(value) {
    const rounded = Math.round(value * 1000) / 1000;
    return `${rounded}s`;
}

const thresholds = thresholdMode === 'strict' ? {
    http_req_failed: ['rate<0.05'],
    dropped_iterations: ['count==0'],
} : {};

function buildHighRpsScenarios() {
    const scenarios = {};
    const slotSeconds = durationSeconds(duration) + cooldown;
    for (let offset = 0; offset < cases.length; offset += 1) {
        const currentCase = cases[offset];
        const index = caseIndex(currentCase, offset);
        scenarios[`payload_${offset}`] = {
            executor: 'constant-arrival-rate',
            exec: 'runHighRpsCase',
            rate,
            timeUnit: '1s',
            duration,
            startTime: secondsDuration(offset * slotSeconds),
            gracefulStop,
            preAllocatedVUs,
            maxVUs,
            env: { CASE_OFFSET: String(offset) },
            tags: {
                payload_id: currentCase.id,
                payload_index: String(index),
            },
        };
    }
    scenarios.batch_controller = {
        executor: 'shared-iterations',
        exec: 'highRpsController',
        vus: 1,
        iterations: 1,
        maxDuration: __ENV.BATCH_MAX_DURATION || '24h',
        gracefulStop: '0s',
    };
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

function sendCase(currentCase, index) {
    const body = encoding.b64decode(currentCase.body_base64, 'std');
    const headers = {
        ...currentCase.headers,
        'X-WAF-Test-Run-ID': __ENV.RUN_ID || 'manual',
        'X-WAF-Test-Sequence': String(index),
    };
    const response = http.request(currentCase.method || 'POST', `${targetBase}${currentCase.path || ''}`, body, {
        headers,
        tags: {
            payload_id: currentCase.id,
            payload_index: String(index),
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
        rps: rate,
        duration,
        cooldown,
        graceful_stop: gracefulStop,
        threshold_mode: thresholdMode,
        preallocated_vus: preAllocatedVUs,
        max_vus: maxVUs,
    }));
    if (!batchMode && !highRpsMode) {
        event('CASE_START', cases[0], caseIndex(cases[0]));
    }
}

export default function () {
    if (!batchMode) {
        sendCase(cases[0], caseIndex(cases[0]));
        return;
    }

    const seconds = durationSeconds(duration);
    const interval = rate > 0 ? 1 / rate : 0;
    for (let offset = 0; offset < cases.length; offset += 1) {
        const currentCase = cases[offset];
        const index = caseIndex(currentCase, offset);
        const started = Date.now();
        let requests = 0;
        event('CASE_START', currentCase, index, { mode: 'fast' });
        while ((Date.now() - started) / 1000 < seconds) {
            const iterationStarted = Date.now();
            sendCase(currentCase, index);
            requests += 1;
            const remaining = interval - ((Date.now() - iterationStarted) / 1000);
            if (remaining > 0) sleep(remaining);
        }
        event('CASE_END', currentCase, index, {
            mode: 'fast',
            requests,
            elapsed_seconds: (Date.now() - started) / 1000,
        });
        if (cooldown > 0 && offset + 1 < cases.length) sleep(cooldown);
    }
}

export function runHighRpsCase() {
    const offset = Number.parseInt(exec.scenario.env.CASE_OFFSET, 10);
    const currentCase = cases[offset];
    if (!currentCase) throw new Error(`No payload for CASE_OFFSET=${offset}`);
    sendCase(currentCase, caseIndex(currentCase, offset));
}

export function highRpsController() {
    const seconds = durationSeconds(duration);
    for (let offset = 0; offset < cases.length; offset += 1) {
        const currentCase = cases[offset];
        const index = caseIndex(currentCase, offset);
        event('CASE_START', currentCase, index, {
            mode: 'high-rps',
            target_rps: rate,
            scheduled_duration: duration,
        });
        sleep(seconds);
        event('CASE_END', currentCase, index, {
            mode: 'high-rps',
            target_rps: rate,
            scheduled_duration: duration,
        });
        if (cooldown > 0 && offset + 1 < cases.length) sleep(cooldown);
    }
}

export function teardown() {
    if (!batchMode && !highRpsMode) {
        event('CASE_END', cases[0], caseIndex(cases[0]));
    }
    console.log(JSON.stringify({ event: 'K6_RUN_END', cases: cases.length, mode: runMode }));
}
