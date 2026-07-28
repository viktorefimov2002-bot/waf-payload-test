import http from 'k6/http';
import { check, sleep } from 'k6';
import encoding from 'k6/encoding';

const caseFile = __ENV.CASE_FILE || './current_case.json';
const loaded = JSON.parse(open(caseFile));
const cases = Array.isArray(loaded) ? loaded : [loaded];
const firstIndex = Number.parseInt(__ENV.CASE_INDEX || '0', 10);
const targetBase = (__ENV.TARGET_URL || 'https://your-target.com').replace(/\/$/, '');
const rate = Number.parseInt(__ENV.RPS || '10', 10);
const duration = __ENV.DURATION || '30s';
const gracefulStop = __ENV.GRACEFUL_STOP || '1s';
const thresholdMode = __ENV.THRESHOLD_MODE || 'disabled';
const batchMode = cases.length > 1;
const preAllocatedVUs = Number.parseInt(__ENV.PREALLOCATED_VUS || String(Math.max(10, rate)), 10);
const maxVUs = Number.parseInt(__ENV.MAX_VUS || String(Math.max(preAllocatedVUs, rate * 2)), 10);

if (!cases.length || cases.some((item) => !item || typeof item !== 'object' || !item.body_base64)) {
    throw new Error(`CASE_FILE=${caseFile} does not contain valid case objects`);
}

function durationSeconds(value) {
    const match = /^([0-9]+(?:\.[0-9]+)?)(ms|s|m|h)$/.exec(value);
    if (!match) throw new Error(`Unsupported duration: ${value}`);
    const amount = Number.parseFloat(match[1]);
    const factors = { ms: 0.001, s: 1, m: 60, h: 3600 };
    return amount * factors[match[2]];
}

const thresholds = thresholdMode === 'strict' ? {
    http_req_failed: ['rate<0.05'],
    dropped_iterations: ['count==0'],
} : {};

export const options = batchMode ? {
    scenarios: {
        batch_payloads: {
            executor: 'shared-iterations',
            vus: 1,
            iterations: 1,
            maxDuration: __ENV.BATCH_MAX_DURATION || '24h',
            gracefulStop,
        },
    },
    thresholds,
    tags: { test_run_id: __ENV.RUN_ID || 'manual' },
} : {
    scenarios: {
        single_payload: {
            executor: 'constant-arrival-rate',
            rate,
            timeUnit: '1s',
            duration,
            gracefulStop,
            preAllocatedVUs,
            maxVUs,
        },
    },
    thresholds,
    tags: {
        test_run_id: __ENV.RUN_ID || 'manual',
        payload_id: cases[0].id,
    },
};

function sendCase(currentCase, caseIndex) {
    const body = encoding.b64decode(currentCase.body_base64, 'std');
    const headers = {
        ...currentCase.headers,
        'X-WAF-Test-Run-ID': __ENV.RUN_ID || 'manual',
        'X-WAF-Test-Sequence': String(caseIndex),
    };
    const url = `${targetBase}${currentCase.path || ''}`;
    const response = http.request(currentCase.method || 'POST', url, body, {
        headers,
        tags: {
            payload_id: currentCase.id,
            payload_index: String(caseIndex),
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
        first_index: firstIndex,
        cases: cases.length,
        rps: rate,
        duration,
        graceful_stop: gracefulStop,
        threshold_mode: thresholdMode,
    }));
}

export default function () {
    if (!batchMode) {
        sendCase(cases[0], firstIndex);
        return;
    }

    const seconds = durationSeconds(duration);
    const interval = rate > 0 ? 1 / rate : 0;
    for (let offset = 0; offset < cases.length; offset += 1) {
        const currentCase = cases[offset];
        const caseIndex = firstIndex + offset;
        const started = Date.now();
        let requests = 0;
        console.log(JSON.stringify({
            event: 'CASE_START',
            payload_index: caseIndex,
            payload_id: currentCase.id,
            sha256: currentCase.sha256,
            wire_body_size: currentCase.wire_body_size,
            metadata: currentCase.metadata,
        }));
        while ((Date.now() - started) / 1000 < seconds) {
            const iterationStarted = Date.now();
            sendCase(currentCase, caseIndex);
            requests += 1;
            const remaining = interval - ((Date.now() - iterationStarted) / 1000);
            if (remaining > 0) sleep(remaining);
        }
        console.log(JSON.stringify({
            event: 'CASE_END',
            payload_index: caseIndex,
            payload_id: currentCase.id,
            requests,
            elapsed_seconds: (Date.now() - started) / 1000,
        }));
        const cooldown = Number.parseFloat(__ENV.COOLDOWN || '0');
        if (cooldown > 0 && offset + 1 < cases.length) sleep(cooldown);
    }
}

export function teardown() {
    console.log(JSON.stringify({
        event: 'K6_RUN_END',
        first_index: firstIndex,
        cases: cases.length,
    }));
}
