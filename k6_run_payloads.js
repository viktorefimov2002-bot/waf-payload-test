import http from 'k6/http';
import { check } from 'k6';
import { SharedArray } from 'k6/data';
import encoding from 'k6/encoding';

const payloads = new SharedArray('payloads', () => JSON.parse(open(__ENV.PAYLOAD_FILE || './payloads.json')));
const caseIndex = Number.parseInt(__ENV.PAYLOAD_INDEX || '0', 10);

if (!Number.isInteger(caseIndex) || caseIndex < 0 || caseIndex >= payloads.length) {
    throw new Error(`PAYLOAD_INDEX=${__ENV.PAYLOAD_INDEX} is outside 0..${payloads.length - 1}`);
}

const currentCase = payloads[caseIndex];
const targetBase = (__ENV.TARGET_URL || 'https://your-target.com').replace(/\/$/, '');
const rate = Number.parseInt(__ENV.RPS || '10', 10);
const duration = __ENV.DURATION || '30s';
const preAllocatedVUs = Number.parseInt(__ENV.PREALLOCATED_VUS || String(Math.max(10, rate)), 10);
const maxVUs = Number.parseInt(__ENV.MAX_VUS || String(Math.max(preAllocatedVUs, rate * 2)), 10);

export const options = {
    scenarios: {
        single_payload: {
            executor: 'constant-arrival-rate',
            rate,
            timeUnit: '1s',
            duration,
            preAllocatedVUs,
            maxVUs,
        },
    },
    thresholds: {
        http_req_failed: ['rate<0.05'],
        dropped_iterations: ['count==0'],
    },
    tags: {
        test_run_id: __ENV.RUN_ID || 'manual',
        payload_id: currentCase.id,
    },
};

export function setup() {
    console.log(JSON.stringify({
        event: 'CASE_START',
        payload_index: caseIndex,
        payload_id: currentCase.id,
        sha256: currentCase.sha256,
        wire_body_size: currentCase.wire_body_size,
        metadata: currentCase.metadata,
        rps: rate,
        duration,
    }));
}

export default function () {
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

export function teardown() {
    console.log(JSON.stringify({
        event: 'CASE_END',
        payload_index: caseIndex,
        payload_id: currentCase.id,
    }));
}
