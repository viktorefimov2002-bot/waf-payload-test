import http from 'k6/http';
import { check } from 'k6';
import { SharedArray } from 'k6/data';
import encoding from 'k6/encoding'; // Встроенный модуль для base64

// Загрузка пейлоадов
const payloads = new SharedArray('payloads', function () {
    const data = open('./payloads.json');
    return JSON.parse(data);
});

// Профили заголовков (добавлены сжатые профили, которые будут переопределены в зависимости от пейлоада)
const baseHeaderProfiles = [
    {
        name: 'default',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Mozilla/5.0 (WAF-Test)',
        },
    },
    {
        name: 'json',
        headers: {
            'Content-Type': 'application/json',
            'User-Agent': 'Mozilla/5.0 (WAF-Test)',
        },
    },
    // ... остальные профили, кроме сжатых (их мы будем генерировать динамически)
];

// Вместо статического headerProfiles мы будем определять заголовки на основе пейлоада.
// Для этого создадим функцию, которая возвращает заголовки для данного пейлоада и выбранного base-профиля.

function buildHeaders(baseProfile, payload) {
    const headers = { ...baseProfile.headers };
    if (payload.is_compressed) {
        // Устанавливаем Content-Encoding в соответствии с типом сжатия
        headers['Content-Encoding'] = payload.compression;
        // Для сжатых данных Content-Type обычно application/octet-stream, но можно оставить как есть
        // Если baseProfile задаёт другой Content-Type, он переопределится.
        // Для корректности, если сжато, лучше установить application/octet-stream или оставить исходный.
        // Оставим как есть, но можно принудительно:
        // headers['Content-Type'] = 'application/octet-stream';
    }
    return headers;
}

export const options = {
    scenarios: {
        waf_test: {
            executor: 'constant-arrival-rate',
            rate: 500,
            timeUnit: '1s',
            duration: `${payloads.length * 30}s`,
            preAllocatedVUs: 10,
            maxVUs: 50,
        },
    },
    thresholds: {
        http_req_failed: ['rate<0.01'],
        http_req_duration: ['p(95)<2000'],
    },
};

export default function () {
    const iter = __ITER;
    const payloadIndex = iter % payloads.length;
    const currentPayload = payloads[payloadIndex];

    // Выбираем базовый профиль заголовков (циклически по всем профилям, но для сжатых используем специальные)
    // Чтобы не усложнять, для простоты используем один профиль для всех, например, 'default'
    // Или можно перебирать, но тогда сжатые пейлоады будут отправляться с разными Content-Type.
    // Для чистоты эксперимента, лучше фиксировать профиль для сжатых, например, application/octet-stream.
    // Мы упростим: будем использовать profile 'default' для всех, но если сжато, переопределим Content-Type.
    const baseProfile = {
        name: 'default',
        headers: {
            'Content-Type': 'application/octet-stream', // для сжатых подойдёт
            'User-Agent': 'Mozilla/5.0 (WAF-Test)',
        },
    };

    // Формируем тело запроса
    let requestBody;
    let headers = { ...baseProfile.headers };

    if (currentPayload.is_compressed) {
        // Декодируем base64 в бинарные данные
        requestBody = encoding.b64decode(currentPayload.payload, 'std', 's' /* raw bytes */);
        headers['Content-Encoding'] = currentPayload.compression;
        // Меняем Content-Type на подходящий (можно оставить application/octet-stream)
        headers['Content-Type'] = 'application/octet-stream';
    } else {
        // Формируем тело в зависимости от Content-Type (как в предыдущей версии)
        const contentType = headers['Content-Type'] || 'application/x-www-form-urlencoded';
        if (contentType.includes('json')) {
            requestBody = JSON.stringify({ input: currentPayload.payload });
        } else if (contentType.includes('xml')) {
            requestBody = `<?xml version="1.0"?><root><input>${currentPayload.payload}</input></root>`;
        } else if (contentType.includes('multipart')) {
            const boundary = '----WebKitFormBoundary';
            requestBody =
                `--${boundary}\r\n` +
                `Content-Disposition: form-data; name="input"\r\n\r\n` +
                `${currentPayload.payload}\r\n` +
                `--${boundary}--\r\n`;
            headers['Content-Type'] = `multipart/form-data; boundary=${boundary}`;
        } else {
            // Обычная форма
            requestBody = `input=${encodeURIComponent(currentPayload.payload)}`;
        }
    }

    const url = 'https://your-target.com/endpoint';
    const response = http.post(url, requestBody, {
        headers: headers,
        tags: {
            payload_name: currentPayload.name,
            payload_size: String(currentPayload.size),
            is_compressed: String(currentPayload.is_compressed),
            compression: currentPayload.compression || 'none',
        },
    });

    check(response, {
        'status is 200 or 403': (r) => r.status === 200 || r.status === 403,
    });
}