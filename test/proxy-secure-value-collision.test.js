const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const vm = require('vm');
const cookieTools = require('cookie');

const testName = 'proxy-secure-value-collision';
const outputDir = process.env.ALEXA_COOKIE_TEST_OUTPUT_DIR || path.join(__dirname, '..', 'test-output');
const outputFile = path.join(outputDir, `${testName}.txt`);
const lines = [];

function line(value = '') {
    lines.push(value);
}

function writeOutput() {
    fs.mkdirSync(outputDir, { recursive: true });
    fs.writeFileSync(outputFile, `${lines.join('\n')}\n`);
}

function recordAssertion(description, fn) {
    try {
        fn();
        line(`${description}: PASS`);
    } catch (err) {
        line(`${description}: FAIL`);
        writeOutput();
        throw err;
    }
}

const proxyFile = path.join(__dirname, '..', 'lib', 'proxy.js');
const source = fs.readFileSync(proxyFile, 'utf8');

let capturedProxyOptions;

function createExpressStub() {
    return {
        use() {},
        get() {},
        listen() {
            const server = {
                address: () => ({ port: 3456 }),
                on: () => server
            };
            return server;
        }
    };
}

function loadProxyModule() {
    capturedProxyOptions = undefined;
    const module = { exports: {} };
    const sandbox = {
        Buffer,
        URL,
        __dirname: path.dirname(proxyFile),
        console,
        module,
        exports: module.exports,
        require(name) {
            if (name === 'express') return createExpressStub;
            if (name === 'http-proxy-response-rewrite') return () => {};
            if (name === 'http-proxy-middleware') {
                return {
                    createProxyMiddleware(_context, options) {
                        capturedProxyOptions = options;
                        return function proxyMiddleware() {};
                    }
                };
            }
            return require(name);
        }
    };
    vm.runInNewContext(source, sandbox, { filename: proxyFile });
    return module.exports;
}

function createProxyResponse(setCookieValues) {
    return {
        statusCode: 200,
        headers: {
            location: 'https://www.amazon.de/ap/maplanding?openid.mode=id_res&openid.oa2.authorization_code=AUTH_CODE',
            'set-cookie': setCookieValues
        },
        socket: {
            _host: 'www.amazon.de',
            parser: {
                outgoing: {
                    method: 'POST',
                    path: '/ap/signin',
                    getHeader() {
                        return undefined;
                    }
                }
            }
        }
    };
}

function createProxyRequest(initialHeaders = {}) {
    const headers = {};
    for (const name of Object.keys(initialHeaders)) {
        headers[name.toLowerCase()] = initialHeaders[name];
    }
    return {
        getHeader(name) {
            return headers[name.toLowerCase()];
        },
        setHeader(name, value) {
            headers[name.toLowerCase()] = value;
        },
        getHeaders() {
            return { ...headers };
        }
    };
}

const proxyModule = loadProxyModule();
const formerDataStorePath = path.join(os.tmpdir(), `alexa-cookie-secure-value-collision-test-${Date.now()}.json`);

try {
    const input = {
        proxyOwnIp: '127.0.0.1',
        proxyPort: 3456,
        proxyListenBind: '0.0.0.0',
        proxyHttps: false,
        baseAmazonPage: 'amazon.de',
        baseAmazonPageHandle: '_de',
        amazonPageProxyLanguage: 'de_DE',
        acceptLanguage: 'de-DE',
        proxyLogLevel: 'silent',
        formerDataStorePath
    };
    let callbackData;
    proxyModule.initAmazonProxy(input, (_err, data) => {
        callbackData = data;
    });

    // The old replacement could corrupt a value containing "Secure". Stripping
    // the attribute must also leave cookies available to the login callback,
    // including when no attributes remain after rewriting the response header.
    const setCookieValues = [
        'session-token=abcSecure123xyz; Path=/; Domain=.amazon.de',
        'ubid-acbde=UBID_VALUE; Path=/; Domain=.amazon.de; Secure; SameSite=None',
        'session-id=SID_ONLY_SECURE; Secure',
        'x-no-attributes=VALUE==',
        'x-combined=SecureVALUE; Path=/; \tSeCuRe \t; HttpOnly',
        'x-Secure=NAME_VALUE;Secure',
        'x-empty=; Secure'
    ];
    const proxyRes = createProxyResponse(setCookieValues);
    const req = {
        method: 'POST',
        url: '/www.amazon.de/ap/signin',
        originalUrl: '/www.amazon.de/ap/signin',
        on() {}
    };
    const proxyReq = createProxyRequest({ host: 'www.amazon.de' });

    capturedProxyOptions.onProxyReq(proxyReq, req, {});
    capturedProxyOptions.onProxyRes(proxyRes, req, {});

    line('TEST: Secure-flag stripping does not corrupt a cookie VALUE containing the substring "Secure"');
    line('');
    line('CODE UNDER TEST:');
    line('- lib/proxy.js: onProxyRes() Secure-flag stripping (proxyHttps=false path)');
    line('');
    line('OBSERVED:');
    line(`set-cookie[0] (session-token): ${proxyRes.headers['set-cookie'][0]}`);
    line(`set-cookie[1] (ubid, had real Secure attribute): ${proxyRes.headers['set-cookie'][1]}`);
    line('');
    line('ASSERTIONS:');
    recordAssertion('session-token VALUE keeps the "Secure" substring intact', () => {
        assert.strictEqual(proxyRes.headers['set-cookie'][0], 'session-token=abcSecure123xyz; Path=/; Domain=.amazon.de');
    });
    recordAssertion('ubid cookie really loses its Secure attribute', () => {
        assert.strictEqual(proxyRes.headers['set-cookie'][1], 'ubid-acbde=UBID_VALUE; Path=/; Domain=.amazon.de; SameSite=None');
    });
    recordAssertion('cookie with only Secure attribute has the expected response header', () => {
        assert.strictEqual(proxyRes.headers['set-cookie'][2], 'session-id=SID_ONLY_SECURE');
    });
    recordAssertion('cookie with only Secure attribute is retained in loginCookie', () => {
        assert.strictEqual(cookieTools.parse(callbackData.loginCookie)['session-id'], 'SID_ONLY_SECURE');
    });
    recordAssertion('cookie without attributes keeps equals signs in its value', () => {
        assert.strictEqual(proxyRes.headers['set-cookie'][3], 'x-no-attributes=VALUE==');
        assert.strictEqual(cookieTools.parse(callbackData.loginCookie)['x-no-attributes'], 'VALUE==');
    });
    recordAssertion('mixed-case Secure attribute is removed without changing a colliding value', () => {
        assert.strictEqual(proxyRes.headers['set-cookie'][4], 'x-combined=SecureVALUE; Path=/; HttpOnly');
        assert.strictEqual(cookieTools.parse(callbackData.loginCookie)['x-combined'], 'SecureVALUE');
    });
    recordAssertion('Secure text in the cookie name survives attribute removal and collection', () => {
        assert.strictEqual(proxyRes.headers['set-cookie'][5], 'x-Secure=NAME_VALUE');
        assert.strictEqual(cookieTools.parse(callbackData.loginCookie)['x-Secure'], 'NAME_VALUE');
    });
    recordAssertion('empty cookie values remain excluded from the collected cookies', () => {
        assert.strictEqual(proxyRes.headers['set-cookie'][6], 'x-empty=');
        assert.strictEqual(Object.prototype.hasOwnProperty.call(cookieTools.parse(callbackData.loginCookie), 'x-empty'), false);
    });
    line('');
    line('RESULT: PASS');
    writeOutput();
} catch (err) {
    if (!lines.includes('RESULT: PASS')) {
        line('');
        line('RESULT: FAIL');
        writeOutput();
    }
    throw err;
} finally {
    fs.rmSync(formerDataStorePath, { force: true });
}
