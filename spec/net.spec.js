const assert = require('assert');

const runner = require('./runner');

describe('net.spec: net namespace tests', () => {
    describe('net.resolveHost', () => {
        it('throws an error if the parameter is missing', async () => {
            runner.run(`
                try {
                    await Neutralino.net.resolveHost();
                }
                catch(err) {
                    await __close(err.code);
                }
            `);
            assert.equal(runner.getOutput(), 'NE_RT_NATRTER');
        });
        it('throws an error if the parameter is not a string (number)', async () => {
            runner.run(`
                try {
                    const result = await Neutralino.net.resolveHost(3510);
                    await __close(JSON.stringify(result));
                } catch(err) {
                    await __close(err.code);
                }
            `);
            assert.equal(runner.getOutput(), 'NE_RT_NATRTER');
        });
        it('throws an error if the parameter is not a string (object)', async () => {
            runner.run(`
                try {
                    const result = await Neutralino.net.resolveHost({ domain: 'wrong.example.com' });
                    await __close(JSON.stringify(result));
                } catch(err) {
                    await __close(err.code);
                }
            `);
            assert.equal(runner.getOutput(), 'NE_RT_NATRTER');
        });
        it('works without throwing errors if parameter is provided', async () => {
            runner.run(`
                try {
                    const result = await Neutralino.net.resolveHost('example.com');
                    await __close(JSON.stringify(result));
                } catch(err) {
                    await __close(err.code);
                }
            `);
            const result = JSON.parse(runner.getOutput());
            assert.ok(Array.isArray(result));
            assert.ok(result.length > 0);
            assert.ok(result.every(ip => typeof ip === 'object' && 'family' in ip && 'address' in ip));
        });
    });

    describe('net.fetch [HTTP]', () => {
        it('throws an error if the parameter(s) are missing', async () => {
            runner.run(`
                try {
                    await Neutralino.net.fetch();
                }
                catch(err) {
                    await __close(err.code);
                }
            `);
            assert.equal(runner.getOutput(), 'NE_RT_NATRTER');
        });
        it('works with simple GET request', async () => {
            runner.run(`
                try {
                    const res = await Neutralino.net.fetch('http://httpbin.org/get');
                    await __close(res.status.toString());
                }
                catch(err) {
                    await __close(err.code);
                }
            `);
            assert.equal(runner.getOutput(), '200');
        });
        it('works with simple body data', async () => {
            runner.run(`
                try {
                    const res = await Neutralino.net.fetch('http://httpbin.org/anything', {
                        method: 'POST',
                        body: 'Hello World',
                    });
                    await __close(res.status.toString());
                }
                catch(err) {
                    await __close(err.code);
                }
            `);
            assert.equal(runner.getOutput(), '200');
        });
        it('works with JSON body data', async () => {
            runner.run(`
                try {
                    const res = await Neutralino.net.fetch('http://httpbin.org/anything', {
                        method: 'POST',
                        body: JSON.stringify({ message: 'Hello World' }),
                        headers: {
                            'Content-Type': 'application/json',
                            'accept-encoding': 'identity',
                            'custom-header': 'NeutralinoJS-Test'
                        }
                    });
                    await __close(await res.text());
                }
                catch(err) {
                    await __close(err.code);
                }
            `);
            const res = JSON.parse(runner.getOutput());
            assert.equal(res.json.message, 'Hello World');
        });
        it('works with deflate response body data', async () => {
            runner.run(`
                try {
                    const res = await Neutralino.net.fetch('http://httpbin.org/deflate');
                    await __close(await res.text());
                }
                catch(err) {
                    await __close(err.code);
                }
            `);
            const res = JSON.parse(runner.getOutput());
            assert.equal(res.deflated, true);
        });
        it('works with gzip response body data', async () => {
            runner.run(`
                try {
                    const res = await Neutralino.net.fetch('http://httpbin.org/gzip');
                    await __close(await res.text());
                }
                catch(err) {
                    await __close(err.code);
                }
            `);
            const res = JSON.parse(runner.getOutput());
            assert.equal(res.gzipped, true);
        });
        it('works with brotli response body data', async () => {
            runner.run(`
                try {
                    const res = await Neutralino.net.fetch('http://httpbin.org/brotli');
                    await __close(await res.text());
                }
                catch(err) {
                    await __close(err.code);
                }
            `);
            const res = JSON.parse(runner.getOutput());
            assert.equal(res.brotli, true);
        });
        it('works with max 5 redirects', async () => {
            runner.run(`
                try {
                    const res = await Neutralino.net.fetch('http://httpbin.org/redirect/5');
                    await __close(await res.status.toString());
                }
                catch(err) {
                    await __close(err.code);
                }
            `);
            assert.equal(runner.getOutput(), '200');
        });
        it('does not follow more than 5 redirects', async () => {
            runner.run(`
                try {
                    const res = await Neutralino.net.fetch('http://httpbin.org/redirect/6');
                    await __close(await res.status.toString());
                }
                catch(err) {
                    await __close(err);
                }
            `);
            const status = parseInt(runner.getOutput(), 10);
            assert.ok(!isNaN(status) && status >= 300 && status < 400);
        });
        it('throw error at signal cancel', async () => {
            runner.run(`
                try {
                    const controller = new AbortController();
                    controller.abort();
                    const res = await Neutralino.net.fetch('http://httpbin.org/get', {
                        signal: controller.signal
                    });
                    await __close(await res.status.toString());
                }
                catch(err) {
                    await __close(err.code);
                }
            `);
            assert.equal(runner.getOutput(), 'NE_NW_REQCANC');
        });
    });

    describe('net.fetch [HTTPS]', () => {
        it('throws an error if the parameter(s) are missing', async () => {
            runner.run(`
                try {
                    await Neutralino.net.fetch();
                }
                catch(err) {
                    await __close(err.code);
                }
            `);
            assert.equal(runner.getOutput(), 'NE_RT_NATRTER');
        });
        it('works with simple GET request', async () => {
            runner.run(`
                try {
                    const res = await Neutralino.net.fetch('https://httpbin.org/get');
                    await __close(res.status.toString());
                }
                catch(err) {
                    await __close(err.code);
                }
            `);
            assert.equal(runner.getOutput(), '200');
        });
        it('works with simple body data', async () => {
            runner.run(`
                try {
                    const res = await Neutralino.net.fetch('https://httpbin.org/anything', {
                        method: 'POST',
                        body: 'Hello World',
                    });
                    await __close(res.status.toString());
                }
                catch(err) {
                    await __close(err.code);
                }
            `);
            assert.equal(runner.getOutput(), '200');
        });
        it('works with JSON body data', async () => {
            runner.run(`
                try {
                    const res = await Neutralino.net.fetch('https://httpbin.org/anything', {
                        method: 'POST',
                        body: JSON.stringify({ message: 'Hello World' }),
                        headers: {
                            'Content-Type': 'application/json',
                            'accept-encoding': 'identity',
                            'custom-header': 'NeutralinoJS-Test'
                        }
                    });
                    await __close(await res.text());
                }
                catch(err) {
                    await __close(err.code);
                }
            `);
            const res = JSON.parse(runner.getOutput());
            assert.equal(res.json.message, 'Hello World');
        });
        it('works with deflate response body data', async () => {
            runner.run(`
                try {
                    const res = await Neutralino.net.fetch('https://httpbin.org/deflate');
                    await __close(await res.text());
                }
                catch(err) {
                    await __close(err.code);
                }
            `);
            const res = JSON.parse(runner.getOutput());
            assert.equal(res.deflated, true);
        });
        it('works with gzip response body data', async () => {
            runner.run(`
                try {
                    const res = await Neutralino.net.fetch('https://httpbin.org/gzip');
                    await __close(await res.text());
                }
                catch(err) {
                    await __close(err.code);
                }
            `);
            const res = JSON.parse(runner.getOutput());
            assert.equal(res.gzipped, true);
        });
        it('works with brotli response body data', async () => {
            runner.run(`
                try {
                    const res = await Neutralino.net.fetch('https://httpbin.org/brotli');
                    await __close(await res.text());
                }
                catch(err) {
                    await __close(err.code);
                }
            `);
            const res = JSON.parse(runner.getOutput());
            assert.equal(res.brotli, true);
        });
        it('works with max 5 redirects', async () => {
            runner.run(`
                try {
                    const res = await Neutralino.net.fetch('https://httpbin.org/redirect/5');
                    await __close(await res.status.toString());
                }
                catch(err) {
                    await __close(err.code);
                }
            `);
            assert.equal(runner.getOutput(), '200');
        });
        it('does not follow more than 5 redirects', async () => {
            runner.run(`
                try {
                    const res = await Neutralino.net.fetch('https://httpbin.org/redirect/6');
                    await __close(await res.status.toString());
                }
                catch(err) {
                    await __close(err);
                }
            `);
            const status = parseInt(runner.getOutput(), 10);
            assert.ok(!isNaN(status) && status >= 300 && status < 400);
        });
        it('throw error at signal cancel', async () => {
            runner.run(`
                try {
                    const controller = new AbortController();
                    controller.abort();
                    const res = await Neutralino.net.fetch('https://httpbin.org/get', {
                        signal: controller.signal
                    });
                    await __close(await res.status.toString());
                }
                catch(err) {
                    await __close(err.code);
                }
            `);
            assert.equal(runner.getOutput(), 'NE_NW_REQCANC');
        });
    });
});