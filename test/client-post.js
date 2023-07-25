const coap = require('coap') // or coap
const HOST = 'localhost'; //172.20.10.3:
// const HOST = '192.168.5.100';
// const HOST = '192.168.137.1';
// const PORT = 5683;
const PORT = 5684;


const req = coap.request({
    method: 'POST',
    host: HOST,
    port: PORT,
    pathname: 'POST'
})

const payload = {
    title: 'this is a test payload',
    body: 'containing nothing useful'
}

req.write(JSON.stringify(payload))

req.on('response', (res) => {
    res.pipe(process.stdout)
})

req.end()
