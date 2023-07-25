const coap = require('coap') // or coap
const HOST = 'localhost';
const PORT = 5684;


// const req = coap.request({
//     method: 'GET',
//     host: HOST,
//     port: PORT,
//     pathname: 'GET',
//     query:'temp=26'
// })

const req = coap.request('coap:192.168.5.100:5683/GET?POST')

req.on('response', (res) => {
    res.pipe(process.stdout)
})

req.end()
