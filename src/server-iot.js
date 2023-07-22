const coap = require('coap') // or coap
const server = coap.createServer()

function obs(req, res) {
    if (req.headers.Observe !== 0) {
        return res.end(new Date().toISOString() + '\n')
    }
    
    const interval = setInterval(() => {
        res.write(new Date().toISOString() + '\n')
    }, 1000)
    
    res.on('finish', () => {
        clearInterval(interval)
    })
}

function getHandle(req, res) {
    res.end('Hello ' + req.url.split('/GET?')[1] + '\n')
}

function postHandle(req, res) {
    res.end('POST successed!\n')
    let payload = JSON.parse(req._packet.payload);
    console.log(`Payload: ${req._packet.payload}`);
    console.log(`Payload: ${payload}`);
    console.log(`"title": ${typeof(payload)}`);
    console.log(`"title": ${payload['title']}`);
}

server.on('request', (req, res) => {
    console.log(req);
    console.log(`url: ${req.url.split('/')[1]}`);
    const key = req.url.split('/')[1].slice(0, 3);
    console.log(`key: ${key}`);
    switch (key) {
        case 'obs':
            obs(req, res);
            break;

        case 'GET':
            getHandle(req, res);
            break;   
            
        case 'POS':
            postHandle(req, res);
            break;

        default:

            res.end('This is a default messenger\n');
            console.log('default');
            let payload = JSON.parse(req.payload);
            
            console.log(`payload: ${req.payload}`);
            console.log(`payload type: ${typeof(req.payload)}`);

            for (const [key, value] of Object.entries(payload)) {
                console.log(`${key}: ${value}`);
              }
            // console.log(`temp: ${payload['temp']}`);
            break;
    }

})

server.listen(() => {
    console.log('server started')
})
