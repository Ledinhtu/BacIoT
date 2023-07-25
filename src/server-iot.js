const coap = require('coap') // or coap
const events = require('events');
const eventEmitter = new events.EventEmitter();
const server = coap.createServer()

let status = true;
let cnt = 0;

function obs(req, res) {
    let count = 0;
    if (req.headers.Observe !== 0) {
        count = 0;
        // return res.end(new Date().toISOString() + '\n')
        return res.end("Oke you fail")
    }

    // console.log(req.options[1].value.toString());
    res.write(status.toString())

    if (0) {     
        const interval = setInterval(() => {
            if (count < 5) {
                res.write(count.toString() + '\n')
                console.log(count);          
                count++;
            } else {
                clearInterval(interval)
                console.log('clearInterval')
                // process.exit()
            }
        }, 10000)
    }

    eventEmitter.on('scream', () => {
        res.write(status.toString())
        // res.write(status.toString() + '\n')
        if (status) {
            console.log('ON');                   
        } else {
            console.log('OFF');                   
        }
        // count++;
    });
    
    res.on('finish', () => {
        // console.log(`Fi: ${JSON.parse(req[0])}`);
        console.log('finsh')
        // exit()
        // process.exit()

    })
}

function getHandle(req, res) {
    // res.end('Hello ' + req.url.split('/GET?')[1] + '\n')
    res.end('Hello\n')
}

function postHandle(req, res) {
    res.end('POST successed!\n')
    let payload = JSON.parse(req.payload);
    for (const [key, value] of Object.entries(payload)) {
        console.log(`${key}: ${value}`);
      }
    // console.log(`Payload: ${req._packet.payload}`);
    // console.log(`Payload: ${payload}`);
    // console.log(`"title": ${typeof(payload)}`);
    // console.log(`"title": ${payload['title']}`);
}

server.on('request', (req, res) => {
    // console.log(req);
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

// server.on('timeout', (req, res) => {

// })

setInterval(()=>{
    if(cnt%2 == 0) {
        status = !status;
        eventEmitter.emit('scream');

    }
    cnt ++;
}, 2000)


server.listen(5684,() => {
    console.log('server started')
})
