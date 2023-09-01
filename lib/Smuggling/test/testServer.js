const http = require('http');

http.createServer((request, response) => {
    let body = [];
    request.on('error', (err) => {
        response.end("error while reading body: " + err)
    }).on('data', (chunk) => {
        body.push(chunk);
    }).on('end', () => {
        body = Buffer.concat(body).toString();

        response.on('error', (err) => {
            response.end("error while sending response: " + err)
        });

        response.end(JSON.stringify({
            "Headers": request.headers,
            "Length": body.length,
            "Body": body,
        }) + "\n");
    });
}).listen(80);