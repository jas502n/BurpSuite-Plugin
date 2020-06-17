var http = require('http');

const PORT = 8000;

const parseQueryString = str => str
  .split('&')
  .map(pair => {
    const idx = pair.indexOf('=');
    if (idx === -1) return null;
    return [pair.substr(0, idx), pair.substr(idx+1)];
  })
  .reduce((acc, kvp) => {
    if (kvp !== null) acc[unescape(kvp[0])] = unescape(kvp[1]);
    return acc;
  }, {});

console.log(`Serving on http://localhost:${PORT}, press ctrl+c to stop`);
http.createServer((req, res) => {
  res.writeHead(200, {'Content-Type': 'text/html'});

  if (req.method === 'POST') {
    const body = [];
    req.on('data', chunk => {
      body.push(chunk);
    }).on('end', () => {
      var data = parseQueryString(Buffer.concat(body).toString()).data;
      data = new Buffer(data, 'base64').toString('ascii');
      
      res.end(`Input received: ${parseQueryString(data).input}`);
    });
  } else {
    res.end(`
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" >
<head runat="server">
    <title>Demo</title>
    <script type="text/javascript">
    function submitform()
    {
        var input = document.forms[0].input.value;
        input = "input=" + input + "&time=" + new Date().getTime();
        input = btoa(input);
        document.forms[1].data.value = input;
    }
    </script>
</head>
<body>
    <form>
    Input: <input type="text" name="input" />
    </form>
    <br />
    <form method="post" onsubmit="submitform()">
    <input type="hidden" name="data" />
    <input type="submit" value="Submit" />
    </form>
    <br />
    <div id="output" runat="server"></div>
</body>
</html>
    `);
  }
}).listen(PORT, 'localhost');
