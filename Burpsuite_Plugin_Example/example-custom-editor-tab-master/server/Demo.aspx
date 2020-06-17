<%@ Page Language="C#" %>

<% 
    string data = Request.Form["data"];
    if (data != null)
    {
        data = Encoding.ASCII.GetString(Convert.FromBase64String(data));
        data = HttpUtility.ParseQueryString(data)["input"];
        output.InnerHtml = "Input received: " + data;
    }
 %>

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



